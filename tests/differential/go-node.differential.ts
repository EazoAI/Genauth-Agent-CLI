import { spawn } from "node:child_process";
import http from "node:http";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { KeychainSecretStore } from "../../src/storage/secret-store.js";

interface CommandCase {
  name: string;
  go: string[];
  node: string[];
  role?: "user" | "tenant_admin";
  input?: string;
  raw?: boolean;
  login?: boolean;
  extraProfile?: boolean;
  credential?: boolean;
  authorization?: boolean;
  expectedExit?: number;
}

interface WireRequest {
  method: string;
  target: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  requests: WireRequest[];
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const secrets = new KeychainSecretStore("darwin");
let suiteRoot = "";
let goBinary = "";
let goKeychainProbe = "";
let nodeBinary = "";

beforeAll(async () => {
  if (process.platform !== "darwin") throw new Error("Go/Node Keychain differential gate must run on macOS");
  suiteRoot = await mkdtemp(path.join(os.tmpdir(), "agent-identity-differential-"));
  const baseline = path.join(suiteRoot, "go-baseline");
  const archive = path.join(suiteRoot, "go-baseline.tar");
  await runChecked("git", ["archive", "--format=tar", "-o", archive, "go-baseline-v0.1.0"], { cwd: repositoryRoot });
  await mkdir(baseline);
  await runChecked("tar", ["-xf", archive, "-C", baseline]);
  goBinary = path.join(suiteRoot, "agent-identity-go");
  await runChecked("go", ["build", "-trimpath", "-o", goBinary, "./cmd/agent-identity"], { cwd: baseline });
  const probeDirectory = path.join(baseline, "cmd/keychain-compat-probe");
  await mkdir(probeDirectory, { recursive: true });
  await writeFile(path.join(probeDirectory, "main.go"), goKeychainProbeSource);
  goKeychainProbe = path.join(suiteRoot, "keychain-compat-probe");
  await runChecked("go", ["build", "-trimpath", "-o", goKeychainProbe, "./cmd/keychain-compat-probe"], { cwd: baseline });
  nodeBinary = path.join(repositoryRoot, "dist/bin/agent-identity.js");
  await chmod(nodeBinary, 0o755);
});

afterAll(async () => {
  if (suiteRoot !== "") await rm(suiteRoot, { recursive: true, force: true });
});

describe("Go baseline and Node commands/v2 differential", () => {
  it("contains the complete 52-leaf mapping plus eight safety failures", () => {
    expect(cases).toHaveLength(60);
    expect(new Set(cases.map(item => item.name)).size).toBe(60);
  });

  it("preserves bidirectional Go and Node Keychain compatibility", async () => {
    const reference = `keychain://agent-identity/compat/${process.pid}-${Date.now()}`;
    const nodeValue = JSON.stringify({ source: "node", value: "引号 ' and unicode ✓" });
    const goValue = JSON.stringify({ source: "go", value: "upgrade-and-rollback" });
    try {
      await secrets.set(reference, nodeValue);
      const goRead = await runProcess(goKeychainProbe, ["get", reference]);
      expect(goRead.exitCode, goRead.stderr).toBe(0);
      expect(goRead.stdout).toBe(nodeValue);

      const goWrite = await runProcess(goKeychainProbe, ["set", reference, goValue]);
      expect(goWrite.exitCode, goWrite.stderr).toBe(0);
      expect(await secrets.get(reference)).toBe(goValue);
    } finally {
      await secrets.delete(reference).catch(() => undefined);
    }
  });

  it("preserves bidirectional Go and Node profile compatibility", async () => {
    const fixture = await createFixture();
    const configDirectory = path.join(suiteRoot, "profile-compatibility");
    const sessionRef = `keychain://agent-identity/session/profile-compat-${process.pid}`;
    try {
      await mkdir(configDirectory, { recursive: true });
      await writeProfile(configDirectory, fixture.endpoint, sessionRef, "tenant_admin", false);
      await secrets.set(sessionRef, JSON.stringify({ access_token: "human-token" }));
      const environment = { ...process.env, AGENT_IDENTITY_CONFIG_DIR: configDirectory };

      const nodeWrite = await runProcess(nodeBinary, ["profiles", "set", "--client-id", "written-by-node", "--profile", "test", "--output", "json", "--non-interactive"], { env: environment });
      expect(nodeWrite.exitCode, nodeWrite.stderr).toBe(0);
      const goRead = await runProcess(goBinary, ["config", "get", "--profile", "test", "--output", "json", "--non-interactive"], { env: environment });
      expect(goRead.exitCode, goRead.stderr).toBe(0);
      expect(parseJson(goRead.stdout).data?.profile?.client_id).toBe("written-by-node");

      const goWrite = await runProcess(goBinary, ["config", "set", "--client-id", "written-by-go", "--profile", "test", "--output", "json", "--non-interactive"], { env: environment });
      expect(goWrite.exitCode, goWrite.stderr).toBe(0);
      const nodeRead = await runProcess(nodeBinary, ["profiles", "get", "--profile", "test", "--output", "json", "--non-interactive"], { env: environment });
      expect(nodeRead.exitCode, nodeRead.stderr).toBe(0);
      expect(parseJson(nodeRead.stdout).data?.profile?.client_id).toBe("written-by-go");
    } finally {
      await fixture.close();
      await secrets.delete(sessionRef).catch(() => undefined);
    }
  });

  for (const commandCase of cases) {
    it(commandCase.name, async () => {
      const go = await runImplementation("go", commandCase);
      const node = await runImplementation("node", commandCase);
      expect(node.exitCode, `Node stderr: ${node.stderr}`).toBe(commandCase.expectedExit ?? 0);
      expect(go.exitCode, `Go stderr: ${go.stderr}`).toBe(commandCase.expectedExit ?? 0);
      if (commandCase.raw) {
        expect(go.stdout.trim().length).toBeGreaterThan(20);
        expect(node.stdout.trim().length).toBeGreaterThan(20);
      } else if ((commandCase.expectedExit ?? 0) === 0) {
        const goEnvelope = normalizeEnvelope(parseJson(go.stdout), commandCase.name);
        const nodeEnvelope = normalizeEnvelope(parseJson(node.stdout), commandCase.name);
        expect(nodeEnvelope).toEqual(goEnvelope);
      } else {
        const goFailure = parseJson(go.stderr);
        const nodeFailure = parseJson(node.stderr);
        expect(nodeFailure.error?.code).toBe(goFailure.error?.code);
      }
      expect(normalizeWire(node.requests)).toEqual(normalizeWire(go.requests));
    });
  }
});

async function runImplementation(implementation: "go" | "node", commandCase: CommandCase): Promise<RunResult> {
  const fixture = await createFixture();
  const caseKey = commandCase.name.replaceAll(/[^a-z0-9]+/giu, "-").replaceAll(/^-|-$/gu, "").toLowerCase();
  const configDirectory = path.join(suiteRoot, `${caseKey}-${implementation}`);
  const sessionRef = `keychain://agent-identity/session/differential-${caseKey}-${implementation}`;
  const credentialRef = "keychain://agent-identity/credential/cred-1";
  const authorizationRefs = ["pkce", "code", "callback", "url"].map(suffix => `keychain://agent-identity/authorization/auth-1/${suffix}`);
  try {
    await mkdir(configDirectory, { recursive: true });
    if (!commandCase.login) {
      await writeProfile(configDirectory, fixture.endpoint, sessionRef, commandCase.role ?? "tenant_admin", commandCase.extraProfile ?? false);
      await secrets.set(sessionRef, JSON.stringify({ access_token: "human-token", refresh_token: "refresh-token" }));
    }
    if (commandCase.credential) {
      await secrets.set(credentialRef, JSON.stringify({ credential_id: "cred-1", client_secret: "credential-secret" }));
    }
    if (commandCase.authorization) {
      await secrets.set(authorizationRefs[0] ?? "", "pkce-verifier");
      await secrets.set(authorizationRefs[1] ?? "", "authorization-code");
    }
    const source = implementation === "go" ? commandCase.go : commandCase.node;
    const arguments_ = source.map(value => value === "<endpoint>" ? fixture.endpoint : value);
    arguments_.push("--output", "json", "--non-interactive");
    if (!commandCase.login) arguments_.push("--profile", "test");
    const result = await runProcess(implementation === "go" ? goBinary : nodeBinary, arguments_, {
      env: { ...process.env, AGENT_IDENTITY_CONFIG_DIR: configDirectory },
      input: commandCase.input ?? ""
    });
    return { ...result, requests: fixture.requests };
  } finally {
    await fixture.close();
    for (const reference of [sessionRef, credentialRef, ...authorizationRefs, "keychain://agent-identity/session/test", "keychain://agent-identity/session/alt"]) {
      await secrets.delete(reference).catch(() => undefined);
    }
  }
}

async function writeProfile(directory: string, endpoint: string, sessionRef: string, role: "user" | "tenant_admin", extra: boolean): Promise<void> {
  const profiles: Record<string, unknown> = {
    test: {
      endpoint,
      client_id: "client-1",
      login_type: role,
      subject_id: role === "user" ? "user-1" : "admin-1",
      selected_user_pool_id: "pool-1",
      secret_ref: sessionRef
    }
  };
  if (extra) {
    profiles.alt = {
      endpoint,
      client_id: "client-1",
      login_type: role,
      subject_id: "alt-1",
      selected_user_pool_id: "pool-1",
      secret_ref: "keychain://agent-identity/session/alt"
    };
    await secrets.set("keychain://agent-identity/session/alt", JSON.stringify({ access_token: "human-token" }));
  }
  await writeFile(path.join(directory, "config.json"), JSON.stringify({
    api_version: "agent-identity.cli/v1",
    current_profile: "test",
    profiles
  }, null, 2), { mode: 0o600 });
}

async function createFixture(): Promise<{ endpoint: string; requests: WireRequest[]; close: () => Promise<void> }> {
  const requests: WireRequest[] = [];
  const server = http.createServer((incoming, response) => {
    const chunks: Buffer[] = [];
    incoming.on("data", chunk => chunks.push(Buffer.from(chunk)));
    incoming.on("end", () => {
      const request: WireRequest = {
        method: incoming.method ?? "",
        target: incoming.url ?? "",
        headers: incoming.headers,
        body: Buffer.concat(chunks).toString("utf8")
      };
      requests.push(request);
      respond(request, response);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("differential fixture failed to listen");
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise<void>(resolve => server.close(() => resolve()))
  };
}

function respond(request: WireRequest, response: http.ServerResponse): void {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("X-Request-Id", "req-differential");
  const pathname = new URL(request.target, "http://fixture").pathname;
  if (pathname === "/oidc/token") {
    response.end('{"access_token":"refreshed-token","refresh_token":"refreshed-refresh"}');
  } else if (pathname === "/oidc/token/revocation") {
    response.statusCode = 200;
    response.end("");
  } else if (pathname === "/api/v3/agent-identity/admin/user-pools") {
    response.end('{"data":{"list":[{"id":"pool-1"}]}}');
  } else if (pathname === "/api/v3/agent-runtime/token") {
    response.end('{"data":{"access_token":"runtime-jwt","jti":"jti-1","expires_in":300}}');
  } else if (pathname.startsWith("/api/v3/agent-runtime/providers/")) {
    response.end('{"order_id":"order-1","status":"ok"}');
  } else if (request.method === "POST" && (pathname.endsWith("/credentials") || pathname.endsWith("/rotate"))) {
    response.end('{"data":{"credential":{"credential_id":"cred-1","expires_at":"2030-01-01T00:00:00Z"},"delivery":{"delivery_id":"delivery-1","delivery_code":"delivery-code"}}}');
  } else if (pathname.includes("/credential-deliveries/")) {
    response.end('{"data":{"credential_id":"cred-1","client_secret":"credential-secret"}}');
  } else if (request.method === "POST" && pathname.endsWith("/authorization-requests")) {
    response.end('{"data":{"request":{"request_id":"auth-1","status":"PENDING"}}}');
  } else if (pathname.endsWith("/consent")) {
    response.end('{"data":{"authorization_code":"authorization-code","redirect_uri":"http://127.0.0.1:39000/callback"}}');
  } else if (pathname.endsWith("/exchange")) {
    response.end('{"data":{"grant_id":"grant-1","status":"ACTIVE","version":1}}');
  } else if (request.method === "GET" && pathname.endsWith("/authorization-requests/auth-1")) {
    response.end('{"data":{"request_id":"auth-1","status":"APPROVED","grant_id":"grant-1"}}');
  } else if (request.method === "POST" && pathname.endsWith("/agents")) {
    response.end('{"data":{"id":"agt-1","record_version":1}}');
  } else {
    response.end('{"data":{"id":"resource-1","status":"OK","record_version":1,"list":[]}}');
  }
}

function normalizeEnvelope(value: Record<string, any>, name: string): Record<string, any> {
  const normalized = normalizeValue(value) as Record<string, any>;
  if (name === "auth login") delete normalized.request_id;
  if (name === "profiles get" && normalized.data) normalized.data.config_path = "<config-path>";
  if (name === "version") {
    return {
      api_version: normalized.api_version,
      kind: normalized.kind,
      data: {
        cli_version: normalized.data?.cli_version,
        api_version: normalized.data?.api_version,
        server_contract: normalized.data?.server_contract
      },
      warnings: normalized.warnings
    };
  }
  return normalized;
}

function normalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeValue(item)]));
  }
  if (typeof value !== "string") return value;
  return value
    .replaceAll(/keychain:\/\/agent-identity\/[^"\s]+/gu, "<secret-ref>")
    .replaceAll(/\/tmp\/agent-identity-differential-[^"\s]+\/[^"\s]+\/config\.json/gu, "<config-path>")
    .replaceAll(/http:\/\/127\.0\.0\.1:\d+/gu, "<endpoint>");
}

function normalizeWire(requests: WireRequest[]): unknown[] {
  return requests.map(request => {
    const url = new URL(request.target, "http://fixture");
    url.searchParams.sort();
    return {
      method: request.method,
      target: `${url.pathname}${url.search}`,
      headers: {
        authorization: request.headers.authorization ?? "",
        user_pool: request.headers["x-authing-userpool-id"] ?? "",
        content_type: request.headers["content-type"] ?? "",
        request_id: request.headers["x-request-id"] ?? "",
        idempotency_key: Boolean(request.headers["idempotency-key"]),
        human_session: Boolean(request.headers["x-human-session-id"])
      },
      body: normalizeBody(request.body)
    };
  });
}

function normalizeBody(body: string): unknown {
  if (body === "") return "";
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    if ("pkce_challenge" in parsed) parsed.pkce_challenge = "<pkce-challenge>";
    if ("redirect_uri" in parsed) parsed.redirect_uri = "<redirect-uri>";
    return parsed;
  } catch {
    const form = new URLSearchParams(body);
    form.sort();
    return form.toString();
  }
}

async function runProcess(command: string, arguments_: string[], options: {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  input?: string;
} = {}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += String(chunk); });
    child.stderr.on("data", chunk => { stderr += String(chunk); });
    child.once("error", reject);
    child.once("exit", code => resolve({ exitCode: code ?? 1, stdout, stderr }));
    child.stdin.end(options.input ?? "");
  });
}

async function runChecked(command: string, arguments_: string[], options: {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  input?: string;
} = {}): Promise<void> {
  const result = await runProcess(command, arguments_, options);
  if (result.exitCode !== 0) {
    throw new Error(`${command} ${arguments_.join(" ")} failed with exit ${result.exitCode}\n${result.stdout}\n${result.stderr}`);
  }
}

function parseJson(content: string): Record<string, any> {
  return JSON.parse(content.trim()) as Record<string, any>;
}

const credentialArguments = ["--credential", "keychain://agent-identity/credential/cred-1", "--grant-id", "grant-1", "--audience", "orders"];
const goKeychainProbeSource = `package main

import (
	"fmt"
	"os"

	"github.com/Authing/genauth-agent-cli/internal/cli/secretstore"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: keychain-compat-probe get <reference> | set <reference> <value>")
		os.Exit(2)
	}
	store := secretstore.New()
	var err error
	switch os.Args[1] {
	case "get":
		var value string
		value, err = store.Get(os.Args[2])
		if err == nil {
			fmt.Print(value)
		}
	case "set":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		err = store.Set(os.Args[2], os.Args[3])
	default:
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`;
const cases: CommandCase[] = [
  { name: "agents capability submit", go: ["agents", "submit", "--agent-id", "agt-1", "--version", "1"], node: ["agents", "capability", "submit", "--agent-id", "agt-1", "--version", "1"] },
  { name: "agents capability update", go: ["agents", "capability", "update", "--agent-id", "agt-1", "--audience", "orders", "--permission-id", "policy-1", "--version", "0"], node: ["agents", "capability", "update", "--agent-id", "agt-1", "--audience", "orders", "--permission-id", "policy-1", "--version", "0"] },
  { name: "agents capability withdraw", go: ["agents", "withdraw", "--agent-id", "agt-1", "--version", "1", "--reason", "edit", "--yes"], node: ["agents", "capability", "withdraw", "--agent-id", "agt-1", "--version", "1", "--reason", "edit", "--yes"] },
  { name: "agents create", go: ["agents", "create", "--identifier", "orders-agent", "--display-name", "Orders", "--description", "purpose", "--owner-user-id", "user-1", "--application-id", "app-1", "--audience", "orders", "--permission-id", "policy-1"], node: ["agents", "create", "--identifier", "orders-agent", "--display-name", "Orders", "--description", "purpose", "--owner-user-id", "user-1", "--application-id", "app-1", "--audience", "orders", "--permission-id", "policy-1"] },
  { name: "agents get", go: ["agents", "get", "--agent-id", "agt-1"], node: ["agents", "get", "--agent-id", "agt-1"] },
  { name: "agents lifecycle archive", go: ["agents", "lifecycle", "archive", "--agent-id", "agt-1", "--version", "1", "--reason", "retired", "--yes"], node: ["agents", "lifecycle", "archive", "--agent-id", "agt-1", "--version", "1", "--reason", "retired", "--yes"] },
  { name: "agents lifecycle pause", go: ["agents", "lifecycle", "pause", "--agent-id", "agt-1", "--version", "1", "--reason", "maintenance"], node: ["agents", "lifecycle", "pause", "--agent-id", "agt-1", "--version", "1", "--reason", "maintenance"] },
  { name: "agents lifecycle resume", go: ["agents", "lifecycle", "resume", "--agent-id", "agt-1", "--version", "2", "--reason", "ready"], node: ["agents", "lifecycle", "resume", "--agent-id", "agt-1", "--version", "2", "--reason", "ready"] },
  { name: "agents list", go: ["agents", "list", "--status", "ACTIVE", "--search", "orders"], node: ["agents", "list", "--status", "ACTIVE", "--search", "orders"] },
  { name: "agents readiness", go: ["agents", "readiness", "--agent-id", "agt-1"], node: ["agents", "readiness", "--agent-id", "agt-1"] },
  { name: "agents settings get", go: ["agents", "settings", "get", "--agent-id", "agt-1"], node: ["agents", "settings", "get", "--agent-id", "agt-1"] },
  { name: "agents settings submit", go: ["agents", "settings", "submit", "--agent-id", "agt-1"], node: ["agents", "settings", "submit", "--agent-id", "agt-1"] },
  { name: "agents settings update", go: ["agents", "settings", "update", "--agent-id", "agt-1", "--authorization-mode", "explicit-only", "--token-ttl", "5m", "--max-user-grant-ttl", "1h", "--redirect-uri", "https://app.example/callback", "--credential-ttl", "24h", "--rotation-overlap", "30s", "--version", "0"], node: ["agents", "settings", "update", "--agent-id", "agt-1", "--authorization-mode", "explicit-only", "--token-ttl", "5m", "--max-user-grant-ttl", "1h", "--redirect-uri", "https://app.example/callback", "--credential-ttl", "24h", "--rotation-overlap", "30s", "--version", "0"] },
  { name: "agents update", go: ["agents", "update", "--agent-id", "agt-1", "--display-name", "Orders v2", "--description", "updated", "--owner-user-id", "user-1", "--version", "2"], node: ["agents", "update", "--agent-id", "agt-1", "--display-name", "Orders v2", "--description", "updated", "--owner-user-id", "user-1", "--version", "2"] },
  { name: "approvals approve", go: ["approvals", "approve", "--approval-id", "apr-1", "--version", "1", "--reason", "ok", "--yes"], node: ["approvals", "approve", "--approval-id", "apr-1", "--version", "1", "--reason", "ok", "--yes"] },
  { name: "approvals get", go: ["approvals", "get", "--approval-id", "apr-1"], node: ["approvals", "get", "--approval-id", "apr-1"] },
  { name: "approvals list", go: ["approvals", "list", "--status", "pending"], node: ["approvals", "list", "--status", "pending"] },
  { name: "approvals reject", go: ["approvals", "reject", "--approval-id", "apr-1", "--version", "1", "--reason", "no", "--yes", "--settings"], node: ["approvals", "reject", "--approval-id", "apr-1", "--version", "1", "--reason", "no", "--yes", "--settings"] },
  { name: "audit list", go: ["audit", "list", "--agent-id", "agt-1", "--action", "TOKEN_ISSUED"], node: ["audit", "list", "--agent-id", "agt-1", "--action", "TOKEN_ISSUED"] },
  { name: "auth login", go: ["auth", "login", "--admin", "--profile-name", "test", "--endpoint", "<endpoint>", "--allow-insecure-localhost", "--user-pool-id", "pool-1", "--client-id", "client-1", "--session-token-stdin"], node: ["auth", "login", "--admin", "--profile-name", "test", "--endpoint", "<endpoint>", "--allow-insecure-localhost", "--user-pool-id", "pool-1", "--client-id", "client-1", "--session-token-stdin"], input: "human-token", login: true },
  { name: "auth logout", go: ["auth", "logout"], node: ["auth", "logout"] },
  { name: "auth refresh", go: ["auth", "refresh"], node: ["auth", "refresh"] },
  { name: "auth select-user-pool", go: ["auth", "switch-user-pool", "--user-pool-id", "pool-1"], node: ["auth", "select-user-pool", "--user-pool-id", "pool-1"] },
  { name: "auth status", go: ["auth", "status"], node: ["auth", "status"] },
  { name: "authorizations cancel", go: ["authorizations", "cancel", "--authorization-id", "auth-1", "--yes"], node: ["authorizations", "cancel", "--authorization-id", "auth-1", "--yes"] },
  { name: "authorizations consent", go: ["authorizations", "consent", "--authorization-id", "auth-1"], node: ["authorizations", "consent", "--authorization-id", "auth-1"], role: "user" },
  { name: "authorizations create", go: ["authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "explicit", "--redirect-uri", "http://127.0.0.1:39000/callback"], node: ["authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "explicit", "--redirect-uri", "http://127.0.0.1:39000/callback"] },
  { name: "authorizations deny", go: ["authorizations", "deny", "--authorization-id", "auth-1", "--reason", "declined", "--yes"], node: ["authorizations", "deny", "--authorization-id", "auth-1", "--reason", "declined", "--yes"], role: "user" },
  { name: "authorizations exchange", go: ["authorizations", "exchange", "--authorization-id", "auth-1"], node: ["authorizations", "exchange", "--authorization-id", "auth-1"], authorization: true },
  { name: "authorizations get", go: ["authorizations", "get", "--authorization-id", "auth-1"], node: ["authorizations", "get", "--authorization-id", "auth-1"] },
  { name: "authorizations wait", go: ["authorizations", "wait", "--authorization-id", "auth-1"], node: ["authorizations", "wait", "--authorization-id", "auth-1"] },
  { name: "completion", go: ["completion", "bash"], node: ["completion", "bash"], raw: true },
  { name: "credentials create", go: ["credentials", "create", "--agent-id", "agt-1"], node: ["credentials", "create", "--agent-id", "agt-1"] },
  { name: "credentials list", go: ["credentials", "list", "--agent-id", "agt-1"], node: ["credentials", "list", "--agent-id", "agt-1"] },
  { name: "credentials revoke", go: ["credentials", "revoke", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"], node: ["credentials", "revoke", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"], credential: true },
  { name: "credentials rotate", go: ["credentials", "rotate", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"], node: ["credentials", "rotate", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"] },
  { name: "doctor", go: ["doctor"], node: ["doctor"] },
  { name: "grants list", go: ["authorizations", "list-grants"], node: ["grants", "list"] },
  { name: "grants revoke", go: ["authorizations", "revoke", "--grant-id", "grant-1", "--version", "1", "--reason", "finished", "--yes"], node: ["grants", "revoke", "--grant-id", "grant-1", "--version", "1", "--reason", "finished", "--yes"] },
  { name: "permissions get", go: ["permissions", "get", "--permission-id", "policy-1"], node: ["permissions", "get", "--permission-id", "policy-1"] },
  { name: "permissions list", go: ["permissions", "list", "--page-size", "5", "--audience", "orders", "--action", "read", "--keyword", "invoice"], node: ["permissions", "list", "--page-size", "5", "--audience", "orders", "--action", "read", "--keyword", "invoice"] },
  { name: "permissions validate", go: ["permissions", "validate", "--audience", "orders", "--permission-id", "policy-1"], node: ["permissions", "validate", "--audience", "orders", "--permission-id", "policy-1"] },
  { name: "profiles get", go: ["config", "get"], node: ["profiles", "get"] },
  { name: "profiles list", go: ["config", "list-profiles"], node: ["profiles", "list"] },
  { name: "profiles set", go: ["config", "set", "--client-id", "client-2"], node: ["profiles", "set", "--client-id", "client-2"] },
  { name: "profiles use", go: ["config", "use-profile", "--name", "alt"], node: ["profiles", "use", "--name", "alt"], extraProfile: true },
  { name: "providers call", go: ["api", "call", ...credentialArguments, "--provider", "orders-provider", "--method", "GET", "--path", "/orders/1"], node: ["providers", "call", ...credentialArguments, "--provider", "orders-provider", "--method", "GET", "--path", "/orders/1"], credential: true },
  { name: "tokens inspect", go: ["tokens", "inspect", "--token-stdin"], node: ["tokens", "inspect", "--token-stdin"], input: `${Buffer.from('{"alg":"RS256"}').toString("base64url")}.${Buffer.from('{"sub":"user-1"}').toString("base64url")}.signature` },
  { name: "tokens issue", go: ["tokens", "issue", ...credentialArguments, "--permission-id", "policy-1", "--ttl-seconds", "300"], node: ["tokens", "issue", ...credentialArguments, "--permission-id", "policy-1", "--ttl-seconds", "300"], credential: true },
  { name: "tokens list", go: ["tokens", "list", "--agent-id", "agt-1"], node: ["tokens", "list", "--agent-id", "agt-1"] },
  { name: "tokens revoke", go: ["tokens", "revoke", "--jti", "jti-1", "--reason", "incident", "--yes"], node: ["tokens", "revoke", "--jti", "jti-1", "--reason", "incident", "--yes"] },
  { name: "version", go: ["version"], node: ["version"] },
  { name: "error admin owner required", go: ["agents", "create", "--identifier", "a", "--display-name", "A", "--application-id", "app-1"], node: ["agents", "create", "--identifier", "a", "--display-name", "A", "--application-id", "app-1"], expectedExit: 2 },
  { name: "error user silent authorization", go: ["authorizations", "create", "--agent-id", "agt-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent", "--yes"], node: ["authorizations", "create", "--agent-id", "agt-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent", "--yes"], role: "user", expectedExit: 2 },
  { name: "error credential secret acknowledgement", go: ["credentials", "create", "--agent-id", "agt-1", "--show-secret"], node: ["credentials", "create", "--agent-id", "agt-1", "--show-secret"], expectedExit: 2 },
  { name: "error provider unsafe path", go: ["api", "call", ...credentialArguments, "--provider", "orders-provider", "--path", "https://evil.example/x"], node: ["providers", "call", ...credentialArguments, "--provider", "orders-provider", "--path", "https://evil.example/x"], credential: true, expectedExit: 2 },
  { name: "error archive confirmation", go: ["agents", "lifecycle", "archive", "--agent-id", "agt-1", "--version", "1", "--reason", "retired"], node: ["agents", "lifecycle", "archive", "--agent-id", "agt-1", "--version", "1", "--reason", "retired"], expectedExit: 2 },
  { name: "error approval confirmation", go: ["approvals", "approve", "--approval-id", "apr-1"], node: ["approvals", "approve", "--approval-id", "apr-1"], expectedExit: 2 },
  { name: "error malformed token", go: ["tokens", "inspect", "--token-stdin"], node: ["tokens", "inspect", "--token-stdin"], input: "not-a-jwt", expectedExit: 2 },
  { name: "error invalid correlation", go: ["agents", "list", "--correlation-id", "not-a-uuid"], node: ["agents", "list", "--correlation-id", "not-a-uuid"], expectedExit: 2 }
];
