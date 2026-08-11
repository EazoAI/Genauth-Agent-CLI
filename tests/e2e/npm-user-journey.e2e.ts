import { spawn } from "node:child_process";
import http from "node:http";
import { once } from "node:events";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ProfileStore } from "../../src/storage/profile-store.js";
import { KeychainSecretStore } from "../../src/storage/secret-store.js";

interface JourneyState {
  capability: "DRAFT" | "PENDING" | "ACTIVE";
  settings: "NONE" | "DRAFT" | "PENDING" | "ACTIVE";
  credential: "NONE" | "ACTIVE" | "REVOKED";
  authorization: "NONE" | "PENDING" | "CONSENTED" | "APPROVED";
  grant: "NONE" | "ACTIVE" | "REVOKED";
  token: "NONE" | "ACTIVE" | "REVOKED";
  providerCalls: number;
  auditEvents: string[];
}

interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  envelope?: Record<string, any>;
}

const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const secretStore = new KeychainSecretStore("darwin");
const transcript: string[] = [];
let testRoot = "";
let configDirectory = "";
let cli = "";
let fixture: Awaited<ReturnType<typeof createJourneyFixture>>;

beforeAll(async () => {
  if (process.platform !== "darwin") throw new Error("installed CLI user-journey gate must run on macOS with a real Keychain");
  testRoot = await mkdtemp(path.join(os.tmpdir(), "genauth-agent-npm-e2e-"));
  configDirectory = path.join(testRoot, "config");
  const packs = path.join(testRoot, "packs");
  const prefix = path.join(testRoot, "install");
  await mkdir(configDirectory, { recursive: true });
  await mkdir(packs, { recursive: true });
  const packed = await run("npm", ["pack", repositoryRoot, "--pack-destination", packs, "--silent"]);
  expect(packed.exitCode, packed.stderr).toBe(0);
  const archiveName = packed.stdout.trim().split(/\r?\n/u).at(-1);
  if (!archiveName) throw new Error("npm pack did not return an archive");
  const installed = await run("npm", ["install", "--global", "--prefix", prefix, path.join(packs, archiveName), "--silent"]);
  expect(installed.exitCode, installed.stderr).toBe(0);
  cli = path.join(prefix, "bin", "genauth-agent");
  fixture = await createJourneyFixture();
});

afterAll(async () => {
  await fixture?.close();
  for (const reference of [
    "keychain://genauth-agent/session/agent-owner",
    "keychain://genauth-agent/session/agent-approver",
    "keychain://genauth-agent/session/agent-user",
    "keychain://genauth-agent/credential/cred-1",
    "keychain://genauth-agent/authorization/auth-1/pkce",
    "keychain://genauth-agent/authorization/auth-1/code",
    "keychain://genauth-agent/authorization/auth-1/callback",
    "keychain://genauth-agent/authorization/auth-1/url"
  ]) await secretStore.delete(reference).catch(() => undefined);
  if (testRoot !== "") await rm(testRoot, { recursive: true, force: true });
});

describe("npm-installed complete Agent Identity user journey", () => {
  it("completes separate-owner approval, settings, Credential, explicit authorization, Token, Provider, and revoke phases", async () => {
    const version = await invoke(undefined, ["version"]);
    expect(version.envelope?.data).toMatchObject({
      command_contract: "genauth-agent.commands/v2",
      runtime: "node"
    });

    await login("agent-owner", "owner-token");
    await login("agent-approver", "approver-token");
    await seedLegacyMemberProfile("agent-user", "user-token");

    for (const [profile, loginType, subject] of [
      ["agent-owner", "tenant_admin", "owner-1"],
      ["agent-approver", "tenant_admin", "approver-1"],
      ["agent-user", "user", "user-1"]
    ] as const) {
      const status = await invoke(profile, ["auth", "status"]);
      expect(status.envelope?.data).toMatchObject({
        login_type: loginType,
        selected_user_pool_id: "pool-1"
      });
      if (loginType === "tenant_admin") {
        expect(status.envelope?.data).toMatchObject({
          selected_user_pool_name: "Development",
          selected_user_pool_domain: "dev"
        });
      }
      expect(JSON.stringify(status.envelope)).toContain(subject);
    }

    const pools = await invoke("agent-owner", ["auth", "list-user-pools"]);
    expect(pools.envelope?.data).toMatchObject({
      list: [{ id: "pool-1", name: "Development", domain: "dev", selected: true }]
    });

    const doctor = await invoke("agent-owner", ["doctor"]);
    expect(doctor.envelope).toMatchObject({
      kind: "DoctorReport",
      data: { selected_user_pool_name: "Development", selected_user_pool_domain: "dev" }
    });

    const permissions = await invoke("agent-owner", ["permissions", "list"]);
    expect(unwrap(permissions.envelope?.data)).toMatchObject({ list: [{ id: "policy-orders-read" }] });
    const permission = await invoke("agent-owner", ["permissions", "get", "--permission-id", "policy-orders-read"]);
    expect(unwrap(permission.envelope?.data)).toMatchObject({ id: "policy-orders-read", audience: "orders" });

    const created = await invoke("agent-owner", [
      "agents", "create",
      "--identifier", "orders-agent",
      "--display-name", "Orders Agent",
      "--description", "Read approved orders",
      "--owner-user-id", "owner-1",
      "--application-id", "app-orders",
      "--permission-id", "policy-orders-read"
    ]);
    expect(created.envelope?.kind).toBe("AgentWithCapabilityDraft");
    expect(fixture.state.capability).toBe("DRAFT");

    await invoke("agent-owner", ["agents", "get", "--agent-id", "agt-1"]);
    const submitted = await invoke("agent-owner", ["agents", "capability", "submit", "--agent-id", "agt-1", "--version", "1"]);
    expect(unwrap(submitted.envelope?.data)).toMatchObject({ approval_id: "apr-cap-1" });
    expect(fixture.state.capability).toBe("PENDING");

    const selfApproval = await invoke("agent-owner", [
      "approvals", "approve", "--approval-id", "apr-cap-1", "--version", "1", "--reason", "self", "--yes"
    ], "", 4);
    expect(selfApproval.envelope?.error?.code).toBe("SELF_APPROVAL_FORBIDDEN");
    expect(fixture.state.capability).toBe("PENDING");

    const frozen = await invoke("agent-approver", ["approvals", "get", "--approval-id", "apr-cap-1"]);
    expect(unwrap(frozen.envelope?.data)).toMatchObject({ requester_id: "owner-1", audience: "orders" });
    await invoke("agent-approver", [
      "approvals", "approve", "--approval-id", "apr-cap-1", "--version", "1", "--reason", "least privilege reviewed", "--yes"
    ]);
    expect(fixture.state.capability).toBe("ACTIVE");

    await invoke("agent-owner", ["agents", "settings", "get", "--agent-id", "agt-1"]);
    await invoke("agent-owner", [
      "agents", "settings", "update", "--agent-id", "agt-1",
      "--authorization-mode", "silent-if-allowed",
      "--token-ttl", "5m",
      "--max-user-grant-ttl", "1h",
      "--credential-ttl", "24h",
      "--rotation-overlap", "30s",
      "--redirect-uri", "http://127.0.0.1:39001/callback",
      "--version", "0"
    ]);
    await invoke("agent-owner", ["agents", "settings", "submit", "--agent-id", "agt-1"]);
    expect(fixture.state.settings).toBe("PENDING");
    await invoke("agent-approver", ["approvals", "get", "--settings", "--approval-id", "apr-settings-1"]);
    await invoke("agent-approver", [
      "approvals", "approve", "--settings", "--approval-id", "apr-settings-1", "--version", "1", "--reason", "settings reviewed", "--yes"
    ]);
    expect(fixture.state.settings).toBe("ACTIVE");

    const blocked = await invoke("agent-owner", ["agents", "readiness", "--agent-id", "agt-1"]);
    expect(unwrap(blocked.envelope?.data)).toMatchObject({ blockers: ["credential_required"] });
    const credential = await invoke("agent-owner", ["credentials", "create", "--agent-id", "agt-1"]);
    expect(credential.envelope?.data).toMatchObject({
      credential_id: "cred-1",
      secret_ref: "keychain://genauth-agent/credential/cred-1"
    });
    expect(JSON.stringify(credential.envelope)).not.toContain("credential-secret");
    await invoke("agent-owner", ["credentials", "list", "--agent-id", "agt-1"]);
    const ready = await invoke("agent-owner", ["agents", "readiness", "--agent-id", "agt-1"]);
    expect(unwrap(ready.envelope?.data)).toMatchObject({ ready: true, blockers: [] });

    const authorization = await invoke("agent-owner", [
      "authorizations", "create",
      "--agent-id", "agt-1",
      "--user-id", "user-1",
      "--audience", "orders",
      "--permission-id", "policy-orders-read",
      "--mode", "explicit",
      "--redirect-uri", "http://127.0.0.1:39001/callback"
    ]);
    expect(authorization.envelope?.data.authorization_url).toContain("request_id=auth-1");
    expect(authorization.envelope?.data.authorization_url).toContain("user_pool_id=pool-1");
    expect(JSON.stringify(authorization.envelope)).not.toContain("pkce-verifier");

    const consent = await invoke("agent-user", ["authorizations", "consent", "--authorization-id", "auth-1"]);
    expect(consent.envelope?.data).toHaveProperty("code_ref");
    expect(JSON.stringify(consent.envelope)).not.toContain("authorization-code");
    const completed = await invoke("agent-owner", ["--timeout", "5s", "authorizations", "wait", "--authorization-id", "auth-1"]);
    expect(unwrap(completed.envelope?.data)).toMatchObject({ grant_id: "grant-1", status: "ACTIVE" });
    expect(fixture.state.grant).toBe("ACTIVE");

    const grants = await invoke("agent-owner", ["grants", "list"]);
    expect(unwrap(grants.envelope?.data)).toMatchObject({
      list: [{ id: "grant-1", subject_id: "user-1", audience: "orders", permission_ids: ["policy-orders-read"], status: "ACTIVE" }]
    });

    const provider = await invoke("agent-owner", [
      "providers", "call",
      "--credential", "keychain://genauth-agent/credential/cred-1",
      "--grant-id", "grant-1",
      "--audience", "orders",
      "--provider", "orders-provider",
      "--method", "GET",
      "--path", "/orders/42"
    ]);
    expect(provider.envelope?.data).toEqual({ order_id: "42", decision: "allowed" });
    expect(fixture.state.providerCalls).toBe(1);

    const audit = await invoke("agent-owner", ["audit", "list", "--agent-id", "agt-1"]);
    expect(unwrap(audit.envelope?.data).list).toContain("PROVIDER_CALLED");
    await invoke("agent-owner", ["tokens", "list", "--agent-id", "agt-1"]);
    await invoke("agent-owner", ["tokens", "revoke", "--jti", "jti-1", "--reason", "journey complete", "--yes"]);
    await invoke("agent-owner", ["grants", "revoke", "--grant-id", "grant-1", "--version", "1", "--reason", "journey complete", "--yes"]);
    await invoke("agent-owner", ["credentials", "revoke", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"]);
    expect(fixture.state).toMatchObject({ token: "REVOKED", grant: "REVOKED", credential: "REVOKED" });

    const revoked = await invoke("agent-owner", [
      "providers", "call",
      "--credential", "keychain://genauth-agent/credential/cred-1",
      "--grant-id", "grant-1",
      "--audience", "orders",
      "--provider", "orders-provider",
      "--path", "/orders/42"
    ], "", 3);
    expect(revoked.envelope?.error?.code).toBe("CREDENTIAL_NOT_FOUND");

    for (const profile of ["agent-user", "agent-approver", "agent-owner"]) await invoke(profile, ["auth", "logout"]);

    const combined = transcript.join("\n");
    for (const secret of ["owner-token", "approver-token", "user-token", "credential-secret", "runtime-jwt", "authorization-code"]) {
      expect(combined).not.toContain(secret);
    }
  });
});

async function login(profile: string, token: string): Promise<void> {
  await invoke(undefined, [
    "auth", "login",
    "--profile-name", profile,
    "--endpoint", fixture.endpoint,
    "--allow-insecure-localhost",
    "--user-pool-id", "pool-1",
    "--session-token-stdin"
  ], token);
}

async function seedLegacyMemberProfile(profile: string, token: string): Promise<void> {
  const secretRef = `keychain://genauth-agent/session/${profile}`;
  await secretStore.set(secretRef, JSON.stringify({ access_token: token }));
  const profileStore = new ProfileStore(path.join(configDirectory, "config.json"));
  const config = await profileStore.load();
  config.profiles[profile] = {
    endpoint: fixture.endpoint,
    client_id: "cli-client",
    login_type: "user",
    subject_id: "user-1",
    selected_user_pool_id: "pool-1",
    secret_ref: secretRef
  };
  await profileStore.save(config);
}

async function invoke(profile: string | undefined, arguments_: string[], input = "", expectedExit = 0): Promise<CliResult> {
  const result = await run(cli, [
    ...(profile ? ["--profile", profile] : []),
    ...arguments_,
    "--output", "json",
    "--non-interactive"
  ], { env: { ...process.env, GENAUTH_AGENT_CONFIG_DIR: configDirectory }, input });
  expect(result.exitCode, result.stderr).toBe(expectedExit);
  const serialized = expectedExit === 0 ? result.stdout : result.stderr;
  const envelope = serialized.trim() ? JSON.parse(serialized) as Record<string, any> : undefined;
  if (envelope) transcript.push(JSON.stringify(envelope));
  return { ...result, ...(envelope === undefined ? {} : { envelope }) };
}

async function createJourneyFixture(): Promise<{
  endpoint: string;
  state: JourneyState;
  close: () => Promise<void>;
}> {
  const state: JourneyState = {
    capability: "DRAFT",
    settings: "NONE",
    credential: "NONE",
    authorization: "NONE",
    grant: "NONE",
    token: "NONE",
    providerCalls: 0,
    auditEvents: []
  };
  const server = http.createServer((incoming, response) => {
    const chunks: Buffer[] = [];
    incoming.on("data", chunk => chunks.push(Buffer.from(chunk)));
    incoming.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      handleJourneyRequest(state, incoming, body, response);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("journey fixture failed to listen");
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    state,
    close: () => new Promise<void>(resolve => server.close(() => resolve()))
  };
}

function handleJourneyRequest(state: JourneyState, request: http.IncomingMessage, body: string, response: http.ServerResponse): void {
  const method = request.method ?? "";
  const pathname = new URL(request.url ?? "/", "http://fixture").pathname;
  const bearer = String(request.headers.authorization ?? "").replace(/^Bearer /u, "");
  const json = parseBody(body);
  response.setHeader("Content-Type", "application/json");
  response.setHeader("X-Request-Id", `req-${state.auditEvents.length + 1}`);

  if (pathname === "/api/v3/agent-identity/auth/config") return send(response, 200, { data: {
    client_id: "cli-client",
    authorization_endpoint: "/oidc/auth",
    token_endpoint: "/oidc/token",
    revocation_endpoint: "/oidc/token/revocation",
    scopes: ["openid", "profile", "offline_access"],
    code_challenge_method: "S256",
    redirect_uri_pattern: "http://127.0.0.1:*/callback"
  } });
  if (pathname === "/oidc/token/revocation") return send(response, 200, undefined);
  if (pathname === "/api/v3/agent-identity/admin/user-pools") {
    return send(response, 200, { data: { list: [{ id: "pool-1", name: "Development", domain: "dev", role: "OWNER" }] } });
  }
  if (pathname === "/api/v3/agent-identity/admin/context") return send(response, 200, { data: identityFor(bearer) });
  if (pathname === "/api/v3/agent-identity/me" && method === "GET") return send(response, 200, { data: identityFor(bearer) });
  if (pathname.endsWith("/permission-catalog") && method === "GET") return send(response, 200, { data: { list: [{ id: "policy-orders-read", audience: "orders", action: "read" }] } });
  if (pathname === "/api/v3/agent-identity/permission-catalog/policy-orders-read") return send(response, 200, { data: { id: "policy-orders-read", audience: "orders", action: "read" } });
  if (pathname === "/api/v3/get-application-simple-info") return send(response, 200, { data: {
    appId: "app-orders",
    appIdentifier: "orders",
    clientCredentialsEnabled: true
  } });

  if (pathname === "/api/v3/agent-identity/admin/agents" && method === "POST") {
    if (json.agent_type !== "company" || json.owner_user_id !== "owner-1") return sendError(response, 422, "INVALID_AGENT", "invalid company Agent");
    state.auditEvents.push("AGENT_CREATED");
    return send(response, 200, { data: { id: "agt-1", identifier: "orders-agent", record_version: 1 } });
  }
  if (pathname.endsWith("/agents/agt-1/capability-grant/draft") && method === "PUT") {
    state.capability = "DRAFT";
    return send(response, 200, { data: { agent_id: "agt-1", status: "DRAFT", record_version: 1, audience: "orders", permission_ids: ["policy-orders-read"] } });
  }
  if (pathname.endsWith("/agents/agt-1/capability-grant/submit") && method === "POST") {
    state.capability = "PENDING";
    return send(response, 200, { data: { approval_id: "apr-cap-1", version: 1, status: "PENDING" } });
  }
  if (pathname === "/api/v3/agent-identity/admin/approvals/apr-cap-1" && method === "GET") return send(response, 200, { data: { id: "apr-cap-1", requester_id: "owner-1", audience: "orders", permission_ids: ["policy-orders-read"], version: 1 } });
  if (pathname === "/api/v3/agent-identity/admin/approvals/apr-cap-1/approve" && method === "POST") {
    if (bearer === "owner-token") return sendError(response, 403, "SELF_APPROVAL_FORBIDDEN", "requester cannot approve their own request");
    state.capability = "ACTIVE";
    state.auditEvents.push("CAPABILITY_APPROVED");
    return send(response, 200, { data: { id: "apr-cap-1", status: "APPROVED", version: 1 } });
  }
  if (pathname.endsWith("/agents/agt-1/settings") && method === "GET") return send(response, 200, { data: { effective: state.settings === "ACTIVE" ? activeSettings() : null, draft: state.settings === "DRAFT" ? activeSettings() : null } });
  if (pathname.endsWith("/agents/agt-1/settings/draft") && method === "PUT") {
    state.settings = "DRAFT";
    return send(response, 200, { data: { ...json, status: "DRAFT", record_version: 1 } });
  }
  if (pathname.endsWith("/agents/agt-1/settings/submit") && method === "POST") {
    state.settings = "PENDING";
    return send(response, 200, { data: { approval_id: "apr-settings-1", version: 1, status: "PENDING" } });
  }
  if (pathname === "/api/v3/agent-identity/admin/settings-approvals/apr-settings-1" && method === "GET") return send(response, 200, { data: { id: "apr-settings-1", requester_id: "owner-1", version: 1, settings: activeSettings() } });
  if (pathname === "/api/v3/agent-identity/admin/settings-approvals/apr-settings-1/approve" && method === "POST") {
    if (bearer === "owner-token") return sendError(response, 403, "SELF_APPROVAL_FORBIDDEN", "requester cannot approve their own request");
    state.settings = "ACTIVE";
    state.auditEvents.push("SETTINGS_APPROVED");
    return send(response, 200, { data: { id: "apr-settings-1", status: "APPROVED", version: 1 } });
  }
  if (pathname.endsWith("/agents/agt-1/readiness") && method === "GET") {
    const blockers = state.credential === "ACTIVE" ? [] : ["credential_required"];
    return send(response, 200, { data: { ready: blockers.length === 0 && state.capability === "ACTIVE" && state.settings === "ACTIVE", blockers } });
  }
  if (pathname.endsWith("/agents/agt-1/credentials") && method === "POST") return send(response, 200, { data: { credential: { credential_id: "cred-1", expires_at: "2030-01-01T00:00:00Z" }, delivery: { delivery_id: "delivery-1", delivery_code: "delivery-code" } } });
  if (pathname.endsWith("/credential-deliveries/delivery-1/consume") && method === "POST") {
    state.credential = "ACTIVE";
    state.auditEvents.push("CREDENTIAL_CREATED");
    return send(response, 200, { data: { credential_id: "cred-1", client_secret: "credential-secret" } });
  }
  if (pathname.endsWith("/agents/agt-1/credentials") && method === "GET") return send(response, 200, { data: { list: [{ id: "cred-1", status: state.credential, expires_at: "2030-01-01T00:00:00Z" }] } });
  if (pathname.endsWith("/agents/agt-1/credentials/cred-1/revoke") && method === "POST") {
    state.credential = "REVOKED";
    return send(response, 200, { data: { id: "cred-1", status: "REVOKED" } });
  }
  if (pathname.endsWith("/agents/agt-1/authorization-requests") && method === "POST") {
    state.authorization = "PENDING";
    return send(response, 200, { data: { request: { request_id: "auth-1", status: "PENDING" } } });
  }
  if (pathname === "/api/v3/agent-identity/me/authorization-requests/auth-1/consent" && method === "POST") {
    if (bearer !== "user-token") return sendError(response, 403, "USER_REQUIRED", "target user required");
    state.authorization = "CONSENTED";
    return send(response, 200, { data: { authorization_code: "authorization-code", redirect_uri: "http://127.0.0.1:39001/callback" } });
  }
  if (pathname === "/api/v3/agent-identity/admin/authorization-requests/auth-1" && method === "GET") return send(response, 200, { data: { request_id: "auth-1", status: state.authorization } });
  if (pathname === "/api/v3/agent-identity/admin/authorization-requests/auth-1/exchange" && method === "POST") {
    if (!json.code_verifier) return sendError(response, 422, "PKCE_REQUIRED", "PKCE verifier required");
    state.authorization = "APPROVED";
    state.grant = "ACTIVE";
    state.auditEvents.push("USER_GRANT_CREATED");
    return send(response, 200, { data: { grant_id: "grant-1", status: "ACTIVE", version: 1, subject_id: "user-1", audience: "orders", permission_ids: ["policy-orders-read"] } });
  }
  if (pathname === "/api/v3/agent-identity/admin/agent-user-grants" && method === "GET") return send(response, 200, { data: { list: [{ id: "grant-1", subject_id: "user-1", audience: "orders", permission_ids: ["policy-orders-read"], status: state.grant, version: 1 }] } });
  if (pathname === "/api/v3/agent-identity/admin/agent-user-grants/grant-1/revoke" && method === "POST") {
    state.grant = "REVOKED";
    return send(response, 200, { data: { id: "grant-1", status: "REVOKED", version: 2 } });
  }
  if (pathname === "/api/v3/agent-runtime/token" && method === "POST") {
    if (String(request.headers.authorization ?? "") !== `Basic ${Buffer.from("cred-1:credential-secret").toString("base64")}` || state.credential !== "ACTIVE" || state.grant !== "ACTIVE") return sendError(response, 403, "RUNTIME_ACCESS_DENIED", "runtime access denied");
    state.token = "ACTIVE";
    state.auditEvents.push("TOKEN_ISSUED");
    return send(response, 200, { data: { access_token: "runtime-jwt", jti: "jti-1", expires_in: 300 } });
  }
  if (pathname === "/api/v3/agent-runtime/providers/orders-provider/orders/42" && method === "GET") {
    if (request.headers.authorization !== "Bearer runtime-jwt") return sendError(response, 401, "INVALID_TOKEN", "invalid runtime Token");
    state.providerCalls += 1;
    state.auditEvents.push("PROVIDER_CALLED");
    return send(response, 200, { order_id: "42", decision: "allowed" });
  }
  if (pathname.endsWith("/agents/agt-1/tokens") && method === "GET") return send(response, 200, { data: { list: [{ jti: "jti-1", status: state.token }] } });
  if (pathname === "/api/v3/agent-identity/admin/runtime/tokens/jti-1/revoke" && method === "POST") {
    state.token = "REVOKED";
    return send(response, 200, { data: { jti: "jti-1", status: "REVOKED" } });
  }
  if (pathname.endsWith("/audit-events") && method === "GET") return send(response, 200, { data: { list: state.auditEvents } });
  if (pathname.endsWith("/agents/agt-1") && method === "GET") return send(response, 200, { data: { id: "agt-1", capability_status: state.capability, settings_status: state.settings, record_version: 1 } });
  if (pathname.endsWith("/agents") && method === "GET") return send(response, 200, { data: { list: [{ id: "agt-1" }] } });
  return sendError(response, 404, "NOT_FOUND", `${method} ${pathname} is not implemented by the journey fixture`);
}

function identityFor(token: string): Record<string, unknown> {
  if (token === "owner-token") return { subject_id: "owner-1", login_type: "tenant_admin", selected_user_pool_id: "pool-1" };
  if (token === "approver-token") return { subject_id: "approver-1", login_type: "tenant_admin", selected_user_pool_id: "pool-1" };
  return { subject_id: "user-1", login_type: "user", selected_user_pool_id: "pool-1" };
}

function activeSettings(): Record<string, unknown> {
  return {
    authorization_mode: "SILENT_IF_ALLOWED",
    token_ttl_seconds: 300,
    max_user_grant_ttl_seconds: 3600,
    credential_ttl_seconds: 86400,
    rotation_overlap_seconds: 30,
    redirect_uris: ["http://127.0.0.1:39001/callback"],
    require_realtime_decision: true,
    record_version: 1
  };
}

function parseBody(body: string): Record<string, any> {
  if (!body) return {};
  try { return JSON.parse(body) as Record<string, any>; }
  catch { return Object.fromEntries(new URLSearchParams(body)); }
}

function send(response: http.ServerResponse, status: number, data: unknown): void {
  response.statusCode = status;
  response.end(data === undefined ? "" : JSON.stringify(data));
}

function sendError(response: http.ServerResponse, status: number, code: string, message: string): void {
  send(response, status, { error: { code, message } });
}

function unwrap(value: any): any {
  let current = value;
  for (let index = 0; index < 4 && current && typeof current === "object" && "data" in current; index += 1) current = current.data;
  return current;
}

async function run(command: string, arguments_: string[], options: { env?: NodeJS.ProcessEnv; input?: string } = {}): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, { env: options.env ?? process.env, stdio: ["pipe", "pipe", "pipe"], shell: false });
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
