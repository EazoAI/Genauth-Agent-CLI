import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Harness, RecordedRequest } from "../helpers/cli-harness.js";
import { createHarness } from "../helpers/cli-harness.js";

const active: Harness[] = [];
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(active.splice(0).map(harness => harness.close()));
  await Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

describe("management command boundaries", () => {
  it.each([
    ["tenant_admin", "/api/v3/agent-identity/admin/agents"],
    ["user", "/api/v3/agent-identity/me/agents"]
  ] as const)("routes %s Agent list through the correct GenAuth BFF", async (loginType, path) => {
    const harness = await fixture(loginType);
    await harness.run(["agents", "list"]);
    expect(harness.requests[0]?.path).toBe(path);
    expect(harness.requests[0]?.headers["x-authing-userpool-id"]).toBe("pool-1");
  });

  it.each([
    ["tenant_admin", "/api/v3/agent-identity/admin/context"],
    ["user", "/api/v3/agent-identity/me"]
  ] as const)("routes %s auth status through the exact identity context path", async (loginType, path) => {
    const harness = await fixture(loginType);
    await harness.run(["auth", "status"]);
    expect(harness.requests[0]?.path).toBe(path);
  });

  it("refreshes an expired session once and retries the original request", async () => {
    let agentCalls = 0;
    const harness = await createHarness({
      handler(request, response) {
        response.setHeader("Content-Type", "application/json");
        if (request.path === "/oidc/token") {
          expect(request.body).toContain("grant_type=refresh_token");
          response.end('{"access_token":"fresh-token","refresh_token":"fresh-refresh"}');
          return;
        }
        agentCalls += 1;
        if (agentCalls === 1) {
          response.statusCode = 401;
          response.end('{"error":{"code":"SESSION_EXPIRED","message":"expired"}}');
          return;
        }
        response.end('{"data":{"list":[]}}');
      }
    });
    active.push(harness);
    await harness.secrets.set("keychain://genauth-agent/session/test", JSON.stringify({
      access_token: "expired-token",
      refresh_token: "refresh-token"
    }));
    await harness.run(["agents", "list"]);
    expect(harness.requests.map(request => request.path)).toEqual([
      "/api/v3/agent-identity/admin/agents",
      "/oidc/token",
      "/api/v3/agent-identity/admin/agents"
    ]);
    expect(harness.requests[0]?.headers.authorization).toBe("Bearer expired-token");
    expect(harness.requests[2]?.headers.authorization).toBe("Bearer fresh-token");
    expect(await harness.secrets.get("keychain://genauth-agent/session/test")).toContain("fresh-refresh");
  });

  it("keeps the local login intact when remote logout revocation fails", async () => {
    const harness = await createHarness({
      handler(_request, response) {
        response.statusCode = 503;
        response.end("unavailable");
      }
    });
    active.push(harness);
    await expect(harness.run(["auth", "logout"])).rejects.toMatchObject({ code: "LOGOUT_REVOKE_FAILED" });
    expect((await harness.profileStore.load()).profiles.test).toBeDefined();
    await expect(harness.secrets.get("keychain://genauth-agent/session/test")).resolves.toContain("human-token");
  });

  it("warns only after remote logout and local profile removal when Keychain cleanup fails", async () => {
    const harness = await createHarness({
      handler(request, response) {
        expect(request.path).toBe("/oidc/token/revocation");
        response.statusCode = 200;
        response.end("");
      }
    });
    active.push(harness);
    harness.secrets.delete = async () => { throw new Error("keychain unavailable"); };
    const result = await harness.run(["auth", "logout"]);
    expect(JSON.parse(result.stdout).warnings).toEqual([
      "remote session was revoked and the local profile was removed, but its OS secret-store entry could not be removed"
    ]);
    expect((await harness.profileStore.load()).profiles.test).toBeUndefined();
  });

  it("requires an owner when an administrator creates an Agent", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "agents", "create", "--identifier", "orders-agent", "--display-name", "Orders", "--application-id", "app-1"
    ])).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(harness.requests).toHaveLength(0);
  });

  it("creates a company Agent then its Capability draft", async () => {
    const harness = await fixture();
    const result = await harness.run([
      "agents", "create", "--identifier", "orders-agent", "--display-name", "Orders",
      "--application-id", "app-1", "--owner-user-id", "user-1",
      "--audience", "orders", "--permission-id", "policy-1"
    ]);
    expect(JSON.parse(result.stdout).kind).toBe("AgentWithCapabilityDraft");
    expect(harness.requests.map(request => request.path)).toEqual([
      "/api/v3/agent-identity/admin/agents",
      "/api/v3/agent-identity/admin/agents/agt-1/capability-grant/draft"
    ]);
    expect(JSON.parse(harness.requests[0]?.body ?? "{}")).toMatchObject({ agent_type: "company", owner_user_id: "user-1" });
    expect(JSON.parse(harness.requests[1]?.body ?? "{}")).toMatchObject({ data_policy_ids: ["policy-1"], version: 0 });
  });

  it("validates an incomplete Capability selection before creating the Agent", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "agents", "create", "--identifier", "orders-agent", "--display-name", "Orders",
      "--application-id", "app-1", "--owner-user-id", "user-1", "--audience", "orders"
    ])).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(harness.requests).toHaveLength(0);
  });

  it("loads Agent YAML and requires an explicit permission merge policy", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "genauth-agent-agent-file-"));
    directories.push(directory);
    const file = path.join(directory, "agent.yaml");
    await writeFile(file, [
      "identifier: file-agent",
      "display_name: File Agent",
      "application_id: app-1",
      "owner_user_id: user-1",
      "audience: orders",
      "permission_ids:",
      "  - policy-file"
    ].join("\n"), "utf8");
    const harness = await fixture();
    await expect(harness.run(["agents", "create", "--file", file, "--permission-id", "policy-cli"]))
      .rejects.toMatchObject({ code: "AMBIGUOUS_PERMISSION_MERGE" });
    await expect(harness.run(["agents", "create", "--file", file, "--permission-id", "policy-cli", "--replace-permissions", "--append-permission"]))
      .rejects.toMatchObject({ code: "AMBIGUOUS_PERMISSION_MERGE" });
    await harness.run(["agents", "create", "--file", file, "--permission-id", "policy-cli", "--append-permission"]);
    expect(JSON.parse(harness.requests.at(-1)?.body ?? "{}").data_policy_ids).toEqual(["policy-file", "policy-cli"]);
  });

  it("allows a user to create their own company Agent without an owner override", async () => {
    const harness = await fixture("user");
    await harness.run(["agents", "create", "--name", "member-agent", "--application-id", "app-1"]);
    expect(JSON.parse(harness.requests[0]?.body ?? "{}")).toMatchObject({ identifier: "member-agent", display_name: "member-agent", agent_type: "company" });
    expect(JSON.parse(harness.requests[0]?.body ?? "{}")).not.toHaveProperty("owner_user_id");
  });

  it("returns a resumable remediation when Agent creation succeeds but Capability draft creation fails", async () => {
    const harness = await createHarness({
      handler(request, response) {
        response.setHeader("Content-Type", "application/json");
        if (request.path.endsWith("/agents") && request.method === "POST") {
          response.end('{"data":{"id":"agt-partial","version":1}}');
          return;
        }
        response.statusCode = 503;
        response.end('{"error":{"code":"CAPABILITY_UNAVAILABLE","message":"try later"}}');
      }
    });
    active.push(harness);
    await expect(harness.run([
      "agents", "create", "--identifier", "orders-agent", "--display-name", "Orders",
      "--application-id", "app-1", "--owner-user-id", "user-1",
      "--audience", "orders", "--permission-id", "policy-1"
    ])).rejects.toMatchObject({
      code: "PARTIAL_AGENT_CREATE",
      remediation: {
        agent_id: "agt-partial",
        cause_code: "CAPABILITY_UNAVAILABLE",
        next_command: expect.stringContaining("agents capability update --agent-id agt-partial")
      }
    });
  });

  it("submits Capability through the canonical nested command", async () => {
    const harness = await fixture();
    await harness.run(["agents", "capability", "submit", "--agent-id", "agt-1", "--version", "3"]);
    expect(harness.requests[0]?.path).toContain("/capability-grant/submit");
    expect(JSON.parse(harness.requests[0]?.body ?? "{}")).toEqual({ version: 3 });
  });

  it("rejects user pause before a request is sent", async () => {
    const harness = await fixture("user");
    await expect(harness.run(["agents", "lifecycle", "pause", "--agent-id", "agt-1", "--reason", "maintenance"])).rejects.toMatchObject({ code: "ADMIN_LOGIN_REQUIRED" });
    expect(harness.requests).toHaveLength(0);
  });

  it("validates settings mode locally", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "agents", "settings", "update", "--agent-id", "agt-1", "--authorization-mode", "anything",
      "--token-ttl", "5m", "--max-user-grant-ttl", "1h"
    ])).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("rejects invalid settings durations before mutation", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "agents", "settings", "update", "--agent-id", "agt-1", "--authorization-mode", "explicit-only",
      "--token-ttl", "zero", "--max-user-grant-ttl", "1h"
    ])).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(harness.requests).toHaveLength(0);
  });

  it("converts settings durations to seconds", async () => {
    const harness = await fixture();
    await harness.run([
      "agents", "settings", "update", "--agent-id", "agt-1", "--authorization-mode", "silent-if-allowed",
      "--token-ttl", "5m", "--max-user-grant-ttl", "1h", "--rotation-overlap", "30s", "--version", "2"
    ]);
    expect(JSON.parse(harness.requests[0]?.body ?? "{}")).toMatchObject({
      expected_record_version: 2,
      authorization_mode: "SILENT_IF_ALLOWED",
      token_ttl_seconds: 300,
      max_user_grant_ttl_seconds: 3600,
      rotation_overlap_seconds: 30
    });
  });

  it("approves only with explicit confirmation", async () => {
    const harness = await fixture();
    await expect(harness.run(["approvals", "approve", "--approval-id", "apr-1"])).rejects.toMatchObject({ code: "CONFIRMATION_REQUIRED" });
    await harness.run(["approvals", "approve", "--approval-id", "apr-1", "--version", "2", "--reason", "reviewed", "--yes"]);
    expect(harness.requests[0]?.path).toBe("/api/v3/agent-identity/admin/approvals/apr-1/approve");
  });

  it("keeps correlation ID separate from approval ID", async () => {
    const harness = await fixture();
    const correlationId = "5ae1768e-65d6-4e4f-8402-e170d719f09c";
    await harness.run([
      "--correlation-id", correlationId,
      "approvals", "approve", "--approval-id", "apr-1", "--version", "2", "--reason", "reviewed", "--yes"
    ]);
    expect(harness.requests[0]?.path).toBe("/api/v3/agent-identity/admin/approvals/apr-1/approve");
    expect(harness.requests[0]?.headers["x-request-id"]).toBe(correlationId);
  });

  it("validates permissions with an idempotency key", async () => {
    const harness = await fixture();
    await harness.run(["permissions", "validate", "--audience", "orders", "--permission-id", "policy-1"]);
    expect(harness.requests[0]?.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/u);
  });

  it("lists profiles without any network call", async () => {
    const harness = await fixture();
    const result = await harness.run(["profiles", "list"]);
    expect(JSON.parse(result.stdout)).toMatchObject({ kind: "ProfileList", data: { current_profile: "test" } });
    expect(harness.requests).toHaveLength(0);
  });

  it("selects only an administrator-manageable user pool", async () => {
    const harness = await fixture();
    await harness.run(["auth", "select-user-pool", "--user-pool-id", "pool-2"]);
    expect((await harness.profileStore.load()).profiles.test?.selected_user_pool_id).toBe("pool-2");
  });

  it("rejects administrator selection of an unknown pool", async () => {
    const harness = await fixture();
    await expect(harness.run(["auth", "select-user-pool", "--user-pool-id", "unknown"])).rejects.toMatchObject({ code: "USER_POOL_NOT_MANAGEABLE" });
  });

  it("requires --yes for silent administrator authorization", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1",
      "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent"
    ])).rejects.toMatchObject({ code: "CONFIRMATION_REQUIRED" });
  });

  it.each([
    [[], "at least one permission-id"],
    [["--permission-id", "policy-1", "--mode", "unknown"], "mode must be explicit or silent"]
  ] as const)("validates authorization input before mutation", async (extra, message) => {
    const harness = await fixture();
    await expect(harness.run([
      "authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1", "--audience", "orders", ...extra
    ])).rejects.toMatchObject({ code: "INVALID_ARGUMENT", message: expect.stringContaining(message) });
    expect(harness.requests).toHaveLength(0);
  });

  it("creates a confirmed silent administrator grant request", async () => {
    const harness = await fixture();
    await harness.run([
      "authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1",
      "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent", "--yes"
    ]);
    expect(JSON.parse(harness.requests[0]?.body ?? "{}")).toMatchObject({ target_user_id: "user-1", mode: "SILENT" });
  });

  it("creates explicit authorization and stores only local references", async () => {
    const harness = await fixture("user");
    const result = await harness.run([
      "authorizations", "create", "--agent-id", "agt-1", "--audience", "orders",
      "--permission-id", "policy-1", "--mode", "explicit"
    ]);
    const envelope = JSON.parse(result.stdout);
    expect(envelope.kind).toBe("AuthorizationRequest");
    expect(envelope.data.authorization_url).toContain("request_id=auth-1");
    expect(envelope.data.authorization_url).toContain("user_pool_id=pool-1");
    expect(envelope.data.pkce_ref).toBe("keychain://genauth-agent/authorization/auth-1/pkce");
    expect(result.stdout).not.toContain("code_verifier");
    expect(await harness.secrets.get(envelope.data.pkce_ref)).not.toBe("");
  });

  it("cancels an explicit authorization if local PKCE persistence fails", async () => {
    const harness = await fixture("user");
    const originalSet = harness.secrets.set.bind(harness.secrets);
    harness.secrets.set = async (reference, value) => {
      if (reference.endsWith("/callback")) throw new Error("keychain unavailable");
      await originalSet(reference, value);
    };
    await expect(harness.run([
      "authorizations", "create", "--agent-id", "agt-1", "--audience", "orders",
      "--permission-id", "policy-1", "--mode", "explicit"
    ])).rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(harness.requests.map(request => request.path)).toEqual([
      "/api/v3/agent-identity/me/agents/agt-1/authorization-requests",
      "/api/v3/agent-identity/me/authorization-requests/auth-1/cancel"
    ]);
    await expect(harness.secrets.get("keychain://genauth-agent/authorization/auth-1/pkce")).rejects.toThrow();
  });

  it("records user consent without displaying its code by default", async () => {
    const harness = await fixture("user");
    const result = await harness.run(["authorizations", "consent", "--authorization-id", "auth-1"]);
    expect(JSON.parse(result.stdout).data).toEqual({
      request_id: "auth-1",
      redirect_uri: "http://127.0.0.1:1234/callback",
      code_ref: "keychain://genauth-agent/authorization/auth-1/code"
    });
    expect(result.stdout).not.toContain("one-time-code");
  });

  it("shows a consent code only when explicitly requested", async () => {
    const harness = await fixture("user");
    const result = await harness.run(["authorizations", "consent", "--authorization-id", "auth-1", "--show-code"]);
    expect(JSON.parse(result.stdout).data.authorization_code).toBe("one-time-code");
  });

  it("rejects user-only authorization decisions from an administrator profile", async () => {
    const harness = await fixture();
    await expect(harness.run(["authorizations", "consent", "--authorization-id", "auth-1"]))
      .rejects.toMatchObject({ code: "USER_LOGIN_REQUIRED" });
    await expect(harness.run(["authorizations", "deny", "--authorization-id", "auth-1", "--reason", "no", "--yes"]))
      .rejects.toMatchObject({ code: "USER_LOGIN_REQUIRED" });
    expect(harness.requests).toHaveLength(0);
  });

  it("rejects an exchange when its PKCE verifier is unavailable", async () => {
    const harness = await fixture("user");
    await expect(harness.run(["authorizations", "exchange", "--authorization-id", "auth-missing"]))
      .rejects.toMatchObject({ code: "PKCE_NOT_FOUND" });
    expect(harness.requests).toHaveLength(0);
  });

  it.each([
    ["DENIED", "AUTHORIZATION_DENIED"],
    ["EXPIRED", "AUTHORIZATION_EXPIRED"],
    ["CANCELLED", "AUTHORIZATION_CANCELLED"]
  ])("maps terminal authorization status %s", async (status, code) => {
    const harness = await createHarness({ loginType: "user", handler: (_request, response) => {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ data: { status } }));
    } });
    active.push(harness);
    await expect(harness.run(["authorizations", "wait", "--authorization-id", "auth-terminal"]))
      .rejects.toMatchObject({ code });
  });

  it("probes the secret store before mutating consent state", async () => {
    const harness = await fixture("user");
    harness.secrets.set = async reference => {
      if (reference.includes("/probe/")) throw new Error("keychain unavailable");
      throw new Error("unexpected secret write");
    };
    await expect(harness.run(["authorizations", "consent", "--authorization-id", "auth-1"]))
      .rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(harness.requests).toHaveLength(0);
  });

  it("routes user grant listing through the user BFF", async () => {
    const harness = await fixture("user");
    await harness.run(["grants", "list"]);
    expect(harness.requests[0]?.path).toBe("/api/v3/agent-identity/me/agent-user-grants");
  });
});

async function fixture(loginType: "user" | "tenant_admin" = "tenant_admin"): Promise<Harness> {
  const harness = await createHarness({ loginType, handler: handleFixture });
  active.push(harness);
  return harness;
}

function handleFixture(request: RecordedRequest, response: import("node:http").ServerResponse): void {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("X-Request-Id", "req-management");
  if (request.path === "/api/v3/agent-identity/admin/user-pools") {
    response.end('{"data":{"list":[{"id":"pool-1"},{"id":"pool-2"}]}}');
  } else if (request.path.endsWith("/agents") && request.method === "POST") {
    response.end('{"data":{"id":"agt-1","version":1}}');
  } else if (request.path.endsWith("/authorization-requests") && request.method === "POST") {
    response.end('{"data":{"request":{"request_id":"auth-1"}}}');
  } else if (request.path.endsWith("/consent")) {
    response.end('{"data":{"authorization_code":"one-time-code","redirect_uri":"http://127.0.0.1:1234/callback"}}');
  } else {
    response.end('{"data":{"status":"OK"}}');
  }
}
