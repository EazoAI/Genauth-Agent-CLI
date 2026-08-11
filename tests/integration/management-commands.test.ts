import { afterEach, describe, expect, it } from "vitest";
import type { Harness, RecordedRequest } from "../helpers/cli-harness.js";
import { createHarness } from "../helpers/cli-harness.js";

const active: Harness[] = [];
afterEach(async () => Promise.all(active.splice(0).map(harness => harness.close())));

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
    expect(envelope.data.pkce_ref).toBe("keychain://agent-identity/authorization/auth-1/pkce");
    expect(result.stdout).not.toContain("code_verifier");
    expect(await harness.secrets.get(envelope.data.pkce_ref)).not.toBe("");
  });

  it("records user consent without displaying its code by default", async () => {
    const harness = await fixture("user");
    const result = await harness.run(["authorizations", "consent", "--authorization-id", "auth-1"]);
    expect(JSON.parse(result.stdout).data).toEqual({
      request_id: "auth-1",
      redirect_uri: "http://127.0.0.1:1234/callback",
      code_ref: "keychain://agent-identity/authorization/auth-1/code"
    });
    expect(result.stdout).not.toContain("one-time-code");
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
