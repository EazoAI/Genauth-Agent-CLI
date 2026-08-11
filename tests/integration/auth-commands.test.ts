import { afterEach, describe, expect, it } from "vitest";
import type { Harness, RecordedRequest } from "../helpers/cli-harness.js";
import { createHarness } from "../helpers/cli-harness.js";

const active: Harness[] = [];
afterEach(async () => Promise.all(active.splice(0).map(harness => harness.close())));

describe("authentication command branches", () => {
  it("logs in an administrator from stdin and persists only the secret reference", async () => {
    const harness = await fixture();
    const result = await harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--user-pool-id", "pool-1", "--profile-name", "admin", "--session-token-stdin"
    ], "opaque-session");
    expect(JSON.parse(result.stdout).data).toMatchObject({
      profile: "admin",
      login_type: "tenant_admin",
      selected_user_pool_id: "pool-1",
      selected_user_pool_name: "Development",
      selected_user_pool_domain: "dev"
    });
    expect((await harness.profileStore.load()).profiles.admin?.secret_ref).toBe("keychain://genauth-agent/session/admin");
    expect(await harness.secrets.get("keychain://genauth-agent/session/admin")).toContain("opaque-session");
  });

  it("logs in an administrator and verifies the selected manageable pool", async () => {
    const harness = await fixture();
    await harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--user-pool-id", "pool-2", "--profile-name", "admin2", "--session-token-stdin"
    ], "admin-session");
    expect(harness.requests.map(request => request.path)).toContain("/api/v3/agent-identity/admin/user-pools");
    expect((await harness.profileStore.load()).profiles.admin2?.selected_user_pool_id).toBe("pool-2");
  });

  it("auto-selects the only administrator pool", async () => {
    const harness = await createHarness({ handler: (request, response) => {
      if (request.path === "/api/v3/agent-identity/auth/config") {
        response.end(JSON.stringify({ data: loginConfig() }));
        return;
      }
      response.end('{"data":{"list":[{"id":"only-pool"}]}}');
    } });
    active.push(harness);
    const result = await harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--profile-name", "only", "--session-token-stdin"
    ], "admin-session");
    expect(JSON.parse(result.stdout).data.selected_user_pool_id).toBe("only-pool");
  });

  it("rejects login without an endpoint", async () => {
    const harness = await fixture();
    await expect(harness.run(["auth", "login", "--session-token-stdin"], "token"))
      .rejects.toMatchObject({ code: "INVALID_ENDPOINT" });
  });

  it("rejects empty stdin and non-interactive browser login", async () => {
    const harness = await fixture();
    const prefix = ["--endpoint", harness.endpoint, "--allow-insecure-localhost", "auth", "login"];
    await expect(harness.run([...prefix, "--session-token-stdin"], "")).rejects.toMatchObject({ code: "INVALID_SESSION" });
    await expect(harness.run(prefix)).rejects.toMatchObject({ code: "LOGIN_INTERACTION_REQUIRED" });
  });

  it("requires an explicit administrator selection when multiple pools exist", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--profile-name", "ambiguous", "--session-token-stdin"
    ], "token")).rejects.toMatchObject({
      code: "USER_POOL_SELECTION_REQUIRED",
      message: "multiple manageable user pools found; choose one and retry with --user-pool-id: Development [dev] (pool-1), Production [prod] (pool-2)",
      remediation: {
        action: "retry_with_user_pool",
        option: "--user-pool-id",
        manageable_user_pools: [
          { id: "pool-1", name: "Development", domain: "dev" },
          { id: "pool-2", name: "Production", domain: "prod" }
        ]
      }
    });
  });

  it("lists manageable pools with display metadata and the current selection", async () => {
    const harness = await fixture();
    const result = await harness.run(["auth", "list-user-pools"]);
    expect(JSON.parse(result.stdout)).toMatchObject({
      kind: "UserPoolList",
      data: {
        selected_user_pool_id: "pool-1",
        total_count: 2,
        list: [
          { id: "pool-1", name: "Development", domain: "dev", selected: true },
          { id: "pool-2", name: "Production", domain: "prod", selected: false }
        ]
      }
    });
  });

  it("shows selected pool metadata after switching and in status and doctor output", async () => {
    const harness = await fixture();
    const switched = JSON.parse((await harness.run([
      "auth", "select-user-pool", "--user-pool-id", "pool-2"
    ])).stdout);
    expect(switched.data).toMatchObject({
      selected_user_pool_id: "pool-2",
      selected_user_pool_name: "Production",
      selected_user_pool_domain: "prod"
    });
    const status = JSON.parse((await harness.run(["auth", "status"])).stdout);
    expect(status.data).toMatchObject({
      selected_user_pool_id: "pool-2",
      selected_user_pool_name: "Production",
      selected_user_pool_domain: "prod"
    });
    const doctor = JSON.parse((await harness.run(["doctor"])).stdout);
    expect(doctor.data).toMatchObject({
      selected_user_pool_id: "pool-2",
      selected_user_pool_name: "Production",
      selected_user_pool_domain: "prod"
    });
  });

  it("returns named manageable pools when a selected pool ID is invalid", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "auth", "select-user-pool", "--user-pool-id", "unknown"
    ])).rejects.toMatchObject({
      code: "USER_POOL_NOT_MANAGEABLE",
      message: "the selected user pool is not manageable by this administrator; choose one: Development [dev] (pool-1), Production [prod] (pool-2)",
      remediation: {
        action: "retry_with_user_pool",
        option: "--user-pool-id",
        manageable_user_pools: [
          { id: "pool-1", name: "Development", domain: "dev" },
          { id: "pool-2", name: "Production", domain: "prod" }
        ]
      }
    });
  });

  it("falls back to pool IDs when an older server omits display metadata", async () => {
    const harness = await createHarness({ handler: (request, response) => {
      response.setHeader("Content-Type", "application/json");
      if (request.path === "/api/v3/agent-identity/auth/config") {
        response.end(JSON.stringify({ data: loginConfig() }));
        return;
      }
      response.end('{"data":{"list":[{"id":"pool-1"},{"id":"pool-2"}]}}');
    } });
    active.push(harness);
    await expect(harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--profile-name", "legacy", "--session-token-stdin"
    ], "token")).rejects.toMatchObject({
      code: "USER_POOL_SELECTION_REQUIRED",
      message: "multiple manageable user pools found; choose one and retry with --user-pool-id: pool-1, pool-2",
      remediation: {
        manageable_user_pools: [{ id: "pool-1" }, { id: "pool-2" }]
      }
    });
  });

  it("refreshes the current profile explicitly", async () => {
    const harness = await fixture();
    await harness.secrets.set("keychain://genauth-agent/session/test", JSON.stringify({ access_token: "old", refresh_token: "refresh" }));
    const result = await harness.run(["auth", "refresh"]);
    expect(JSON.parse(result.stdout).data.refreshed).toBe(true);
    expect(await harness.secrets.get("keychain://genauth-agent/session/test")).toContain("new-access");
  });

  it("rejects refresh without a refresh token", async () => {
    const harness = await fixture();
    await expect(harness.run(["auth", "refresh"])).rejects.toMatchObject({ code: "SESSION_REFRESH_FAILED" });
  });

  it("rejects pool switching for a user profile", async () => {
    const harness = await fixture("user");
    await expect(harness.run(["auth", "list-user-pools"]))
      .rejects.toMatchObject({ code: "ADMIN_LOGIN_REQUIRED" });
    await expect(harness.run(["auth", "select-user-pool", "--user-pool-id", "pool-2"]))
      .rejects.toMatchObject({ code: "TENANT_CONTEXT_REQUIRED" });
  });

  it("validates profile mutation and explicit localhost acknowledgement", async () => {
    const harness = await fixture();
    await expect(harness.run(["profiles", "set"])).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(harness.run(["profiles", "set", "--endpoint", harness.endpoint])).rejects.toMatchObject({ code: "INVALID_ENDPOINT" });
    await harness.run(["--allow-insecure-localhost", "profiles", "set", "--endpoint", harness.endpoint]);
    await expect(harness.run(["--profile", "missing", "profiles", "get"])).rejects.toMatchObject({ code: "PROFILE_NOT_FOUND" });
  });
});

async function fixture(loginType: "user" | "tenant_admin" = "tenant_admin"): Promise<Harness> {
  const harness = await createHarness({ loginType, handler: handleFixture });
  active.push(harness);
  return harness;
}

function handleFixture(request: RecordedRequest, response: import("node:http").ServerResponse): void {
  response.setHeader("Content-Type", "application/json");
  if (request.path === "/api/v3/agent-identity/auth/config") {
    response.end(JSON.stringify({ data: loginConfig() }));
  } else if (request.path === "/api/v3/agent-identity/admin/user-pools") {
    response.end('{"data":{"list":[{"id":"pool-1","name":"Development","domain":"dev"},{"id":"pool-2","name":"Production","domain":"prod"}]}}');
  } else if (request.path === "/oidc/token") {
    response.end('{"access_token":"new-access","refresh_token":"new-refresh"}');
  } else {
    response.end('{"data":{}}');
  }
}

function loginConfig(): Record<string, unknown> {
  return {
    client_id: "cli-client",
    authorization_endpoint: "/oidc/auth",
    token_endpoint: "/oidc/token",
    revocation_endpoint: "/oidc/token/revocation",
    scopes: ["openid", "profile", "offline_access"],
    code_challenge_method: "S256",
    redirect_uri_pattern: "http://127.0.0.1:*/callback"
  };
}
