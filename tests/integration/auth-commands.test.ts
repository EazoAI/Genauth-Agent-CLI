import { afterEach, describe, expect, it } from "vitest";
import type { Harness, RecordedRequest } from "../helpers/cli-harness.js";
import { createHarness } from "../helpers/cli-harness.js";

const active: Harness[] = [];
afterEach(async () => Promise.all(active.splice(0).map(harness => harness.close())));

describe("authentication command branches", () => {
  it("logs in a user from stdin and persists only the secret reference", async () => {
    const harness = await fixture();
    const result = await harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--user-pool-id", "pool-1", "--profile-name", "member", "--session-token-stdin"
    ], "opaque-session");
    expect(JSON.parse(result.stdout).data).toMatchObject({ profile: "member", login_type: "user", selected_user_pool_id: "pool-1" });
    expect((await harness.profileStore.load()).profiles.member?.secret_ref).toBe("keychain://agent-identity/session/member");
    expect(await harness.secrets.get("keychain://agent-identity/session/member")).toContain("opaque-session");
  });

  it("logs in an administrator and verifies the selected manageable pool", async () => {
    const harness = await fixture();
    await harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--admin", "--user-pool-id", "pool-2", "--profile-name", "admin2", "--session-token-stdin"
    ], "admin-session");
    expect(harness.requests[0]?.path).toBe("/api/v3/agent-identity/admin/user-pools");
    expect((await harness.profileStore.load()).profiles.admin2?.selected_user_pool_id).toBe("pool-2");
  });

  it("auto-selects the only administrator pool", async () => {
    const harness = await createHarness({ handler: (_request, response) => response.end('{"data":{"list":[{"id":"only-pool"}]}}') });
    active.push(harness);
    const result = await harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--admin", "--profile-name", "only", "--session-token-stdin"
    ], "admin-session");
    expect(JSON.parse(result.stdout).data.selected_user_pool_id).toBe("only-pool");
  });

  it.each([
    [[], "INVALID_ARGUMENT"],
    [["--user-pool-id", "pool-1"], "INVALID_ENDPOINT"]
  ] as const)("rejects incomplete login arguments", async (extra, code) => {
    const harness = await fixture();
    await expect(harness.run(["auth", "login", ...extra, "--session-token-stdin"], "token"))
      .rejects.toMatchObject({ code });
  });

  it("rejects empty stdin and non-interactive browser login", async () => {
    const harness = await fixture();
    const prefix = ["--endpoint", harness.endpoint, "--allow-insecure-localhost", "auth", "login", "--user-pool-id", "pool-1"];
    await expect(harness.run([...prefix, "--session-token-stdin"], "")).rejects.toMatchObject({ code: "INVALID_SESSION" });
    await expect(harness.run(prefix)).rejects.toMatchObject({ code: "LOGIN_INTERACTION_REQUIRED" });
  });

  it("requires an explicit administrator selection when multiple pools exist", async () => {
    const harness = await fixture();
    await expect(harness.run([
      "--endpoint", harness.endpoint, "--allow-insecure-localhost",
      "auth", "login", "--admin", "--profile-name", "ambiguous", "--session-token-stdin"
    ], "token")).rejects.toMatchObject({ code: "USER_POOL_SELECTION_REQUIRED" });
  });

  it("refreshes the current profile explicitly", async () => {
    const harness = await fixture();
    await harness.secrets.set("keychain://agent-identity/session/test", JSON.stringify({ access_token: "old", refresh_token: "refresh" }));
    const result = await harness.run(["auth", "refresh"]);
    expect(JSON.parse(result.stdout).data.refreshed).toBe(true);
    expect(await harness.secrets.get("keychain://agent-identity/session/test")).toContain("new-access");
  });

  it("rejects refresh without a refresh token", async () => {
    const harness = await fixture();
    await expect(harness.run(["auth", "refresh"])).rejects.toMatchObject({ code: "SESSION_REFRESH_FAILED" });
  });

  it("rejects pool switching for a user profile", async () => {
    const harness = await fixture("user");
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
  if (request.path === "/api/v3/agent-identity/admin/user-pools") {
    response.end('{"data":{"list":[{"id":"pool-1"},{"id":"pool-2"}]}}');
  } else if (request.path === "/oidc/token") {
    response.end('{"access_token":"new-access","refresh_token":"new-refresh"}');
  } else {
    response.end('{"data":{}}');
  }
}
