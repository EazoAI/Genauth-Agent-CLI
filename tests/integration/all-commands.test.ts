import { afterEach, describe, expect, it } from "vitest";
import type { Harness, RecordedRequest } from "../helpers/cli-harness.js";
import { createHarness } from "../helpers/cli-harness.js";

const active: Harness[] = [];
afterEach(async () => Promise.all(active.splice(0).map(harness => harness.close())));

describe("commands/v2 executable journey coverage", () => {
  it("executes every management command family against GenAuth public routes", async () => {
    const harness = await fixture();
    const commands: string[][] = [
      ["doctor"],
      ["profiles", "get"],
      ["profiles", "list"],
      ["profiles", "use", "--name", "test"],
      ["auth", "status"],
      ["auth", "list-user-pools"],
      ["auth", "select-user-pool", "--user-pool-id", "pool-1"],
      ["permissions", "list", "--page-size", "5", "--audience", "orders", "--action", "read", "--keyword", "invoice"],
      ["permissions", "get", "--permission-id", "policy-1"],
      ["permissions", "validate", "--audience", "orders", "--permission-id", "policy-1"],
      ["agents", "create", "--identifier", "orders-agent", "--display-name", "Orders", "--application-id", "app-1", "--owner-user-id", "user-1"],
      ["agents", "list", "--status", "ACTIVE", "--search", "orders"],
      ["agents", "get", "--agent-id", "agt-1"],
      ["agents", "update", "--agent-id", "agt-1", "--display-name", "Orders v2", "--description", "updated", "--owner-user-id", "user-1", "--version", "2"],
      ["agents", "capability", "update", "--agent-id", "agt-1", "--audience", "orders", "--permission-id", "policy-1", "--version", "1"],
      ["agents", "capability", "submit", "--agent-id", "agt-1", "--version", "2"],
      ["agents", "capability", "withdraw", "--agent-id", "agt-1", "--version", "2", "--reason", "edit", "--yes"],
      ["agents", "readiness", "--agent-id", "agt-1"],
      ["agents", "settings", "get", "--agent-id", "agt-1"],
      ["agents", "settings", "update", "--agent-id", "agt-1", "--authorization-mode", "explicit-only", "--token-ttl", "5m", "--max-user-grant-ttl", "1h", "--redirect-uri", "https://app.example/callback", "--credential-ttl", "24h", "--rotation-overlap", "30s"],
      ["agents", "settings", "submit", "--agent-id", "agt-1"],
      ["agents", "lifecycle", "pause", "--agent-id", "agt-1", "--reason", "maintenance", "--version", "2"],
      ["agents", "lifecycle", "resume", "--agent-id", "agt-1", "--reason", "ready", "--version", "3"],
      ["agents", "lifecycle", "archive", "--agent-id", "agt-1", "--reason", "retired", "--version", "4", "--yes"],
      ["approvals", "list", "--status", "pending"],
      ["approvals", "list", "--settings"],
      ["approvals", "get", "--approval-id", "apr-1"],
      ["approvals", "get", "--approval-id", "apr-1", "--settings"],
      ["approvals", "approve", "--approval-id", "apr-1", "--version", "1", "--reason", "ok", "--yes"],
      ["approvals", "reject", "--approval-id", "apr-2", "--version", "1", "--reason", "no", "--yes", "--settings"],
      ["credentials", "list", "--agent-id", "agt-1"],
      ["credentials", "create", "--agent-id", "agt-1"],
      ["credentials", "rotate", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"],
      ["authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent", "--yes"],
      ["authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-1", "--audience", "orders", "--permission-id", "policy-1", "--mode", "explicit", "--redirect-uri", "http://127.0.0.1:32123/callback"],
      ["authorizations", "get", "--authorization-id", "auth-smoke"],
      ["authorizations", "wait", "--authorization-id", "auth-smoke"],
      ["authorizations", "cancel", "--authorization-id", "auth-smoke", "--yes"],
      ["grants", "list"],
      ["grants", "revoke", "--grant-id", "grant-1", "--version", "1", "--reason", "finished", "--yes"],
      ["tokens", "list", "--agent-id", "agt-1"],
      ["tokens", "revoke", "--jti", "jti-1", "--reason", "incident", "--yes"],
      ["audit", "list", "--agent-id", "agt-1", "--action", "TOKEN_ISSUED"]
    ];
    for (const command of commands) {
      const result = await harness.run(command);
      expect(result.stderr, command.join(" ")).toBe("");
    }
    expect(harness.requests.length).toBeGreaterThan(commands.length - 6);
  });

  it("executes user-only consent, denial, and user Token revocation routes", async () => {
    const harness = await fixture("user");
    await harness.run(["authorizations", "consent", "--authorization-id", "auth-smoke"]);
    await harness.run(["authorizations", "deny", "--authorization-id", "auth-smoke", "--reason", "declined", "--yes"]);
    await harness.run(["tokens", "revoke", "--agent-id", "agt-1", "--jti", "jti-1", "--reason", "incident", "--yes"]);
    expect(harness.requests.map(request => request.path)).toContain("/api/v3/agent-identity/me/authorization-requests/auth-smoke/consent");
    expect(harness.requests.map(request => request.path)).toContain("/api/v3/agent-identity/me/authorization-requests/auth-smoke/deny");
    expect(harness.requests.map(request => request.path)).toContain("/api/v3/agent-identity/me/agents/agt-1/tokens/jti-1/revoke");
  });

  it("executes non-network system commands and profile mutation", async () => {
    const harness = await fixture();
    expect(JSON.parse((await harness.run(["version"])).stdout).data.command_contract).toBe("genauth-agent.commands/v2");
    expect((await harness.run(["completion", "bash"])).stdout).toContain("complete -W");
    await harness.run(["profiles", "set", "--client-id", "client-2"]);
    expect((await harness.profileStore.load()).profiles.test?.client_id).toBe("client-2");
  });
});

async function fixture(loginType: "user" | "tenant_admin" = "tenant_admin"): Promise<Harness> {
  const harness = await createHarness({ loginType, handler: handleFixture });
  active.push(harness);
  return harness;
}

function handleFixture(request: RecordedRequest, response: import("node:http").ServerResponse): void {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("X-Request-Id", "req-all-commands");
  if (request.path === "/api/v3/agent-identity/admin/user-pools") {
    response.end('{"data":{"list":[{"id":"pool-1"}]}}');
  } else if (request.path.endsWith("/agents") && request.method === "POST") {
    response.end('{"data":{"id":"agt-1","version":1}}');
  } else if (request.path.endsWith("/authorization-requests") && request.method === "POST") {
    response.end('{"data":{"request":{"request_id":"auth-smoke"}}}');
  } else if (request.path.endsWith("/consent")) {
    response.end('{"data":{"authorization_code":"auth-code","redirect_uri":"http://127.0.0.1:32123/callback"}}');
  } else if (request.path.includes("/authorization-requests/auth-smoke") && request.method === "GET") {
    response.end('{"data":{"status":"APPROVED"}}');
  } else if (request.path.endsWith("/credentials") && request.method === "POST" || request.path.endsWith("/rotate")) {
    response.end('{"data":{"credential":{"credential_id":"cred-1","expires_at":"2030-01-01T00:00:00Z"},"delivery":{"delivery_id":"delivery-1","delivery_code":"delivery-code"}}}');
  } else if (request.path.includes("credential-deliveries")) {
    response.end('{"data":{"credential_id":"cred-1","client_secret":"credential-secret"}}');
  } else {
    response.end('{"data":{"id":"resource-1","status":"OK"}}');
  }
}
