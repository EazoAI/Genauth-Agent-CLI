import { afterEach, describe, expect, it } from "vitest";
import type { Harness, RecordedRequest } from "../helpers/cli-harness.js";
import { createHarness } from "../helpers/cli-harness.js";

const active: Harness[] = [];
afterEach(async () => Promise.all(active.splice(0).map(harness => harness.close())));

describe("runtime command journey", () => {
  it("creates and stores a Credential without printing its secret", async () => {
    const harness = await fixtureHarness();
    const result = await harness.run(["credentials", "create", "--agent-id", "agt-1"]);
    const envelope = JSON.parse(result.stdout);
    expect(envelope.kind).toBe("AgentCredential");
    expect(envelope.data).toEqual({
      credential_id: "cred-1",
      expires_at: "2030-01-01T00:00:00Z",
      secret_ref: "keychain://genauth-agent/credential/cred-1"
    });
    expect(result.stdout).not.toContain("credential-secret");
    expect(await harness.secrets.get("keychain://genauth-agent/credential/cred-1")).toContain("credential-secret");
    expect(harness.requests.map(request => request.path)).toEqual([
      "/api/v3/agent-identity/admin/agents/agt-1/credentials",
      "/api/v3/agent-identity/admin/credential-deliveries/delivery-1/consume"
    ]);
  });

  it("warns without rewriting elapsed active and rotating Credential states", async () => {
    const harness = await createHarness({ handler: (_request, response) => {
      response.setHeader("Content-Type", "application/json");
      response.end('{"data":{"data":[{"credential_id":"active-old","status":"ACTIVE","expires_at":"2020-01-01T00:00:00Z"},{"credential_id":"rotation-old","status":"ROTATING","overlap_ends_at":"2020-01-01T00:00:00Z"}]}}');
    } });
    active.push(harness);
    const result = JSON.parse((await harness.run(["credentials", "list", "--agent-id", "agt-1"])).stdout);
    expect(result.data).toEqual({ data: { data: [
      { credential_id: "active-old", status: "ACTIVE", expires_at: "2020-01-01T00:00:00Z" },
      { credential_id: "rotation-old", status: "ROTATING", overlap_ends_at: "2020-01-01T00:00:00Z" }
    ] } });
    expect(result.warnings).toEqual([
      "GenAuth returned 1 Credential(s) as ACTIVE even though expires_at has passed; do not use them for Token or Provider calls",
      "GenAuth returned 1 Credential(s) as ROTATING even though overlap_ends_at has passed; do not use the expired rotation credential"
    ]);
  });

  it.each(["json", "yaml"])("requires a second acknowledgement before showing a Credential secret in %s", async output => {
    const harness = await fixtureHarness();
    await expect(harness.run([
      "--output", output, "credentials", "create", "--agent-id", "agt-1", "--show-secret"
    ])).rejects.toMatchObject({ code: "SECRET_OUTPUT_ACKNOWLEDGEMENT_REQUIRED" });
    expect(harness.requests).toHaveLength(0);
  });

  it("requires a Credential secret destination", async () => {
    const harness = await fixtureHarness();
    await expect(harness.run(["credentials", "create", "--agent-id", "agt-1", "--no-store-keychain"]))
      .rejects.toMatchObject({ code: "SECRET_DESTINATION_REQUIRED" });
    expect(harness.requests).toHaveLength(0);
  });

  it("probes the secret store before creating a Credential delivery", async () => {
    const harness = await fixtureHarness();
    const originalSet = harness.secrets.set.bind(harness.secrets);
    harness.secrets.set = async (reference, value) => {
      if (reference.includes("/probe/")) throw new Error("keychain unavailable");
      await originalSet(reference, value);
    };
    await expect(harness.run(["credentials", "create", "--agent-id", "agt-1"]))
      .rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(harness.requests).toHaveLength(0);
  });

  it("allows acknowledged machine-readable Credential secret output without Keychain storage", async () => {
    const harness = await fixtureHarness();
    const result = await harness.run([
      "credentials", "create", "--agent-id", "agt-1", "--no-store-keychain", "--show-secret", "--allow-secret-output"
    ]);
    expect(JSON.parse(result.stdout).data.client_secret).toBe("credential-secret");
    expect(JSON.parse(result.stdout).data).not.toHaveProperty("secret_ref");
  });

  it("revokes a newly delivered Credential if Keychain persistence fails", async () => {
    const harness = await fixtureHarness();
    const originalSet = harness.secrets.set.bind(harness.secrets);
    harness.secrets.set = async (reference, value) => {
      if (reference.includes("/credential/")) throw new Error("keychain unavailable");
      await originalSet(reference, value);
    };
    await expect(harness.run(["credentials", "create", "--agent-id", "agt-1"]))
      .rejects.toMatchObject({ code: "SECRET_STORE_UNAVAILABLE" });
    expect(harness.requests.map(request => request.path)).toEqual([
      "/api/v3/agent-identity/admin/agents/agt-1/credentials",
      "/api/v3/agent-identity/admin/credential-deliveries/delivery-1/consume",
      "/api/v3/agent-identity/admin/agents/agt-1/credentials/cred-1/revoke"
    ]);
  });

  it("removes a local Credential only after successful remote revoke", async () => {
    const harness = await fixtureHarness();
    await harness.secrets.set("keychain://genauth-agent/credential/cred-1", "stored");
    const result = await harness.run(["credentials", "revoke", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"]);
    expect(JSON.parse(result.stdout).kind).toBe("Credential");
    await expect(harness.secrets.get("keychain://genauth-agent/credential/cred-1")).rejects.toThrow();
  });

  it("reports a warning if remote Credential revoke succeeds but local cleanup fails", async () => {
    const harness = await fixtureHarness();
    await harness.secrets.set("keychain://genauth-agent/credential/cred-1", "stored");
    harness.secrets.delete = async reference => {
      if (reference.includes("/credential/")) throw new Error("keychain unavailable");
    };
    const result = await harness.run(["credentials", "revoke", "--agent-id", "agt-1", "--credential-id", "cred-1", "--yes"]);
    expect(JSON.parse(result.stdout).warnings).toEqual([
      "credential was revoked, but its local OS secret-store entry could not be removed"
    ]);
  });

  it("issues a Token but omits access_token by default", async () => {
    const harness = await fixtureHarness();
    await storeCredential(harness);
    const result = await harness.run(tokenArguments());
    const envelope = JSON.parse(result.stdout);
    expect(envelope.kind).toBe("AgentAccessToken");
    expect(envelope.data).toEqual({ jti: "jti-1", expires_in: 300 });
    expect(result.stdout).not.toContain("runtime-jwt");
    expect(harness.requests.at(-1)?.headers.authorization).toBe(`Basic ${Buffer.from("cred-1:credential-secret").toString("base64")}`);
    expect(JSON.parse(harness.requests.at(-1)?.body ?? "{}").permission_ids).toBeNull();
  });

  it("shows a Token only when explicitly requested", async () => {
    const harness = await fixtureHarness();
    await storeCredential(harness);
    const result = await harness.run([...tokenArguments(), "--show-token"]);
    expect(JSON.parse(result.stdout).data.access_token).toBe("runtime-jwt");
  });

  it("passes a process-lifetime Token to a child only through the environment", async () => {
    const harness = await fixtureHarness();
    await storeCredential(harness);
    const result = await harness.run([
      ...tokenArguments(), "--exec", process.execPath,
      "--exec-arg=-e", "--exec-arg=process.exit(process.env.GENAUTH_AGENT_ACCESS_TOKEN === 'runtime-jwt' ? 0 : 1)"
    ]);
    expect(result.stdout).toBe("");
  });

  it.each([
    ["not-json", "INVALID_CREDENTIAL_REFERENCE"],
    ['{"credential_id":"cred-1"}', "INVALID_CREDENTIAL_REFERENCE"]
  ])("rejects invalid stored Credential %s", async (stored, code) => {
    const harness = await fixtureHarness();
    await harness.secrets.set("keychain://genauth-agent/credential/bad", stored);
    await expect(harness.run([
      "tokens", "issue", "--credential", "keychain://genauth-agent/credential/bad", "--grant-id", "grant-1", "--audience", "orders"
    ])).rejects.toMatchObject({ code });
    expect(harness.requests).toHaveLength(0);
  });

  it("rejects a missing Credential reference", async () => {
    const harness = await fixtureHarness();
    await expect(harness.run([
      "tokens", "issue", "--credential", "keychain://genauth-agent/credential/missing", "--grant-id", "grant-1", "--audience", "orders"
    ])).rejects.toMatchObject({ code: "CREDENTIAL_NOT_FOUND" });
  });

  it("decodes a Token from stdin without claiming signature verification", async () => {
    const harness = await fixtureHarness();
    const token = `${Buffer.from('{"alg":"RS256"}').toString("base64url")}.${Buffer.from('{"sub":"user-1"}').toString("base64url")}.signature`;
    const result = await harness.run(["tokens", "inspect", "--token-stdin"], token);
    expect(JSON.parse(result.stdout).data).toEqual({
      header: { alg: "RS256" },
      claims: { sub: "user-1" },
      signature_verified: false
    });
  });

  it("calls only the fixed Provider route with an in-memory Token", async () => {
    const harness = await fixtureHarness();
    await storeCredential(harness);
    const result = await harness.run([
      "providers", "call",
      "--credential", "keychain://genauth-agent/credential/cred-1",
      "--grant-id", "grant-1",
      "--audience", "orders",
      "--provider", "orders-provider",
      "--method", "GET",
      "--path", "/orders/1"
    ]);
    expect(JSON.parse(result.stdout)).toMatchObject({ kind: "ProviderResponse", data: { order_id: "1" } });
    const request = harness.requests.at(-1);
    expect(request?.path).toBe("/api/v3/agent-runtime/providers/orders-provider/orders/1");
    expect(request?.headers.authorization).toBe("Bearer runtime-jwt");
  });

  it("encodes a non-JSON Provider response", async () => {
    const harness = await createHarness({ handler(request, response) {
      if (request.path === "/api/v3/agent-runtime/token") response.end('{"data":{"access_token":"runtime-jwt"}}');
      else { response.setHeader("X-Request-Id", "req-binary"); response.end("plain response"); }
    } });
    active.push(harness);
    await storeCredential(harness);
    const result = await harness.run([
      "providers", "call", "--credential", "keychain://genauth-agent/credential/cred-1",
      "--grant-id", "grant-1", "--audience", "orders", "--provider", "p", "--path", "/plain"
    ]);
    expect(JSON.parse(result.stdout).data).toEqual({ content_base64: Buffer.from("plain response").toString("base64"), encoding: "base64" });
  });

  it.each(["https://evil.example/x", "//evil", "/orders/../admin"])("rejects unsafe Provider path %s", async path => {
    const harness = await fixtureHarness();
    await storeCredential(harness);
    await expect(harness.run([
      "providers", "call", "--credential", "keychain://genauth-agent/credential/cred-1",
      "--grant-id", "grant-1", "--audience", "orders", "--provider", "p", "--path", path
    ])).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("revokes a UserGrant with version and reason", async () => {
    const harness = await fixtureHarness();
    await harness.run(["grants", "revoke", "--grant-id", "grant-1", "--version", "2", "--reason", "finished", "--yes"]);
    const request = harness.requests.at(-1);
    expect(request?.path).toBe("/api/v3/agent-identity/admin/agent-user-grants/grant-1/revoke");
    expect(JSON.parse(request?.body ?? "{}")).toEqual({ version: 2, reason: "finished" });
  });

  it("cleans one-time authorization values after exchange and warns on partial cleanup", async () => {
    const harness = await fixtureHarness();
    const values: Array<[string, string]> = [["pkce", "verifier"], ["code", "code"], ["callback", "http://127.0.0.1/callback"], ["url", "https://example.test/authorize"]];
    for (const [suffix, value] of values) {
      await harness.secrets.set(`keychain://genauth-agent/authorization/auth-1/${suffix}`, value);
    }
    const originalDelete = harness.secrets.delete.bind(harness.secrets);
    harness.secrets.delete = async reference => {
      if (reference.endsWith("/code")) throw new Error("keychain unavailable");
      await originalDelete(reference);
    };
    const result = await harness.run(["authorizations", "exchange", "--authorization-id", "auth-1"]);
    expect(JSON.parse(result.stdout).warnings).toEqual([
      "authorization exchange succeeded, but one or more one-time values could not be removed from the OS secret store"
    ]);
    expect(JSON.parse(harness.requests.at(-1)?.body ?? "{}")).toEqual({ code_verifier: "verifier", authorization_code: "code" });
  });

  it("does not let a user request silent authorization or another user ID", async () => {
    const harness = await fixtureHarness("user");
    await expect(harness.run([
      "authorizations", "create", "--agent-id", "agt-1", "--user-id", "user-2",
      "--audience", "orders", "--permission-id", "policy-1", "--mode", "silent", "--yes"
    ])).rejects.toMatchObject({ code: "FORBIDDEN_USER_AUTHORIZATION_MODE" });
    expect(harness.requests).toHaveLength(0);
  });

  it("does not let a user execute approval operations", async () => {
    const harness = await fixtureHarness("user");
    await expect(harness.run(["approvals", "list"])).rejects.toMatchObject({ code: "ADMIN_LOGIN_REQUIRED" });
    expect(harness.requests).toHaveLength(0);
  });
});

async function fixtureHarness(loginType: "user" | "tenant_admin" = "tenant_admin"): Promise<Harness> {
  const harness = await createHarness({ loginType, handler: handleFixture });
  active.push(harness);
  return harness;
}

function handleFixture(request: RecordedRequest, response: import("node:http").ServerResponse): void {
  response.setHeader("Content-Type", "application/json");
  response.setHeader("X-Request-Id", "req-test");
  if (request.path.endsWith("/credentials") && request.method === "POST") {
    response.end('{"data":{"credential":{"credential_id":"cred-1","expires_at":"2030-01-01T00:00:00Z"},"delivery":{"delivery_id":"delivery-1","delivery_code":"one-time"}}}');
  } else if (request.path.includes("credential-deliveries")) {
    response.end('{"data":{"credential_id":"cred-1","client_secret":"credential-secret"}}');
  } else if (request.path === "/api/v3/agent-runtime/token") {
    response.end('{"data":{"access_token":"runtime-jwt","jti":"jti-1","expires_in":300}}');
  } else if (request.path.includes("/agent-runtime/providers/")) {
    response.end('{"order_id":"1"}');
  } else {
    response.end('{"data":{"status":"REVOKED"}}');
  }
}

async function storeCredential(harness: Harness): Promise<void> {
  await harness.secrets.set("keychain://genauth-agent/credential/cred-1", JSON.stringify({ credential_id: "cred-1", client_secret: "credential-secret" }));
}

function tokenArguments(): string[] {
  return [
    "tokens", "issue",
    "--credential", "keychain://genauth-agent/credential/cred-1",
    "--grant-id", "grant-1",
    "--audience", "orders"
  ];
}
