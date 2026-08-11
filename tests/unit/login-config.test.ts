import http from "node:http";
import { once } from "node:events";
import { Agent } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import { discoverLoginConfig } from "../../src/auth/login-config.js";
import { ApiClient } from "../../src/http/client.js";

const servers: http.Server[] = [];
const agents: Agent[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  await Promise.all(agents.splice(0).map(agent => agent.close()));
});

describe("Agent CLI login configuration discovery", () => {
  it("accepts the dedicated public PKCE client contract", async () => {
    const client = await fixture((_request, response) => {
      response.setHeader("Content-Type", "application/json");
      response.setHeader("X-Request-Id", "request-login-config");
      response.end(JSON.stringify({ data: {
        client_id: "cli-client",
        authorization_endpoint: "/oidc/auth",
        token_endpoint: "/oidc/token",
        revocation_endpoint: "/oidc/token/revocation",
        scopes: ["openid", "profile", "offline_access"],
        code_challenge_method: "S256",
        redirect_uri_pattern: "http://127.0.0.1:*/callback"
      } }));
    });

    await expect(discoverLoginConfig(client)).resolves.toEqual({
      clientId: "cli-client",
      requestId: "request-login-config"
    });
  });

  it("rejects a weakened or malformed server contract", async () => {
    const client = await fixture((_request, response) => {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ data: {
        client_id: "cli-client",
        authorization_endpoint: "/oidc/auth",
        token_endpoint: "/oidc/token",
        revocation_endpoint: "/oidc/token/revocation",
        scopes: ["openid"],
        code_challenge_method: "plain",
        redirect_uri_pattern: "http://127.0.0.1:*/callback"
      } }));
    });

    await expect(discoverLoginConfig(client)).rejects.toMatchObject({
      code: "LOGIN_CONFIGURATION_INVALID",
      exitCode: 7
    });
  });

  it("preserves the server's stable not-configured error", async () => {
    const client = await fixture((_request, response) => {
      response.statusCode = 503;
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({
        code: "AGENT_CLI_LOGIN_NOT_CONFIGURED",
        message: "Agent CLI login client is not configured"
      }));
    });

    await expect(discoverLoginConfig(client)).rejects.toMatchObject({
      code: "AGENT_CLI_LOGIN_NOT_CONFIGURED",
      exitCode: 7
    });
  });
});

async function fixture(handler: http.RequestListener): Promise<ApiClient> {
  const server = http.createServer(handler);
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server unavailable");
  const dispatcher = new Agent();
  agents.push(dispatcher);
  return ApiClient.create({
    endpoint: `http://127.0.0.1:${address.port}`,
    dispatcher
  });
}
