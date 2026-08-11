import http from "node:http";
import { once } from "node:events";
import { Agent } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import { OAuthClient } from "../../src/auth/oauth.js";
import { createPkce } from "../../src/auth/pkce.js";
import { listenAuthorizationCallback, reserveLoopbackRedirectUri } from "../../src/auth/authorization-callback.js";
import { inspectJwt, tokenSubject } from "../../src/core/jwt.js";

const servers: http.Server[] = [];
const agents: Agent[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  await Promise.all(agents.splice(0).map(agent => agent.close()));
});

describe("OAuth and PKCE", () => {
  it("creates an S256 PKCE pair", () => {
    const pair = createPkce();
    expect(pair.verifier.length).toBeGreaterThan(43);
    expect(pair.challenge).toMatch(/^[A-Za-z0-9_-]+$/u);
  });

  it("refreshes with form encoding and retains a non-rotated refresh token", async () => {
    let body = "";
    const endpoint = await listen((request, response) => {
      request.setEncoding("utf8");
      request.on("data", chunk => { body += String(chunk); });
      request.on("end", () => response.end('{"access_token":"access-2","expires_in":3600}'));
    });
    const dispatcher = new Agent();
    agents.push(dispatcher);
    const token = await new OAuthClient({ endpoint, clientId: "client-1", dispatcher }).refresh("refresh-1");
    expect(new URLSearchParams(body).get("grant_type")).toBe("refresh_token");
    expect(token).toMatchObject({ access_token: "access-2", refresh_token: "refresh-1" });
  });

  it("revokes the refresh token as a public client", async () => {
    let body = "";
    const endpoint = await listen((request, response) => {
      request.setEncoding("utf8");
      request.on("data", chunk => { body += String(chunk); });
      request.on("end", () => { response.statusCode = 200; response.end(); });
    });
    const dispatcher = new Agent();
    agents.push(dispatcher);
    await new OAuthClient({ endpoint, clientId: "client-1", dispatcher }).revoke({
      access_token: "access-1",
      refresh_token: "refresh-1"
    });
    const form = new URLSearchParams(body);
    expect(form.get("client_id")).toBe("client-1");
    expect(form.get("token")).toBe("refresh-1");
    expect(form.get("token_type_hint")).toBe("refresh_token");
  });

  it("completes browserless authorization-code login with state and PKCE", async () => {
    let tokenBody = "";
    const endpoint = await listen((request, response) => {
      request.setEncoding("utf8");
      request.on("data", chunk => { tokenBody += String(chunk); });
      request.on("end", () => response.end('{"access_token":"login-access","refresh_token":"login-refresh"}'));
    });
    const dispatcher = new Agent();
    agents.push(dispatcher);
    const token = await new OAuthClient({ endpoint, clientId: "client-1", dispatcher }).login({
      noBrowser: true,
      notify(url) {
        const authorize = new URL(url);
        expect(authorize.searchParams.has("user_pool_id")).toBe(false);
        expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
        const callback = new URL(authorize.searchParams.get("redirect_uri") ?? "");
        callback.searchParams.set("code", "login-code");
        callback.searchParams.set("state", authorize.searchParams.get("state") ?? "");
        setImmediate(() => { void httpGet(callback); });
      }
    });
    expect(token).toEqual({ access_token: "login-access", refresh_token: "login-refresh" });
    const form = new URLSearchParams(tokenBody);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code_verifier")).not.toBe("");
  });

  it("validates OAuth inputs and error responses", async () => {
    const endpoint = await listen((_request, response) => { response.statusCode = 500; response.end("failure"); });
    const dispatcher = new Agent();
    agents.push(dispatcher);
    const client = new OAuthClient({ endpoint, clientId: "", dispatcher });
    await expect(client.refresh("refresh")).rejects.toThrow("client ID");
    await expect(client.revoke({ access_token: "token" })).rejects.toThrow("client ID");
    await expect(new OAuthClient({ endpoint, clientId: "client", dispatcher }).refresh("refresh")).rejects.toThrow("returned 500");
  });

  it("receives and validates Agent authorization loopback callbacks", async () => {
    const callbackUri = await reserveLoopbackRedirectUri();
    const listener = await listenAuthorizationCallback(callbackUri, "auth-1");
    const invalid = new URL(callbackUri);
    invalid.searchParams.set("request_id", "wrong");
    expect((await httpGet(invalid)).statusCode).toBe(400);
    const valid = new URL(callbackUri);
    valid.searchParams.set("request_id", "auth-1");
    valid.searchParams.set("code", "one-time-code");
    expect((await httpGet(valid)).statusCode).toBe(200);
    await expect(listener.event).resolves.toEqual({ code: "one-time-code", error: "" });
    await listener.close();
    await expect(listenAuthorizationCallback("https://example.com/callback", "auth-1")).rejects.toThrow("supported loopback");
  });
});

describe("JWT inspection", () => {
  it("decodes header and claims without returning the signature", () => {
    const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
    const claims = Buffer.from('{"sub":"user-1","aud":"api"}').toString("base64url");
    const token = `${header}.${claims}.signature`;
    expect(inspectJwt(token)).toEqual({ header: { alg: "RS256" }, claims: { sub: "user-1", aud: "api" } });
    expect(tokenSubject(token)).toBe("user-1");
  });

  it("returns an empty subject for a non-JWT session token", () => {
    expect(tokenSubject("opaque-token")).toBe("");
  });
});

async function listen(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("server did not listen on TCP");
  }
  return `http://127.0.0.1:${address.port}`;
}

async function httpGet(target: URL): Promise<{ statusCode: number }> {
  return new Promise((resolve, reject) => {
    const request = http.get(target, response => {
      response.resume();
      response.on("end", () => resolve({ statusCode: response.statusCode ?? 0 }));
    });
    request.once("error", reject);
  });
}
