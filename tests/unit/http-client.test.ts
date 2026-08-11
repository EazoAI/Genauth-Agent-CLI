import http from "node:http";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Agent } from "undici";
import { afterEach, describe, expect, it } from "vitest";
import { ApiClient, createDispatcher, decodeData, validateApiPath, validateProxyUrl } from "../../src/http/client.js";
import { ApiError, InvalidCaFileError, InvalidProxyError } from "../../src/http/errors.js";
import { validateCliEndpoint } from "../../src/cli/context.js";

const servers: http.Server[] = [];
const dispatchers: Agent[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  await Promise.all(dispatchers.splice(0).map(dispatcher => dispatcher.close()));
});

describe("API client", () => {
  it("adds human headers and uses Basic only for runtime token", async () => {
    let receivedAuthorization = "";
    let receivedPool = "";
    let receivedBody = "";
    const endpoint = await listen((request, response) => {
      receivedAuthorization = String(request.headers.authorization ?? "");
      receivedPool = String(request.headers["x-authing-userpool-id"] ?? "");
      request.setEncoding("utf8");
      request.on("data", chunk => { receivedBody += String(chunk); });
      request.on("end", () => {
        response.end('{"access_token":"jwt"}');
      });
    });
    const dispatcher = new Agent();
    dispatchers.push(dispatcher);
    const client = await ApiClient.create({ endpoint, sessionToken: "human", userPoolId: "pool-1", dispatcher });
    await client.runtimeToken({
      credentialId: "aic_123",
      secret: "secret-value",
      userGrantId: "ugr-1",
      audience: "https://api.example.com",
      permissionIds: [],
      ttlSeconds: 0
    });
    expect(receivedAuthorization).toBe(`Basic ${Buffer.from("aic_123:secret-value").toString("base64")}`);
    expect(receivedPool).toBe("pool-1");
    expect(JSON.parse(receivedBody)).not.toHaveProperty("user_pool_id");
  });

  it("retries GET and idempotent writes but not unsafe writes", async () => {
    let requests = 0;
    const endpoint = await listen((_request, response) => {
      requests += 1;
      response.statusCode = requests < 3 ? 503 : 200;
      response.end('{"ok":true}');
    });
    const dispatcher = new Agent();
    dispatchers.push(dispatcher);
    const client = await ApiClient.create({ endpoint, dispatcher, timeoutMs: 3_000 });
    await expect(client.do({ method: "GET", path: "/safe" })).resolves.toMatchObject({ status: 200 });
    expect(requests).toBe(3);
    requests = 0;
    await expect(client.do({ method: "POST", path: "/unsafe", body: { value: 1 } })).rejects.toBeInstanceOf(ApiError);
    expect(requests).toBe(1);
    requests = 0;
    await expect(client.do({ method: "POST", path: "/safe-write", body: {}, headers: { "Idempotency-Key": "key-1" } })).resolves.toMatchObject({ status: 200 });
    expect(requests).toBe(3);
  });

  it("unwraps at most three API data envelopes", () => {
    expect(decodeData({ data: { data: { data: { id: "a" } } } })).toEqual({ id: "a" });
  });

  it.each(["https://evil.example.com", "relative"])("rejects API path %s", value => {
    expect(() => validateApiPath(value)).toThrow("invalid API path");
  });

  it.each([
    "http://user:secret@proxy.example.com",
    "https://proxy.example.com/path",
    "socks5://proxy.example.com"
  ])("rejects unsafe proxy %s", value => {
    expect(() => validateProxyUrl(value)).toThrow(InvalidProxyError);
  });

  it("maps an unreadable or malformed CA file to a stable typed error", async () => {
    await expect(createDispatcher({ caFile: "/definitely/not/a/ca.pem" })).rejects.toBeInstanceOf(InvalidCaFileError);
    const directory = await mkdtemp(path.join(os.tmpdir(), "agent-identity-ca-test-"));
    try {
      const caFile = path.join(directory, "ca.pem");
      await writeFile(caFile, "not a certificate\n", "utf8");
      await expect(createDispatcher({ caFile })).rejects.toMatchObject({
        name: "InvalidCaFileError",
        message: "the configured CA file does not contain a PEM certificate"
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("requires explicit acknowledgement for a localhost HTTP override", () => {
    expect(() => validateCliEndpoint("http://127.0.0.1:3000", false)).toThrowError(expect.objectContaining({ code: "INVALID_ENDPOINT" }));
    expect(() => validateCliEndpoint("http://127.0.0.1:3000", true)).not.toThrow();
    expect(() => validateCliEndpoint("http://example.com", true)).toThrowError(expect.objectContaining({ code: "INVALID_ENDPOINT" }));
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
