import http from "node:http";
import { once } from "node:events";

export interface AuthorizationCallback {
  code: string;
  error: string;
}

export async function reserveLoopbackRedirectUri(): Promise<string> {
  const server = http.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    await close(server);
    throw new Error("could not reserve loopback callback");
  }
  const result = `http://127.0.0.1:${address.port}/callback`;
  await close(server);
  return result;
}

export async function listenAuthorizationCallback(
  callbackUri: string,
  requestId: string,
  signal?: AbortSignal
): Promise<{ event: Promise<AuthorizationCallback>; close: () => Promise<void> }> {
  const parsed = new URL(callbackUri);
  if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || !parsed.port || parsed.pathname !== "/callback") {
    throw new Error("callback is not a supported loopback URI");
  }
  let resolveEvent: (event: AuthorizationCallback) => void = () => undefined;
  const event = new Promise<AuthorizationCallback>(resolve => { resolveEvent = resolve; });
  const server = http.createServer((request, response) => {
    const target = new URL(request.url ?? "/", callbackUri);
    if (target.pathname !== "/callback" || target.searchParams.get("request_id") !== requestId) {
      response.statusCode = 400;
      response.end("Invalid Agent Identity authorization callback.");
      return;
    }
    const result = {
      code: target.searchParams.get("code") ?? "",
      error: target.searchParams.get("error") ?? ""
    };
    if (!result.code && !result.error) {
      response.statusCode = 400;
      response.end("Missing Agent Identity authorization result.");
      return;
    }
    response.setHeader("Content-Type", "text/plain; charset=utf-8");
    response.setHeader("Cache-Control", "no-store");
    response.end("Agent Identity authorization received. You may close this window.");
    resolveEvent(result);
  });
  server.listen(Number(parsed.port), "127.0.0.1");
  await once(server, "listening");
  signal?.addEventListener("abort", () => { void close(server); }, { once: true });
  return { event, close: () => close(server) };
}

async function close(server: http.Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>(resolve => server.close(() => resolve()));
}
