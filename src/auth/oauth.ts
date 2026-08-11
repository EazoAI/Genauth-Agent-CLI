import http from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { request, type Dispatcher } from "undici";
import { createPkce, randomState } from "./pkce.js";
import { openBrowser } from "./browser.js";

export interface OAuthToken {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

export interface OAuthOptions {
  endpoint: string;
  clientId: string;
  dispatcher: Dispatcher;
  timeoutMs?: number;
}

export class OAuthClient {
  readonly endpoint: string;
  readonly clientId: string;
  readonly dispatcher: Dispatcher;
  readonly timeoutMs: number;

  constructor(options: OAuthOptions) {
    this.endpoint = options.endpoint.replace(/\/$/u, "");
    this.clientId = options.clientId.trim();
    this.dispatcher = options.dispatcher;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  async refresh(refreshToken: string, signal?: AbortSignal): Promise<OAuthToken> {
    if (this.clientId === "" || refreshToken.trim() === "") {
      throw new Error("client ID and refresh token are required");
    }
    const token = await this.formPost<OAuthToken>("/oidc/token", new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.clientId,
      refresh_token: refreshToken
    }), signal);
    if (!token.access_token) {
      throw new Error("invalid OAuth token response");
    }
    return token.refresh_token ? token : { ...token, refresh_token: refreshToken };
  }

  async revoke(token: OAuthToken, signal?: AbortSignal): Promise<void> {
    if (this.clientId === "") {
      throw new Error("client ID is required");
    }
    const value = token.refresh_token?.trim() || token.access_token.trim();
    const hint = token.refresh_token?.trim() ? "refresh_token" : "access_token";
    if (value === "") {
      throw new Error("session token is required");
    }
    await this.formPost<unknown>("/oidc/token/revocation", new URLSearchParams({
      client_id: this.clientId,
      token: value,
      token_type_hint: hint
    }), signal, true);
  }

  async login(options: {
    userPoolId?: string;
    noBrowser?: boolean;
    notify: (url: string) => void;
    signal?: AbortSignal;
  }): Promise<OAuthToken> {
    if (this.clientId === "") {
      throw new Error("client ID is required for browser login");
    }
    const callbackServer = http.createServer();
    callbackServer.listen(0, "127.0.0.1");
    await once(callbackServer, "listening");
    const address = callbackServer.address() as AddressInfo;
    const redirectUri = `http://127.0.0.1:${address.port}/callback`;
    const state = randomState();
    const pkce = createPkce();
    const authorize = new URL(`${this.endpoint}/oidc/auth`);
    authorize.search = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid profile offline_access",
      state,
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      ...(options.userPoolId?.trim() ? { user_pool_id: options.userPoolId.trim() } : {})
    }).toString();
    const callback = waitForLoginCallback(callbackServer, state, options.signal);
    options.notify(authorize.toString());
    if (!options.noBrowser) {
      openBrowser(authorize.toString());
    }
    try {
      const code = await callback;
      const token = await this.formPost<OAuthToken>("/oidc/token", new URLSearchParams({
        grant_type: "authorization_code",
        client_id: this.clientId,
        code,
        redirect_uri: redirectUri,
        code_verifier: pkce.verifier
      }), options.signal);
      if (!token.access_token) {
        throw new Error("invalid OAuth token response");
      }
      return token;
    } finally {
      await closeServer(callbackServer);
    }
  }

  private async formPost<T>(path: string, form: URLSearchParams, signal?: AbortSignal, allowEmpty = false): Promise<T> {
    const response = await request(`${this.endpoint}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      dispatcher: this.dispatcher,
      headersTimeout: this.timeoutMs,
      bodyTimeout: this.timeoutMs,
      ...(signal === undefined ? {} : { signal })
    });
    const content = await response.body.text();
    if (response.statusCode < 200 || response.statusCode >= 300) {
      const operation = path.endsWith("revocation") ? "revocation" : path.endsWith("token") ? "token exchange" : "request";
      throw new Error(`OAuth ${operation} returned ${response.statusCode}`);
    }
    if (allowEmpty && content.trim() === "") {
      return undefined as T;
    }
    return JSON.parse(content) as T;
  }
}

function waitForLoginCallback(server: http.Server, expectedState: string, signal?: AbortSignal): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const abort = (): void => reject(signal?.reason instanceof Error ? signal.reason : new Error("OAuth login aborted"));
    signal?.addEventListener("abort", abort, { once: true });
    server.on("request", (request, response) => {
      const target = new URL(request.url ?? "/", "http://127.0.0.1");
      if (target.pathname !== "/callback") {
        response.statusCode = 404;
        response.end("Not found");
        return;
      }
      response.setHeader("Content-Type", "text/plain; charset=utf-8");
      response.end("Agent Identity CLI login received. You may close this window.");
      const code = target.searchParams.get("code") ?? "";
      const state = target.searchParams.get("state") ?? "";
      if (target.searchParams.get("error") || state !== expectedState || code === "") {
        reject(new Error("OAuth authorization was denied or invalid"));
      } else {
        resolve(code);
      }
    });
  });
}

async function closeServer(server: http.Server): Promise<void> {
  if (!server.listening) {
    return;
  }
  await new Promise<void>(resolve => server.close(() => resolve()));
}
