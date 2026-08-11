import { randomUUID } from "node:crypto";
import type { Command } from "commander";
import { ApiClient, decodeData } from "../http/client.js";
import type { Dispatcher } from "undici";
import { ApiError, InvalidCaFileError, InvalidProxyError } from "../http/errors.js";
import { OAuthClient, type OAuthToken } from "../auth/oauth.js";
import { CliError } from "../core/errors.js";
import { parseDurationMs } from "../core/duration.js";
import { parseOutputFormat, serializeSuccess, type OutputFormat } from "../core/output.js";
import { InvalidProfileError, ProfileStore, validateEndpoint, type Profile } from "../storage/profile-store.js";
import { KeychainSecretStore, type SecretStore } from "../storage/secret-store.js";

export interface GlobalOptions {
  profile: string;
  timeoutMs: number;
  endpoint: string;
  output: OutputFormat;
  requestId: string;
  noBrowser: boolean;
  nonInteractive: boolean;
  quiet: boolean;
  debug: boolean;
  proxy: string;
  caFile: string;
  allowInsecureLocalhost: boolean;
}

export interface LoadedClient {
  client: ApiClient;
  token: OAuthToken;
  name: string;
  profile: Profile;
}

export interface AppIo {
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
  error: NodeJS.WritableStream;
}

export class AppContext {
  readonly profiles: ProfileStore;
  readonly secrets: SecretStore;
  readonly io: AppIo;
  readonly dispatcher?: Dispatcher;

  constructor(options: { profiles?: ProfileStore; secrets?: SecretStore; io?: Partial<AppIo>; dispatcher?: Dispatcher } = {}) {
    this.profiles = options.profiles ?? new ProfileStore();
    this.secrets = options.secrets ?? new KeychainSecretStore();
    this.io = {
      input: options.io?.input ?? process.stdin,
      output: options.io?.output ?? process.stdout,
      error: options.io?.error ?? process.stderr
    };
    if (options.dispatcher !== undefined) this.dispatcher = options.dispatcher;
  }

  global(command: Command): GlobalOptions {
    const values = command.optsWithGlobals<Record<string, unknown>>();
    const requestId = stringOption(values.correlationId) || stringOption(values.requestId);
    if (requestId !== "" && !isUuid(requestId)) {
      throw new CliError({ code: "INVALID_ARGUMENT", message: "request-id must be a UUID", exitCode: 2 });
    }
    let output: OutputFormat;
    try {
      output = parseOutputFormat(stringOption(values.output) || "json");
    } catch (error) {
      throw new CliError({ code: "INVALID_ARGUMENT", message: error instanceof Error ? error.message : "invalid output", exitCode: 2 });
    }
    let timeoutMs: number;
    try {
      timeoutMs = parseDurationMs(stringOption(values.timeout) || "15s");
    } catch (error) {
      throw new CliError({ code: "INVALID_ARGUMENT", message: error instanceof Error ? error.message : "invalid timeout", exitCode: 2 });
    }
    return {
      profile: stringOption(values.profile),
      timeoutMs,
      endpoint: stringOption(values.endpoint).replace(/\/$/u, ""),
      output,
      requestId,
      noBrowser: Boolean(values.noBrowser),
      nonInteractive: Boolean(values.nonInteractive),
      quiet: Boolean(values.quiet),
      debug: Boolean(values.debug),
      proxy: stringOption(values.proxy),
      caFile: stringOption(values.caFile),
      allowInsecureLocalhost: Boolean(values.allowInsecureLocalhost)
    };
  }

  success(global: GlobalOptions, kind: string, data: unknown, requestId = "", warnings: string[] = []): void {
    this.io.output.write(serializeSuccess(global.output, kind, data, requestId, warnings));
  }

  async loadClient(global: GlobalOptions): Promise<LoadedClient> {
    let current: Awaited<ReturnType<ProfileStore["current"]>>;
    try {
      current = await this.profiles.current(global.profile);
    } catch (error) {
      if (error instanceof InvalidProfileError) {
        throw new CliError({ code: "NOT_LOGGED_IN", message: "run agent-identity auth login first", exitCode: 3 });
      }
      throw error;
    }
    let serialized: string;
    try {
      serialized = await this.secrets.get(current.profile.secret_ref);
    } catch {
      throw new CliError({ code: "SESSION_EXPIRED", message: "login session is unavailable", exitCode: 3 });
    }
    let token: OAuthToken;
    try {
      const parsed = JSON.parse(serialized) as Partial<OAuthToken>;
      token = parsed.access_token ? parsed as OAuthToken : { access_token: serialized };
    } catch {
      token = { access_token: serialized };
    }
    const profile = { ...current.profile };
    if (global.endpoint !== "") {
      validateCliEndpoint(global.endpoint, global.allowInsecureLocalhost);
      profile.endpoint = global.endpoint;
    }
    let client: ApiClient;
    try {
      client = await ApiClient.create({
        endpoint: profile.endpoint,
        sessionToken: token.access_token,
        userPoolId: profile.selected_user_pool_id,
        requestId: global.requestId,
        timeoutMs: global.timeoutMs,
        proxyUrl: global.proxy,
        caFile: global.caFile,
        ...(this.dispatcher === undefined ? {} : { dispatcher: this.dispatcher })
      });
    } catch (error) {
      if (error instanceof InvalidCaFileError) throw new CliError({ code: "INVALID_CA_FILE", message: error.message, exitCode: 2 });
      if (error instanceof InvalidProxyError) throw new CliError({ code: "INVALID_PROXY", message: error.message, exitCode: 2 });
      throw error;
    }
    return { client, token, name: current.name, profile };
  }

  async call<T = unknown>(global: GlobalOptions, requestOptions: Parameters<ApiClient["do"]>[0]): Promise<{ data: T; requestId: string }> {
    const loaded = await this.loadClient(global);
    let result: Awaited<ReturnType<ApiClient["do"]>>;
    try {
      result = await loaded.client.do(requestOptions);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401 || !loaded.token.refresh_token || !loaded.profile.client_id) {
        throw classifyApiError(error);
      }
      const oauth = new OAuthClient({
        endpoint: loaded.profile.endpoint,
        clientId: loaded.profile.client_id,
        dispatcher: loaded.client.dispatcher,
        timeoutMs: global.timeoutMs
      });
      let refreshed: OAuthToken;
      try {
        refreshed = await oauth.refresh(loaded.token.refresh_token);
        await this.secrets.set(loaded.profile.secret_ref, JSON.stringify(refreshed));
      } catch {
        throw classifyApiError(error);
      }
      const retryClient = await ApiClient.create({
        endpoint: loaded.profile.endpoint,
        sessionToken: refreshed.access_token,
        userPoolId: loaded.profile.selected_user_pool_id,
        requestId: global.requestId,
        timeoutMs: global.timeoutMs,
        dispatcher: loaded.client.dispatcher
      });
      try {
        result = await retryClient.do(requestOptions);
      } catch (retryError) {
        throw classifyApiError(retryError);
      }
    }
    if (global.debug) {
      this.io.error.write(`agent-identity debug method=${requestOptions.method} path=${requestOptions.path} result=success request_id=${result.requestId}\n`);
    }
    return { data: result.data, requestId: result.requestId } as { data: T; requestId: string };
  }

  async simple(global: GlobalOptions, options: Parameters<AppContext["call"]>[1], kind: string): Promise<void> {
    const result = await this.call(global, options);
    this.success(global, kind, result.data, result.requestId);
  }

  async probeSecretStore(): Promise<void> {
    const reference = `keychain://agent-identity/probe/${randomUUID()}`;
    try {
      await this.secrets.set(reference, "secret-store-readiness-probe");
      await this.secrets.delete(reference);
    } catch {
      throw new CliError({ code: "SECRET_STORE_UNAVAILABLE", message: "OS secret store is unavailable", exitCode: 9 });
    }
  }

  managementPrefix(profile: Profile): string {
    return profile.login_type === "user" ? "/api/v3/agent-identity/me" : "/api/v3/agent-identity/admin";
  }

  async currentProfile(global: GlobalOptions): Promise<{ name: string; profile: Profile }> {
    const current = await this.profiles.current(global.profile);
    return { name: current.name, profile: current.profile };
  }
}

export function classifyApiError(error: unknown): CliError {
  if (error instanceof CliError) {
    return error;
  }
  if (!(error instanceof ApiError)) {
    return new CliError({ code: "UPSTREAM_UNAVAILABLE", message: "GenAuth is unavailable", exitCode: 7, retryable: true, cause: error });
  }
  const exitCode = error.status === 401 ? 3
    : error.status === 403 ? 4
      : error.status === 404 || error.status === 410 || error.status === 422 ? 5
        : error.status === 409 ? 8
          : error.status === 429 || error.status >= 500 ? 7
            : error.status >= 400 ? 2
              : 9;
  return new CliError({
    code: error.code,
    message: error.message,
    requestId: error.requestId,
    exitCode,
    retryable: exitCode === 7
  });
}

export function decodeResponseData<T>(value: unknown): T {
  return decodeData<T>(value);
}

export function validateCliEndpoint(endpoint: string, allowInsecureLocalhost: boolean): void {
  try {
    validateEndpoint(endpoint);
    const parsed = new URL(endpoint);
    if (parsed.protocol === "http:" && !allowInsecureLocalhost) {
      throw new Error("insecure localhost endpoint requires explicit acknowledgement");
    }
  } catch {
    throw new CliError({ code: "INVALID_ENDPOINT", message: "endpoint must be a GenAuth HTTPS origin", exitCode: 2 });
  }
}

function stringOption(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}
