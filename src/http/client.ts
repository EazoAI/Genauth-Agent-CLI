import { readFile } from "node:fs/promises";
import { rootCertificates } from "node:tls";
import { X509Certificate } from "node:crypto";
import { Agent, EnvHttpProxyAgent, ProxyAgent, request, type Dispatcher } from "undici";
import { ApiError, InvalidCaFileError, InvalidProxyError } from "./errors.js";

const maximumResponseBytes = 52 * 1024 * 1024;
const retryStatuses = new Set([429, 502, 503, 504]);

export interface ClientOptions {
  endpoint: string;
  sessionToken?: string;
  userPoolId?: string;
  requestId?: string;
  timeoutMs?: number;
  proxyUrl?: string;
  caFile?: string;
  dispatcher?: Dispatcher;
}

export interface ApiResponse<T = unknown> {
  data: T;
  requestId: string;
  status: number;
}

export class ApiClient {
  readonly endpoint: string;
  readonly sessionToken: string;
  readonly userPoolId: string;
  readonly requestId: string;
  readonly timeoutMs: number;
  readonly dispatcher: Dispatcher;

  private constructor(options: ClientOptions, dispatcher: Dispatcher) {
    this.endpoint = options.endpoint.replace(/\/$/u, "");
    this.sessionToken = options.sessionToken ?? "";
    this.userPoolId = options.userPoolId ?? "";
    this.requestId = options.requestId ?? "";
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.dispatcher = dispatcher;
  }

  static async create(options: ClientOptions): Promise<ApiClient> {
    const dispatcher = options.dispatcher ?? await createDispatcher(options);
    return new ApiClient(options, dispatcher);
  }

  async do<T = unknown>(options: {
    method: string;
    path: string;
    query?: URLSearchParams | Record<string, string | number | boolean | undefined>;
    body?: unknown;
    headers?: Record<string, string>;
    signal?: AbortSignal;
    responseType?: "json" | "buffer";
  }): Promise<ApiResponse<T>> {
    validateApiPath(options.path);
    const target = new URL(`${this.endpoint}${options.path}`);
    if (options.query instanceof URLSearchParams) {
      target.search = options.query.toString();
    } else if (options.query) {
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined) {
          target.searchParams.append(key, String(value));
        }
      }
    }
    const headers: Record<string, string> = { ...(options.headers ?? {}) };
    if (this.sessionToken !== "" && headers.Authorization === undefined) {
      headers.Authorization = `Bearer ${this.sessionToken}`;
    }
    if (this.userPoolId !== "") {
      headers["x-authing-userpool-id"] = this.userPoolId;
    }
    if (this.requestId !== "") {
      headers["X-Request-Id"] = this.requestId;
    }
    let encodedBody: string | undefined;
    if (options.body !== undefined) {
      encodedBody = JSON.stringify(options.body);
      headers["Content-Type"] = "application/json";
    }
    const method = options.method.toUpperCase();
    const retryable = method === "GET" || method === "HEAD" || hasHeader(headers, "Idempotency-Key");
    const attempts = retryable ? 3 : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        const response = await request(target, {
          method: method as Dispatcher.HttpMethod,
          headers,
          dispatcher: this.dispatcher,
          headersTimeout: this.timeoutMs,
          bodyTimeout: this.timeoutMs,
          ...(encodedBody === undefined ? {} : { body: encodedBody }),
          ...(options.signal === undefined ? {} : { signal: options.signal })
        });
        const responseRequestId = headerValue(response.headers["x-request-id"]);
        const content = await readBoundedBody(response.body);
        const textContent = content.toString("utf8");
        if (attempt + 1 < attempts && retryStatuses.has(response.statusCode)) {
          await waitForRetry(attempt, options.signal);
          continue;
        }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          throw decodeApiError(response.statusCode, textContent, responseRequestId, headerValue(response.headers["retry-after"]));
        }
        return {
          data: (options.responseType === "buffer" ? content : decodeJson<T>(textContent)) as T,
          requestId: responseRequestId,
          status: response.statusCode
        };
      } catch (error) {
        lastError = error;
        if (error instanceof ApiError || attempt + 1 >= attempts || options.signal?.aborted) {
          throw error;
        }
        await waitForRetry(attempt, options.signal);
      }
    }
    throw lastError instanceof Error ? lastError : new Error("request retry exhausted");
  }

  async runtimeToken<T = unknown>(options: {
    credentialId: string;
    secret: string;
    userGrantId: string;
    audience: string;
    permissionIds: string[];
    ttlSeconds: number;
    signal?: AbortSignal;
  }): Promise<ApiResponse<T>> {
    const authorization = Buffer.from(`${options.credentialId}:${options.secret}`, "utf8").toString("base64");
    return this.do<T>({
      method: "POST",
      path: "/api/v3/agent-runtime/token",
      body: {
        user_grant_id: options.userGrantId,
        audience: options.audience,
        permission_ids: options.permissionIds,
        token_ttl_seconds: options.ttlSeconds
      },
      headers: { Authorization: `Basic ${authorization}` },
      ...(options.signal === undefined ? {} : { signal: options.signal })
    });
  }
}

export function decodeData<T>(raw: unknown): T {
  let current = raw;
  for (let index = 0; index < 3; index += 1) {
    if (isRecord(current) && current.data !== undefined && current.data !== null) {
      current = current.data;
      continue;
    }
    break;
  }
  return current as T;
}

export function validateApiPath(value: string): void {
  if (!value.startsWith("/") || value.includes("://")) {
    throw new Error("invalid API path");
  }
}

export async function createDispatcher(options: Pick<ClientOptions, "proxyUrl" | "caFile">): Promise<Dispatcher> {
  const connect: Record<string, unknown> = { minVersion: "TLSv1.2" };
  if (options.caFile) {
    let customCa: string;
    try {
      customCa = await readFile(options.caFile, "utf8");
      validatePemCertificates(customCa);
    } catch (error) {
      throw error instanceof InvalidCaFileError ? error : new InvalidCaFileError("unable to read the configured CA file", { cause: error });
    }
    connect.ca = [...rootCertificates, customCa];
  }
  if (options.proxyUrl) {
    const proxy = validateProxyUrl(options.proxyUrl);
    return new ProxyAgent({ uri: proxy, requestTls: connect });
  }
  if (process.env.HTTP_PROXY || process.env.HTTPS_PROXY || process.env.NO_PROXY) {
    return new EnvHttpProxyAgent({ requestTls: connect });
  }
  return new Agent({ connect });
}

export function validateProxyUrl(value: string): string {
  let proxy: URL;
  try { proxy = new URL(value); }
  catch { throw new InvalidProxyError(); }
  if (
    (proxy.protocol !== "http:" && proxy.protocol !== "https:") ||
    proxy.username !== "" ||
    proxy.password !== "" ||
    (proxy.pathname !== "" && proxy.pathname !== "/") ||
    proxy.search !== "" ||
    proxy.hash !== ""
  ) {
    throw new InvalidProxyError();
  }
  return proxy.origin;
}

function validatePemCertificates(content: string): void {
  const certificates = content.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/gu) ?? [];
  if (certificates.length === 0) throw new InvalidCaFileError("the configured CA file does not contain a PEM certificate");
  try { for (const certificate of certificates) void new X509Certificate(certificate); }
  catch (error) { throw new InvalidCaFileError("the configured CA file does not contain a valid PEM certificate", { cause: error }); }
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const target = name.toLowerCase();
  return Object.entries(headers).some(([key, value]) => key.toLowerCase() === target && value.trim() !== "");
}

function headerValue(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? "" : value ?? "";
}

function decodeJson<T>(content: string): T {
  if (content.trim() === "") {
    return null as T;
  }
  return JSON.parse(content) as T;
}

function decodeApiError(status: number, content: string, requestId: string, retryAfter: string): ApiError {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    parsed = undefined;
  }
  const envelope = isRecord(parsed) ? parsed : {};
  const nested = isRecord(envelope.error) ? envelope.error : {};
  const code = stringValue(nested.code) || stringValue(envelope.code) || "HTTP_ERROR";
  const message = stringValue(nested.message) || stringValue(envelope.message) || statusText(status);
  const resolvedRequestId = stringValue(nested.request_id) || requestId;
  return new ApiError({
    status,
    code,
    message,
    requestId: resolvedRequestId,
    retryAfterMs: parseRetryAfter(retryAfter)
  });
}

function statusText(status: number): string {
  return `HTTP ${status}`;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseRetryAfter(value: string): number {
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds > 0) {
    return Math.round(seconds * 1000);
  }
  const target = Date.parse(value);
  return Number.isFinite(target) ? Math.max(0, target - Date.now()) : 0;
}

async function waitForRetry(attempt: number, signal?: AbortSignal): Promise<void> {
  const delay = 100 * (2 ** attempt) + Math.floor(Math.random() * 100);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, delay);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(signal.reason instanceof Error ? signal.reason : new Error("request aborted"));
    }, { once: true });
  });
}

async function readBoundedBody(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of body) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > maximumResponseBytes) {
      throw new Error("response body exceeds 52 MiB limit");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}
