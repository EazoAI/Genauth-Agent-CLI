export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;
  readonly retryAfterMs: number;

  constructor(options: {
    status: number;
    code: string;
    message: string;
    requestId?: string;
    retryAfterMs?: number;
  }) {
    super(options.message);
    this.name = "ApiError";
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId ?? "";
    this.retryAfterMs = options.retryAfterMs ?? 0;
  }
}

export class InvalidCaFileError extends Error {
  constructor(message = "the configured CA file is invalid", options?: ErrorOptions) {
    super(message, options);
    this.name = "InvalidCaFileError";
  }
}

export class InvalidProxyError extends Error {
  constructor(message = "proxy must be an HTTP(S) origin without credentials, path, query, or fragment") {
    super(message);
    this.name = "InvalidProxyError";
  }
}
