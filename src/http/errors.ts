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
