export type Remediation = Record<string, unknown>;

export class CliError extends Error {
  readonly code: string;
  readonly exitCode: number;
  readonly requestId: string;
  readonly remediation?: Remediation;
  readonly retryable: boolean;

  constructor(options: {
    code: string;
    message: string;
    exitCode: number;
    requestId?: string;
    remediation?: Remediation;
    retryable?: boolean;
    cause?: unknown;
  }) {
    super(options.message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "CliError";
    this.code = options.code;
    this.exitCode = options.exitCode;
    this.requestId = options.requestId ?? "";
    this.retryable = options.retryable ?? false;
    if (options.remediation !== undefined) {
      this.remediation = options.remediation;
    }
  }
}

export function invalidInput(message: string, remediation?: Remediation): CliError {
  return new CliError({
    code: "INVALID_INPUT",
    message,
    exitCode: 2,
    ...(remediation === undefined ? {} : { remediation })
  });
}

export function internalError(message: string, cause?: unknown): CliError {
  return new CliError({ code: "CLI_INTERNAL_ERROR", message, exitCode: 9, cause });
}

export function asCliError(error: unknown): CliError {
  if (error instanceof CliError) {
    return error;
  }
  if (error instanceof Error) {
    return internalError(error.message, error);
  }
  return internalError("unexpected CLI failure", error);
}
