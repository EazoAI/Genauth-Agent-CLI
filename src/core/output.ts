import { stringify as stringifyYaml } from "yaml";

export const CLI_API_VERSION = "agent-identity.cli/v1";
export type OutputFormat = "json" | "yaml" | "table";

export interface SuccessEnvelope<T = unknown> {
  api_version: typeof CLI_API_VERSION;
  kind: string;
  data: T;
  request_id?: string;
  warnings: string[];
}

export interface FailureEnvelope {
  api_version: typeof CLI_API_VERSION;
  error: {
    code: string;
    message: string;
    remediation?: Record<string, unknown>;
  };
  request_id?: string;
}

export function parseOutputFormat(value: string): OutputFormat {
  const normalized = value.trim().toLowerCase();
  if (normalized === "json" || normalized === "yaml" || normalized === "table") {
    return normalized;
  }
  throw new Error("output must be table, json, or yaml");
}

export function serializeSuccess(
  format: OutputFormat,
  kind: string,
  data: unknown,
  requestId = "",
  warnings: string[] = []
): string {
  const envelope: SuccessEnvelope = {
    api_version: CLI_API_VERSION,
    kind,
    data,
    warnings
  };
  if (requestId !== "") {
    envelope.request_id = requestId;
  }
  if (format === "yaml") {
    return stringifyYaml(envelope);
  }
  if (format === "table") {
    const rows = [`KIND\t${kind}`];
    if (requestId !== "") {
      rows.push(`REQUEST_ID\t${requestId}`);
    }
    writeTableRows(rows, "DATA", data);
    for (const warning of warnings) {
      rows.push(`WARNING\t${warning}`);
    }
    return `${rows.join("\n")}\n`;
  }
  return `${JSON.stringify(envelope)}\n`;
}

export function serializeFailure(
  code: string,
  message: string,
  requestId = "",
  remediation?: Record<string, unknown>
): string {
  const error: FailureEnvelope["error"] = { code, message };
  if (remediation !== undefined) {
    error.remediation = remediation;
  }
  const envelope: FailureEnvelope = { api_version: CLI_API_VERSION, error };
  if (requestId !== "") {
    envelope.request_id = requestId;
  }
  return `${JSON.stringify(envelope)}\n`;
}

function writeTableRows(rows: string[], prefix: string, value: unknown): void {
  if (isRecord(value)) {
    for (const key of Object.keys(value).sort()) {
      writeTableRows(rows, key, value[key]);
    }
    return;
  }
  const encoded = JSON.stringify(value);
  rows.push(`${prefix.toUpperCase()}\t${stripJsonStringQuotes(encoded)}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stripJsonStringQuotes(value: string | undefined): string {
  if (value === undefined) {
    return "null";
  }
  return value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value;
}
