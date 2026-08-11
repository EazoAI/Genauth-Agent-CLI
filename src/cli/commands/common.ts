import type { OptionValues } from "commander";
import { CliError } from "../../core/errors.js";

export function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

export function requiredText(value: unknown, name: string): string {
  const result = text(value);
  if (result === "") {
    throw new CliError({ code: "INVALID_ARGUMENT", message: `${name} is required`, exitCode: 2 });
  }
  return result;
}

export function stringOptions(value: unknown): string[] {
  return Array.isArray(value)
    ? [...new Set(value.filter((item): item is string => typeof item === "string").map(item => item.trim()).filter(Boolean))]
    : [];
}

export function integerOption(value: unknown, name: string, defaultValue = 0): number {
  const parsed = value === undefined ? defaultValue : Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new CliError({ code: "INVALID_ARGUMENT", message: `${name} must be an integer`, exitCode: 2 });
  }
  return parsed;
}

export function confirmation(options: OptionValues, action: string): void {
  if (!options.yes) {
    throw new CliError({ code: "CONFIRMATION_REQUIRED", message: `pass --yes after confirming: ${action}`, exitCode: 2 });
  }
}

export function compactQuery(values: Record<string, string>): URLSearchParams {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== "") {
      query.set(key, value);
    }
  }
  return query;
}
