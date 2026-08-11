import { readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import { invalidInput } from "./errors.js";

export async function readJsonFile(filePath: string): Promise<unknown> {
  const content = await readFile(filePath, "utf8");
  try {
    return JSON.parse(content) as unknown;
  } catch {
    throw invalidInput("input file must contain valid JSON");
  }
}

export async function readObjectFile(filePath: string): Promise<Record<string, unknown>> {
  const content = await readFile(filePath, "utf8");
  try {
    const parsed: unknown = parseYaml(content);
    if (!isRecord(parsed)) {
      throw new Error("not an object");
    }
    return parsed;
  } catch {
    throw invalidInput("input file must contain a YAML or JSON object");
  }
}

export function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.map(value => value.trim()).filter(Boolean))];
}

export function stringList(value: unknown): string[] {
  return Array.isArray(value) ? uniqueStrings(value.filter((item): item is string => typeof item === "string")) : [];
}

export function permissionIds(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return uniqueStrings(value.flatMap(item => isRecord(item) && typeof item.permission_id === "string" ? [item.permission_id] : []));
}

export async function readLimitedStdin(stream: NodeJS.ReadableStream, maximumBytes = 64 * 1024): Promise<string> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    length += buffer.length;
    if (length > maximumBytes) {
      throw invalidInput("stdin exceeds the allowed size");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
