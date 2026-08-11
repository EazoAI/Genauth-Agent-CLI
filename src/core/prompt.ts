import type { Readable, Writable } from "node:stream";
import { createInterface } from "node:readline/promises";
import { CliError } from "./errors.js";

export async function promptIfEmpty(
  input: NodeJS.ReadableStream,
  output: NodeJS.WritableStream,
  label: string,
  current: string
): Promise<string> {
  if (current.trim() !== "") {
    return current;
  }
  const readline = createInterface({ input: input as Readable, output: output as Writable });
  try {
    const value = (await readline.question(`${label}: `)).trim();
    if (value === "") {
      throw new CliError({ code: "INVALID_ARGUMENT", message: `${label} is required`, exitCode: 2 });
    }
    return value;
  } finally {
    readline.close();
  }
}
