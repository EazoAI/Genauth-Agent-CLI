#!/usr/bin/env node

import { CommanderError } from "commander";
import { createProgram } from "../cli/create-program.js";
import { asCliError } from "../core/errors.js";
import { serializeFailure } from "../core/output.js";

export async function run(arguments_: string[] = process.argv): Promise<number> {
  const { program, app } = createProgram();
  try {
    await program.parseAsync(arguments_);
    return 0;
  } catch (error) {
    if (error instanceof CommanderError && (error.code === "commander.helpDisplayed" || error.code === "commander.version")) {
      return 0;
    }
    const failure = error instanceof CommanderError
      ? { code: "INVALID_ARGUMENT", message: error.message, exitCode: 2, requestId: "", remediation: undefined }
      : asCliError(error);
    app.io.error.write(serializeFailure(failure.code, failure.message, failure.requestId, failure.remediation));
    return failure.exitCode;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await run();
}
