import { Command } from "commander";
import { AppContext } from "./context.js";
import { CommandRegistry } from "./manifest.js";
import { registerAuthCommands } from "./commands/auth.js";
import { registerProfileCommands } from "./commands/profiles.js";
import { registerPermissionCommands } from "./commands/permissions.js";
import { registerSystemCommands } from "./commands/system.js";
import { registerAgentCommands } from "./commands/agents.js";
import { registerApprovalCommands } from "./commands/approvals.js";
import { registerCredentialCommands } from "./commands/credentials.js";
import { registerAuthorizationCommands } from "./commands/authorizations.js";
import { registerRuntimeCommands } from "./commands/runtime.js";

export interface ProgramBundle {
  program: Command;
  registry: CommandRegistry;
  app: AppContext;
}

export function createProgram(app = new AppContext()): ProgramBundle {
  const program = new Command();
  const registry = new CommandRegistry();
  program
    .name("genauth-agent")
    .description("GenAuth Agent Identity CLI")
    .showHelpAfterError(false)
    .option("--profile <name>", "local profile name")
    .option("--timeout <duration>", "request timeout", "15s")
    .option("--endpoint <url>", "override GenAuth HTTPS origin")
    .option("--output <format>", "output format: table, json, or yaml", "json")
    .option("--request-id <uuid>", "caller-provided UUID request ID")
    .option("--correlation-id <uuid>", "caller-provided UUID correlation ID")
    .option("--no-browser", "do not open a browser")
    .option("--non-interactive", "fail instead of waiting for interactive input")
    .option("--quiet", "suppress progress output")
    .option("--debug", "emit redacted diagnostics")
    .option("--proxy <url>", "HTTP(S) proxy URL without credentials")
    .option("--ca-file <path>", "PEM CA bundle used in addition to system roots")
    .option("--allow-insecure-localhost", "allow an explicit localhost HTTP GenAuth endpoint");
  program.exitOverride();

  registerAuthCommands(program, registry, app);
  registerProfileCommands(program, registry, app);
  registerPermissionCommands(program, registry, app);
  registerAgentCommands(program, registry, app);
  registerApprovalCommands(program, registry, app);
  registerCredentialCommands(program, registry, app);
  registerAuthorizationCommands(program, registry, app);
  registerRuntimeCommands(program, registry, app);
  registerSystemCommands(program, registry, app);
  return { program, registry, app };
}
