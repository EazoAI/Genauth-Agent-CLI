import type { Command } from "commander";
import type { AppContext } from "../context.js";
import { COMMAND_CONTRACT, type CommandRegistry } from "../manifest.js";

export const CLI_VERSION = "0.1.0";

export function registerSystemCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  registry.leaf(parent, { path: "doctor", description: "Check profile, Keychain, and GenAuth connectivity", options: [] }, async (_options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    const result = await app.call(global, {
      method: "GET",
      path: `${app.managementPrefix(current.profile)}/agents`,
      query: { page_size: 1 }
    });
    app.success(global, "DoctorReport", {
      profile: current.name,
      endpoint: current.profile.endpoint,
      selected_user_pool_id: current.profile.selected_user_pool_id,
      secret_store: "available",
      genauth: true
    }, result.requestId);
  });

  registry.leaf(parent, { path: "version", description: "Show CLI and contract versions", options: [] }, async (_options, command) => {
    const global = app.global(command);
    app.success(global, "Version", {
      cli_version: CLI_VERSION,
      api_version: "genauth-agent.cli/v1",
      command_contract: COMMAND_CONTRACT,
      server_contract: "genauth-agent-identity-v1",
      runtime: "node",
      node_version: process.version
    });
  });

  registry.leaf(parent, {
    path: "completion",
    description: "Generate shell completion",
    arguments: "<shell>",
    options: []
  }, async (_options, command) => {
    const global = app.global(command);
    const shell = String(command.args[0] ?? "");
    if (!["bash", "zsh", "fish", "powershell"].includes(shell)) {
      const { CliError } = await import("../../core/errors.js");
      throw new CliError({ code: "INVALID_ARGUMENT", message: "shell must be bash, zsh, fish, or powershell", exitCode: 2 });
    }
    const words = registry.commands.flatMap(item => item.path.split(" "));
    const unique = [...new Set(words)].sort().join(" ");
    const scripts: Record<string, string> = {
      bash: `complete -W "${unique}" genauth-agent\n`,
      zsh: `compdef '_arguments "1:command:(${unique})"' genauth-agent\n`,
      fish: unique.split(" ").map(word => `complete -c genauth-agent -a '${word}'`).join("\n") + "\n",
      powershell: `Register-ArgumentCompleter -CommandName genauth-agent -ScriptBlock { param($wordToComplete) '${unique}'.Split(' ') | Where-Object { $_ -like \"$wordToComplete*\" } }\n`
    };
    app.io.output.write(scripts[shell] ?? "");
    void global;
  });
}
