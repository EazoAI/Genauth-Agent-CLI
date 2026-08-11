import { Option, type Command, type OptionValues } from "commander";

export const COMMAND_CONTRACT = "agent-identity.commands/v2";

export interface OptionContract {
  flags: string;
  description: string;
  defaultValue?: unknown;
  hidden?: boolean;
  collect?: boolean;
}

export interface CommandContract {
  path: string;
  description: string;
  options: OptionContract[];
  arguments?: string;
  aliases?: string[];
}

export type CommandHandler = (options: OptionValues, command: Command) => Promise<void>;

export class CommandRegistry {
  readonly commands: CommandContract[] = [];

  group(parent: Command, name: string, description: string): Command {
    const command = parent.command(name).description(description);
    return command;
  }

  leaf(parent: Command, contract: CommandContract, handler: CommandHandler): Command {
    const name = contract.arguments ? `${leafName(contract.path)} ${contract.arguments}` : leafName(contract.path);
    const command = parent.command(name).description(contract.description);
    for (const alias of contract.aliases ?? []) {
      command.alias(alias);
    }
    for (const option of contract.options) {
      const commanderOption = new Option(option.flags, option.description);
      if (option.defaultValue !== undefined) {
        commanderOption.default(option.defaultValue);
      }
      if (option.hidden) {
        commanderOption.hideHelp();
      }
      if (option.collect) {
        commanderOption.argParser((value: string, previous: unknown) => [
          ...(Array.isArray(previous) ? previous : []),
          value
        ]).default([]);
      }
      command.addOption(commanderOption);
    }
    command.action(async (...values: unknown[]) => {
      const active = values.at(-1);
      if (!isCommand(active)) {
        throw new Error("command context is unavailable");
      }
      await handler(active.opts(), active);
    });
    this.commands.push(contract);
    return command;
  }

  export(): { command_contract: string; commands: CommandContract[] } {
    return {
      command_contract: COMMAND_CONTRACT,
      commands: [...this.commands].sort((left, right) => left.path.localeCompare(right.path))
    };
  }
}

function leafName(path: string): string {
  return path.split(" ").at(-1) ?? path;
}

function isCommand(value: unknown): value is Command {
  return typeof value === "object" && value !== null && "opts" in value && typeof value.opts === "function";
}
