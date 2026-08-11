import type { Command } from "commander";
import { CliError } from "../../core/errors.js";
import { validateEndpoint } from "../../storage/profile-store.js";
import type { AppContext } from "../context.js";
import type { CommandRegistry } from "../manifest.js";

export function registerProfileCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const profiles = registry.group(parent, "profiles", "Manage local non-secret CLI profiles");

  registry.leaf(profiles, { path: "profiles get", description: "Show the selected profile", options: [] }, async (_options, command) => {
    const global = app.global(command);
    const current = await app.profiles.current(global.profile).catch(() => {
      throw new CliError({ code: "PROFILE_NOT_FOUND", message: "profile not found", exitCode: 2 });
    });
    app.success(global, "Profile", { name: current.name, profile: current.profile, config_path: app.profiles.filePath });
  });

  registry.leaf(profiles, { path: "profiles list", description: "List local profiles", options: [] }, async (_options, command) => {
    const global = app.global(command);
    const config = await app.profiles.load();
    app.success(global, "ProfileList", { current_profile: config.current_profile, profiles: config.profiles });
  });

  registry.leaf(profiles, {
    path: "profiles use",
    description: "Select the current profile",
    options: [{ flags: "--name <name>", description: "profile name" }]
  }, async (options, command) => {
    const global = app.global(command);
    const name = text(options.name);
    const config = await app.profiles.load();
    if (!config.profiles[name]) {
      throw new CliError({ code: "PROFILE_NOT_FOUND", message: "profile not found", exitCode: 2 });
    }
    config.current_profile = name;
    await app.profiles.save(config);
    app.success(global, "Profile", { current_profile: name });
  });

  registry.leaf(profiles, {
    path: "profiles set",
    description: "Update endpoint or OIDC client ID on the selected profile",
    options: [
      { flags: "--endpoint <url>", description: "GenAuth HTTPS origin" },
      { flags: "--client-id <id>", description: "GenAuth OIDC client ID" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const endpoint = text(options.endpoint);
    const clientId = text(options.clientId);
    if (endpoint === "" && clientId === "") {
      throw new CliError({ code: "INVALID_ARGUMENT", message: "at least one of endpoint or client-id is required", exitCode: 2 });
    }
    const current = await app.profiles.current(global.profile).catch(() => {
      throw new CliError({ code: "PROFILE_NOT_FOUND", message: "profile not found", exitCode: 2 });
    });
    const updated = { ...current.profile };
    if (endpoint !== "") {
      try {
        validateEndpoint(endpoint);
      } catch {
        throw new CliError({ code: "INVALID_ENDPOINT", message: "endpoint must be a GenAuth HTTPS origin", exitCode: 2 });
      }
      updated.endpoint = endpoint.replace(/\/$/u, "");
    }
    if (clientId !== "") {
      updated.client_id = clientId;
    }
    current.config.profiles[current.name] = updated;
    await app.profiles.save(current.config);
    app.success(global, "Profile", { name: current.name, profile: updated });
  });
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}
