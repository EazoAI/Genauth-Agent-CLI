import type { Command } from "commander";
import { CliError } from "../../core/errors.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import type { AppContext } from "../context.js";
import type { CommandRegistry } from "../manifest.js";

export function registerPermissionCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const permissions = registry.group(parent, "permissions", "Inspect GenAuth DataPolicy permissions");

  registry.leaf(permissions, {
    path: "permissions list",
    description: "List permissions available in the selected user pool",
    options: [
      { flags: "--page-size <number>", description: "page size", defaultValue: "20" },
      { flags: "--audience <audience>", description: "ResourceServer audience" },
      { flags: "--action <action>", description: "permission action" },
      { flags: "--keyword <keyword>", description: "search keyword" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    const query = compactQuery({
      audience: text(options.audience),
      action: text(options.action),
      keyword: text(options.keyword),
      limit: text(options.pageSize) || "20"
    });
    await app.simple(global, {
      method: "GET",
      path: `${app.managementPrefix(current.profile)}/permission-catalog`,
      query
    }, "PermissionList");
  });

  registry.leaf(permissions, {
    path: "permissions get",
    description: "Get a permission by DataPolicy ID",
    options: [{ flags: "--permission-id <id>", description: "DataPolicy ID" }]
  }, async (options, command) => {
    const global = app.global(command);
    const permissionId = requiredText(options.permissionId, "permission-id");
    await app.simple(global, {
      method: "GET",
      path: `/api/v3/agent-identity/permission-catalog/${encodeURIComponent(permissionId)}`
    }, "Permission");
  });

  registry.leaf(permissions, {
    path: "permissions validate",
    description: "Validate selected DataPolicy IDs for an audience",
    options: [
      { flags: "--permission-id <id>", description: "DataPolicy ID (repeatable)", collect: true },
      { flags: "--audience <audience>", description: "ResourceServer audience" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const permissionIds = list(options.permissionId);
    if (permissionIds.length === 0) {
      throw new CliError({ code: "INVALID_ARGUMENT", message: "at least one permission-id is required", exitCode: 2 });
    }
    const audience = requiredText(options.audience, "audience");
    await app.simple(global, {
      method: "POST",
      path: "/api/v3/agent-identity/permissions/validate",
      body: { permission_ids: permissionIds, audience },
      headers: idempotencyHeaders()
    }, "PermissionValidation");
  });
}

function compactQuery(values: Record<string, string>): URLSearchParams {
  const result = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== "") {
      result.set(key, value);
    }
  }
  return result;
}

function requiredText(value: unknown, name: string): string {
  const result = text(value);
  if (result === "") {
    throw new CliError({ code: "INVALID_ARGUMENT", message: `${name} is required`, exitCode: 2 });
  }
  return result;
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim() !== "") : [];
}
