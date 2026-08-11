import type { Command } from "commander";
import { CliError } from "../../core/errors.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import type { AppContext } from "../context.js";
import type { CommandRegistry, OptionContract } from "../manifest.js";
import { compactQuery, confirmation, integerOption, requiredText, text } from "./common.js";

const approvalOptions: OptionContract[] = [
  { flags: "--approval-id <id>", description: "approval request ID" },
  { flags: "--settings", description: "operate on Agent settings approval" }
];

export function registerApprovalCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const approvals = registry.group(parent, "approvals", "Review Agent Capability and settings approvals");
  registry.leaf(approvals, {
    path: "approvals list",
    description: "List approval requests",
    options: [
      { flags: "--status <status>", description: "approval status", defaultValue: "pending" },
      { flags: "--settings", description: "list Agent settings approvals" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const current = await requireAdmin(app, global);
    const resource = options.settings ? "settings-approvals" : "approvals";
    await app.simple(global, {
      method: "GET",
      path: `${app.managementPrefix(current.profile)}/${resource}`,
      query: compactQuery({ status: text(options.status) || "pending" })
    }, "ApprovalList");
  });
  registry.leaf(approvals, {
    path: "approvals get",
    description: "Get an approval request",
    options: approvalOptions
  }, async (options, command) => {
    const global = app.global(command);
    const current = await requireAdmin(app, global);
    const resource = options.settings ? "settings-approvals" : "approvals";
    await app.simple(global, {
      method: "GET",
      path: `${app.managementPrefix(current.profile)}/${resource}/${encodeURIComponent(requiredText(options.approvalId, "approval-id"))}`
    }, "ApprovalRequest");
  });
  for (const action of ["approve", "reject"] as const) {
    registry.leaf(approvals, {
      path: `approvals ${action}`,
      description: `${action} an approval request`,
      options: [
        ...approvalOptions,
        { flags: "--version <number>", description: "approval version", defaultValue: "1" },
        { flags: "--reason <reason>", description: "decision reason" },
        { flags: "--yes", description: "confirm this decision" }
      ]
    }, async (options, command) => {
      const global = app.global(command);
      const current = await requireAdmin(app, global);
      confirmation(options, `${action} approval`);
      const resource = options.settings ? "settings-approvals" : "approvals";
      await app.simple(global, {
        method: "POST",
        path: `${app.managementPrefix(current.profile)}/${resource}/${encodeURIComponent(requiredText(options.approvalId, "approval-id"))}/${action}`,
        body: { version: integerOption(options.version, "version", 1), reason: text(options.reason) },
        headers: idempotencyHeaders()
      }, "ApprovalRequest");
    });
  }
}

async function requireAdmin(app: AppContext, global: ReturnType<AppContext["global"]>): Promise<Awaited<ReturnType<AppContext["currentProfile"]>>> {
  const current = await app.currentProfile(global);
  if (current.profile.login_type === "user") {
    throw new CliError({ code: "ADMIN_LOGIN_REQUIRED", message: "approval operations require a tenant administrator profile", exitCode: 2 });
  }
  return current;
}
