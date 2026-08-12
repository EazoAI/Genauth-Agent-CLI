import type { Command, OptionValues } from "commander";
import { CliError } from "../../core/errors.js";
import { durationSeconds } from "../../core/duration.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import {
  isRecord,
  permissionIds,
  readObjectFile,
  stringList,
  uniqueStrings,
} from "../../core/input.js";
import { promptIfEmpty } from "../../core/prompt.js";
import type { AppContext, GlobalOptions } from "../context.js";
import { decodeResponseData } from "../context.js";
import type { CommandRegistry, OptionContract } from "../manifest.js";
import {
  compactQuery,
  confirmation,
  integerOption,
  requiredText,
  stringOptions,
  text,
} from "./common.js";

const agentIdOption: OptionContract = {
  flags: "--agent-id <id>",
  description: "Agent ID",
};

export function registerAgentCommands(
  parent: Command,
  registry: CommandRegistry,
  app: AppContext,
): void {
  const agents = registry.group(
    parent,
    "agents",
    "Create and manage company Agents",
  );

  registry.leaf(
    agents,
    {
      path: "agents create",
      description: "Create a company Agent and optionally its Capability draft",
      options: [
        {
          flags: "--identifier <identifier>",
          description: "stable Agent identifier",
        },
        { flags: "--name <name>", description: "stable Agent name" },
        { flags: "--display-name <name>", description: "Agent display name" },
        {
          flags: "--description <description>",
          description: "Agent description",
        },
        { flags: "--owner-user-id <id>", description: "Agent owner user ID" },
        {
          flags: "--application-id <id>",
          description: "GenAuth application ID",
        },
        {
          flags: "--audience <audience>",
          description:
            "compatibility override for the Application-derived audience",
          hidden: true,
        },
        {
          flags: "--permission-id <id>",
          description:
            "DataPolicy ID (repeatable); audience is inferred from Application",
          collect: true,
        },
        {
          flags: "--file <path>",
          description: "Agent YAML or JSON input file",
        },
        {
          flags: "--replace-permissions",
          description: "replace file permissions with command-line values",
        },
        {
          flags: "--append-permission",
          description: "append command-line permissions to file values",
        },
      ],
    },
    async (options, command) => createAgent(app, options, command),
  );

  registry.leaf(
    agents,
    {
      path: "agents list",
      description: "List Agents visible to the current profile",
      options: [
        { flags: "--status <status>", description: "Agent status" },
        { flags: "--search <text>", description: "search text" },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      await app.simple(
        global,
        {
          method: "GET",
          path: `${app.managementPrefix(current.profile)}/agents`,
          query: compactQuery({
            status: text(options.status),
            search: text(options.search),
          }),
        },
        "AgentList",
      );
    },
  );

  registry.leaf(
    agents,
    {
      path: "agents get",
      description: "Get Agent details",
      options: [agentIdOption],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      const agentId = requiredText(options.agentId, "agent-id");
      await app.simple(
        global,
        {
          method: "GET",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(agentId)}`,
        },
        "Agent",
      );
    },
  );

  registry.leaf(
    agents,
    {
      path: "agents update",
      description: "Update an Agent profile",
      options: [
        agentIdOption,
        { flags: "--display-name <name>", description: "Agent display name" },
        {
          flags: "--description <description>",
          description: "Agent description",
        },
        { flags: "--owner-user-id <id>", description: "Agent owner user ID" },
        {
          flags: "--version <number>",
          description: "Agent record version",
          defaultValue: "1",
        },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      const ownerUserId = text(options.ownerUserId);
      if (current.profile.login_type === "tenant_admin" && ownerUserId === "") {
        requiredText(ownerUserId, "owner-user-id");
      }
      const body: Record<string, unknown> = {
        display_name: requiredText(options.displayName, "display-name"),
        description: text(options.description),
        version: integerOption(options.version, "version", 1),
      };
      if (ownerUserId !== "") body.owner_user_id = ownerUserId;
      await app.simple(
        global,
        {
          method: "PATCH",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/profile`,
          body,
          headers: idempotencyHeaders(),
        },
        "Agent",
      );
    },
  );

  const capability = registry.group(
    agents,
    "capability",
    "Manage Agent Capability drafts",
  );
  registry.leaf(
    capability,
    {
      path: "agents capability update",
      description: "Create or update an Agent Capability draft",
      options: [
        agentIdOption,
        {
          flags: "--audience <audience>",
          description:
            "compatibility override for the Application-derived audience",
          hidden: true,
        },
        {
          flags: "--permission-id <id>",
          description:
            "DataPolicy ID (repeatable); audience is inferred from the Agent Application",
          collect: true,
        },
        {
          flags: "--version <number>",
          description: "expected draft record version",
          defaultValue: "0",
        },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      const policies = stringOptions(options.permissionId);
      if (policies.length === 0)
        throw invalid("at least one permission-id is required");
      const version = integerOption(options.version, "version", 0);
      if (version < 0) throw invalid("version cannot be negative");
      const agentId = requiredText(options.agentId, "agent-id");
      let audience = text(options.audience);
      if (audience === "") {
        const agentResult = await app.call(global, {
          method: "GET",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(agentId)}`,
        });
        const agent = decodeResponseData<Record<string, unknown>>(
          agentResult.data,
        );
        const applicationId = firstString(
          agent,
          "application_id",
          "applicationId",
        );
        if (applicationId === "") {
          throw invalidServerResponse(
            "Agent response does not include application_id",
            agentResult.requestId,
          );
        }
        audience = await resolveApplicationAudience(app, global, applicationId);
      }
      await app.simple(
        global,
        {
          method: "PUT",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(agentId)}/capability-grant/draft`,
          body: {
            audience,
            data_policy_ids: policies,
            permission_snapshot: {},
            version,
          },
          headers: idempotencyHeaders(),
        },
        "CapabilityGrant",
      );
    },
  );

  for (const action of ["submit", "withdraw"] as const) {
    registry.leaf(
      capability,
      {
        path: `agents capability ${action}`,
        description: `${action} an Agent Capability approval request`,
        options: [
          agentIdOption,
          {
            flags: "--version <number>",
            description: "Capability draft version",
            defaultValue: "1",
          },
          ...(action === "withdraw"
            ? [
                {
                  flags: "--reason <reason>",
                  description: "withdrawal reason",
                },
                { flags: "--yes", description: "confirm withdrawal" },
              ]
            : []),
        ],
      },
      async (options, command) => {
        const global = app.global(command);
        const current = await app.currentProfile(global);
        if (action === "withdraw")
          confirmation(options, "withdraw Agent approval request");
        const body: Record<string, unknown> = {
          version: integerOption(options.version, "version", 1),
        };
        if (action === "withdraw")
          body.reason = requiredText(options.reason, "reason");
        await app.simple(
          global,
          {
            method: "POST",
            path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/capability-grant/${action}`,
            body,
            headers: idempotencyHeaders(),
          },
          "ApprovalRequest",
        );
      },
    );
  }

  const agentPermissions = registry.group(
    agents,
    "permissions",
    "Reconcile Agent DataPolicy assignments",
  );
  registry.leaf(
    agentPermissions,
    {
      path: "agents permissions sync",
      description:
        "Idempotently reconcile the active Capability DataPolicies to the Agent Programmatic Account",
      options: [
        agentIdOption,
        {
          flags: "--yes",
          description: "confirm DataPolicy assignment reconciliation",
        },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      confirmation(options, "reconcile Agent DataPolicy assignments");
      await app.simple(
        global,
        {
          method: "POST",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(
            requiredText(options.agentId, "agent-id"),
          )}/data-permissions/sync`,
          body: {},
          headers: idempotencyHeaders(),
        },
        "CapabilityPermissionSync",
      );
    },
  );

  registry.leaf(
    agents,
    {
      path: "agents readiness",
      description: "Inspect Agent runtime readiness",
      options: [agentIdOption],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      await app.simple(
        global,
        {
          method: "GET",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/readiness`,
        },
        "AgentReadiness",
      );
    },
  );

  const lifecycle = registry.group(
    agents,
    "lifecycle",
    "Pause, resume, or archive an Agent",
  );
  for (const action of ["pause", "resume", "archive"] as const) {
    registry.leaf(
      lifecycle,
      {
        path: `agents lifecycle ${action}`,
        description: `${action} an Agent`,
        options: [
          agentIdOption,
          { flags: "--reason <reason>", description: "lifecycle reason" },
          {
            flags: "--version <number>",
            description: "Agent record version",
            defaultValue: "1",
          },
          { flags: "--yes", description: "confirm this operation" },
        ],
      },
      async (options, command) => {
        const global = app.global(command);
        const current = await app.currentProfile(global);
        if (current.profile.login_type === "user" && action !== "archive") {
          throw new CliError({
            code: "ADMIN_LOGIN_REQUIRED",
            message: "only a tenant administrator can pause or resume an Agent",
            exitCode: 2,
          });
        }
        if (action === "archive") confirmation(options, "archive Agent");
        await app.simple(
          global,
          {
            method: "POST",
            path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/${action}`,
            body: {
              version: integerOption(options.version, "version", 1),
              reason: requiredText(options.reason, "reason"),
            },
            headers: idempotencyHeaders(),
          },
          "Agent",
        );
      },
    );
  }

  registerSettings(agents, registry, app);
}

async function createAgent(
  app: AppContext,
  options: OptionValues,
  command: Command,
): Promise<void> {
  const global = app.global(command);
  const current = await app.currentProfile(global);
  let identifier = text(options.identifier);
  const name = text(options.name);
  let displayName = text(options.displayName);
  let description = text(options.description);
  let ownerUserId = text(options.ownerUserId);
  let applicationId = text(options.applicationId);
  let audience = text(options.audience);
  let policies = stringOptions(options.permissionId);
  const cliPolicies = [...policies];
  const file = text(options.file);
  let filePolicies: string[] = [];
  if (file !== "") {
    const input = await readObjectFile(file);
    identifier ||= firstString(input, "identifier", "name");
    displayName ||= firstString(input, "display_name", "name");
    description ||= firstString(input, "description");
    ownerUserId ||= firstString(input, "owner_user_id");
    applicationId ||= firstString(input, "application_id");
    audience ||= firstString(input, "audience");
    filePolicies = stringList(input.permission_ids);
    if (filePolicies.length === 0) filePolicies = stringList(input.permissions);
    const capabilities = Array.isArray(input.capabilities)
      ? input.capabilities
      : [];
    const first = capabilities.find(isRecord);
    if (first) {
      audience ||= firstString(first, "audience");
      if (filePolicies.length === 0)
        filePolicies = stringList(first.permission_ids);
      if (filePolicies.length === 0)
        filePolicies = permissionIds(first.permissions);
    }
  }
  if (name !== "") {
    identifier = name;
    displayName ||= name;
  }
  if (filePolicies.length > 0 && cliPolicies.length > 0) {
    if (
      Boolean(options.replacePermissions) === Boolean(options.appendPermission)
    ) {
      throw new CliError({
        code: "AMBIGUOUS_PERMISSION_MERGE",
        message:
          "file and command-line permissions require exactly one merge option",
        exitCode: 2,
      });
    }
    policies = options.replacePermissions
      ? cliPolicies
      : uniqueStrings([...filePolicies, ...cliPolicies]);
  } else if (filePolicies.length > 0) {
    policies = filePolicies;
  }
  if (!global.nonInteractive && file === "") {
    identifier = await promptIfEmpty(
      app.io.input,
      app.io.error,
      "Agent identifier",
      identifier,
    );
    displayName = await promptIfEmpty(
      app.io.input,
      app.io.error,
      "Agent display name",
      displayName,
    );
    applicationId = await promptIfEmpty(
      app.io.input,
      app.io.error,
      "GenAuth application ID",
      applicationId,
    );
  }
  requiredText(identifier, "identifier");
  requiredText(displayName, "display-name");
  requiredText(applicationId, "application-id");
  if (current.profile.login_type === "tenant_admin")
    requiredText(ownerUserId, "owner-user-id");
  if (audience !== "" && policies.length === 0) {
    throw invalid("audience cannot be used without at least one permission-id");
  }
  if (audience === "" && policies.length > 0) {
    audience = await resolveApplicationAudience(app, global, applicationId);
  }
  const body: Record<string, unknown> = {
    identifier,
    display_name: displayName,
    description,
    application_id: applicationId,
    agent_type: "company",
  };
  if (ownerUserId !== "") body.owner_user_id = ownerUserId;
  const created = await app.call(global, {
    method: "POST",
    path: `${app.managementPrefix(current.profile)}/agents`,
    body,
    headers: idempotencyHeaders(),
  });
  const agent = decodeResponseData<{ id?: string; version?: number }>(
    created.data,
  );
  if (!agent.id) {
    throw new CliError({
      code: "INVALID_SERVER_RESPONSE",
      message: "Agent creation response is invalid",
      exitCode: 9,
      requestId: created.requestId,
    });
  }
  if (audience !== "" || policies.length > 0) {
    try {
      const grant = await app.call(global, {
        method: "PUT",
        path: `${app.managementPrefix(current.profile)}/agents/${escape(agent.id)}/capability-grant/draft`,
        body: {
          audience,
          data_policy_ids: policies,
          permission_snapshot: {},
          version: 0,
        },
        headers: idempotencyHeaders(),
      });
      app.success(
        global,
        "AgentWithCapabilityDraft",
        { agent: created.data, capability_grant: grant.data },
        grant.requestId,
      );
      return;
    } catch (error) {
      const cause =
        error instanceof CliError ? error : invalid("Capability draft failed");
      throw new CliError({
        code: "PARTIAL_AGENT_CREATE",
        message:
          "Agent was created, but its Capability draft could not be saved",
        exitCode: cause.exitCode,
        requestId: cause.requestId,
        remediation: {
          agent_id: agent.id,
          cause_code: cause.code,
          next_command: `genauth-agent agents capability update --agent-id ${agent.id} --permission-id <policy-id> --version 0`,
        },
      });
    }
  }
  app.success(global, "Agent", created.data, created.requestId);
}

function registerSettings(
  agents: Command,
  registry: CommandRegistry,
  app: AppContext,
): void {
  const settings = registry.group(
    agents,
    "settings",
    "Manage Agent-level authorization and Token settings",
  );
  registry.leaf(
    settings,
    {
      path: "agents settings get",
      description: "Get active and draft Agent settings",
      options: [agentIdOption],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      await app.simple(
        global,
        {
          method: "GET",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/settings`,
        },
        "AgentSettings",
      );
    },
  );
  registry.leaf(
    settings,
    {
      path: "agents settings update",
      description: "Create or update an Agent settings draft",
      options: [
        agentIdOption,
        {
          flags: "--file <path>",
          description: "complete settings YAML or JSON file",
        },
        {
          flags: "--authorization-mode <mode>",
          description: "explicit-only or silent-if-allowed",
        },
        {
          flags: "--token-ttl <duration>",
          description: "Agent access Token TTL",
        },
        {
          flags: "--max-user-grant-ttl <duration>",
          description: "maximum UserGrant TTL",
        },
        {
          flags: "--redirect-uri <uri>",
          description: "allowed authorization redirect URI",
          collect: true,
        },
        {
          flags: "--require-realtime-decision",
          description: "require a current GenAuth decision",
          defaultValue: true,
        },
        {
          flags: "--credential-ttl <duration>",
          description: "Agent Credential TTL",
        },
        {
          flags: "--rotation-overlap <duration>",
          description: "Credential rotation overlap",
        },
        {
          flags: "--version <number>",
          description: "expected existing draft record version",
          defaultValue: "0",
        },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      const file = text(options.file);
      let body: Record<string, unknown>;
      if (file !== "") {
        const changed = [
          "authorizationMode",
          "tokenTtl",
          "maxUserGrantTtl",
          "redirectUri",
          "credentialTtl",
          "rotationOverlap",
        ].some((name) => command.getOptionValueSource(name) === "cli");
        if (changed)
          throw new CliError({
            code: "AMBIGUOUS_SETTINGS_INPUT",
            message: "--file is exclusive with Agent settings value flags",
            exitCode: 2,
          });
        body = await readObjectFile(file);
      } else {
        const mode = text(options.authorizationMode)
          .replaceAll("-", "_")
          .toUpperCase();
        if (mode !== "EXPLICIT_ONLY" && mode !== "SILENT_IF_ALLOWED")
          throw invalid(
            "authorization-mode must be explicit-only or silent-if-allowed",
          );
        const tokenTtl = positiveDuration(options.tokenTtl, "token-ttl");
        const maxGrantTtl = positiveDuration(
          options.maxUserGrantTtl,
          "max-user-grant-ttl",
        );
        const overlap = optionalDuration(options.rotationOverlap);
        body = {
          expected_record_version: integerOption(options.version, "version", 0),
          authorization_mode: mode,
          token_ttl_seconds: tokenTtl,
          max_user_grant_ttl_seconds: maxGrantTtl,
          redirect_uris: stringOptions(options.redirectUri),
          require_realtime_decision: Boolean(options.requireRealtimeDecision),
          rotation_overlap_seconds: overlap,
        };
        const credentialTtl = optionalDuration(options.credentialTtl);
        if (credentialTtl > 0) body.credential_ttl_seconds = credentialTtl;
      }
      await app.simple(
        global,
        {
          method: "PUT",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/settings/draft`,
          body,
          headers: idempotencyHeaders(),
        },
        "AgentSettings",
      );
    },
  );
  registry.leaf(
    settings,
    {
      path: "agents settings submit",
      description: "Submit an Agent settings draft for approval",
      options: [agentIdOption],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      await app.simple(
        global,
        {
          method: "POST",
          path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/settings/submit`,
          headers: idempotencyHeaders(),
        },
        "ApprovalRequest",
      );
    },
  );
}

function firstString(
  value: Record<string, unknown>,
  ...keys: string[]
): string {
  for (const key of keys) {
    const item = value[key];
    if (typeof item === "string" && item.trim() !== "") return item.trim();
  }
  return "";
}

async function resolveApplicationAudience(
  app: AppContext,
  global: GlobalOptions,
  applicationId: string,
): Promise<string> {
  const result = await app.call(global, {
    method: "GET",
    path: "/api/v3/get-application-simple-info",
    query: { appId: applicationId },
  });
  const application = decodeResponseData<Record<string, unknown>>(result.data);
  const audience = firstString(
    application,
    "appIdentifier",
    "app_identifier",
    "identifier",
  );
  if (audience === "") {
    throw invalidServerResponse(
      "Application response does not include appIdentifier",
      result.requestId,
    );
  }
  return audience;
}

function invalidServerResponse(message: string, requestId: string): CliError {
  return new CliError({
    code: "INVALID_SERVER_RESPONSE",
    message,
    exitCode: 9,
    requestId,
  });
}

function positiveDuration(value: unknown, name: string): number {
  const raw = requiredText(value, name);
  try {
    return durationSeconds(raw);
  } catch {
    throw invalid(`${name} must be a positive duration`);
  }
}

function optionalDuration(value: unknown): number {
  const raw = text(value);
  if (raw === "") return 0;
  try {
    return durationSeconds(raw);
  } catch {
    throw invalid("duration must be positive");
  }
}

function invalid(message: string): CliError {
  return new CliError({ code: "INVALID_ARGUMENT", message, exitCode: 2 });
}

function escape(value: string): string {
  return encodeURIComponent(value);
}
