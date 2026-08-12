import type { Command, OptionValues } from "commander";
import { CliError } from "../../core/errors.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import { isRecord, readObjectFile, stringList } from "../../core/input.js";
import type { AppContext } from "../context.js";
import { decodeResponseData } from "../context.js";
import type { CommandRegistry } from "../manifest.js";
import { confirmation } from "./common.js";

export function registerPermissionCommands(
  parent: Command,
  registry: CommandRegistry,
  app: AppContext,
): void {
  const permissions = registry.group(
    parent,
    "permissions",
    "Inspect GenAuth DataPolicy permissions",
  );

  registry.leaf(
    permissions,
    {
      path: "permissions list",
      description: "List permissions available in the selected user pool",
      options: [
        {
          flags: "--page-size <number>",
          description: "page size",
          defaultValue: "20",
        },
        {
          flags: "--audience <audience>",
          description: "ResourceServer audience",
        },
        { flags: "--action <action>", description: "permission action" },
        { flags: "--keyword <keyword>", description: "search keyword" },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const current = await app.currentProfile(global);
      const query = compactQuery({
        audience: text(options.audience),
        action: text(options.action),
        keyword: text(options.keyword),
        limit: text(options.pageSize) || "20",
      });
      await app.simple(
        global,
        {
          method: "GET",
          path: `${app.managementPrefix(current.profile)}/permission-catalog`,
          query,
        },
        "PermissionList",
      );
    },
  );

  registry.leaf(
    permissions,
    {
      path: "permissions get",
      description: "Get a permission by DataPolicy ID",
      options: [
        { flags: "--permission-id <id>", description: "DataPolicy ID" },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const permissionId = requiredText(options.permissionId, "permission-id");
      await app.simple(
        global,
        {
          method: "GET",
          path: `/api/v3/agent-identity/permission-catalog/${encodeURIComponent(permissionId)}`,
        },
        "Permission",
      );
    },
  );

  registry.leaf(
    permissions,
    {
      path: "permissions validate",
      description: "Validate selected DataPolicy IDs for an audience",
      options: [
        {
          flags: "--permission-id <id>",
          description: "DataPolicy ID (repeatable)",
          collect: true,
        },
        {
          flags: "--audience <audience>",
          description: "ResourceServer audience",
        },
      ],
    },
    async (options, command) => {
      const global = app.global(command);
      const permissionIds = list(options.permissionId);
      if (permissionIds.length === 0) {
        throw new CliError({
          code: "INVALID_ARGUMENT",
          message: "at least one permission-id is required",
          exitCode: 2,
        });
      }
      const audience = requiredText(options.audience, "audience");
      await app.simple(
        global,
        {
          method: "POST",
          path: "/api/v3/agent-identity/permissions/validate",
          body: { permission_ids: permissionIds, audience },
          headers: idempotencyHeaders(),
        },
        "PermissionValidation",
      );
    },
  );

  registry.leaf(
    permissions,
    {
      path: "permissions apply",
      description: "Idempotently apply a DataPolicy catalog manifest",
      options: [
        {
          flags: "--file <path>",
          description: "permission catalog YAML or JSON manifest",
        },
        { flags: "--yes", description: "confirm permission catalog changes" },
      ],
    },
    async (options, command) => applyPermissionCatalog(app, options, command),
  );

  registry.leaf(
    permissions,
    {
      path: "permissions authorize-user",
      description: "Idempotently authorize DataPolicies to one user",
      options: [
        {
          flags: "--permission-id <id>",
          description: "DataPolicy ID (repeatable)",
          collect: true,
        },
        { flags: "--user-id <id>", description: "target user ID" },
        {
          flags: "--user-name <name>",
          description: "target user display name",
        },
        { flags: "--yes", description: "confirm DataPolicy authorization" },
      ],
    },
    async (options, command) => authorizePoliciesToUser(app, options, command),
  );
}

async function authorizePoliciesToUser(
  app: AppContext,
  options: OptionValues,
  command: Command,
): Promise<void> {
  const global = app.global(command);
  const current = await app.currentProfile(global);
  if (current.profile.login_type !== "tenant_admin") {
    throw new CliError({
      code: "ADMIN_LOGIN_REQUIRED",
      message: "only a tenant administrator can authorize DataPolicies",
      exitCode: 4,
    });
  }
  confirmation(options, "authorize DataPolicies to a user");
  const permissionIds = list(options.permissionId);
  if (permissionIds.length === 0) {
    throw new CliError({
      code: "INVALID_ARGUMENT",
      message: "at least one permission-id is required",
      exitCode: 2,
    });
  }
  const userId = requiredText(options.userId, "user-id");
  const userName = requiredText(options.userName, "user-name");
  const missing: string[] = [];
  let requestId = "";
  for (const permissionId of permissionIds) {
    const result = await app.call(global, {
      method: "GET",
      path: "/api/v3/list-data-policy-targets",
      query: {
        policyId: permissionId,
        page: 1,
        limit: 50,
        targetType: "USER",
      },
    });
    requestId = result.requestId;
    const data = decodeResponseData<Record<string, unknown>>(result.data);
    const targets = Array.isArray(data.list) ? data.list : [];
    if (
      !targets.some(
        (target) =>
          isRecord(target) &&
          (target.targetIdentifier === userId || target.id === userId) &&
          String(target.targetType || target.type || "").toUpperCase() ===
            "USER",
      )
    ) {
      missing.push(permissionId);
    }
  }
  if (missing.length > 0) {
    const result = await app.call(global, {
      method: "POST",
      path: "/api/v3/authorize-data-policies",
      body: {
        policyIds: missing,
        targetList: [{ id: userId, type: "USER", name: userName }],
      },
      headers: idempotencyHeaders(),
    });
    requestId = result.requestId;
  }
  app.success(
    global,
    "PermissionAuthorization",
    {
      target: { id: userId, type: "USER", name: userName },
      permission_ids: permissionIds,
      newly_authorized_permission_ids: missing,
      status: missing.length > 0 ? "authorized" : "unchanged",
    },
    requestId,
  );
}

interface CatalogResource {
  code: string;
  name: string;
  description: string;
  actions: string[];
}

interface CatalogPolicy {
  key: string;
  name: string;
  description: string;
  permissions: string[];
}

async function applyPermissionCatalog(
  app: AppContext,
  options: OptionValues,
  command: Command,
): Promise<void> {
  const global = app.global(command);
  const current = await app.currentProfile(global);
  if (current.profile.login_type !== "tenant_admin") {
    throw new CliError({
      code: "ADMIN_LOGIN_REQUIRED",
      message: "only a tenant administrator can apply a permission catalog",
      exitCode: 4,
    });
  }
  confirmation(options, "apply DataPolicy catalog changes");
  const manifest = await readObjectFile(requiredText(options.file, "file"));
  const parsed = parseCatalog(manifest);
  const requestIds: string[] = [];

  const namespaceCheck = await app.call(global, {
    method: "POST",
    path: "/api/v3/check-permission-namespace-exists",
    body: { code: parsed.namespace.code },
    headers: idempotencyHeaders(),
  });
  requestIds.push(namespaceCheck.requestId);
  const namespaceAvailability = decodeResponseData<Record<string, unknown>>(
    namespaceCheck.data,
  );
  const namespaceCreated = namespaceAvailability.isValid === true;
  if (namespaceCreated) {
    const created = await app.call(global, {
      method: "POST",
      path: "/api/v3/create-permission-namespace",
      body: parsed.namespace,
      headers: idempotencyHeaders(),
    });
    requestIds.push(created.requestId);
  }

  const resources: Array<{
    resource_code: string;
    status: "created" | "reconciled" | "reused";
  }> = [];
  for (const resource of parsed.resources) {
    const availabilityResult = await app.call(global, {
      method: "GET",
      path: "/api/v3/check-data-resource-exists",
      query: {
        namespaceCode: parsed.namespace.code,
        resourceCode: resource.code,
      },
    });
    requestIds.push(availabilityResult.requestId);
    const availability = decodeResponseData<Record<string, unknown>>(
      availabilityResult.data,
    );
    const body = {
      namespaceCode: parsed.namespace.code,
      resourceName: resource.name,
      resourceCode: resource.code,
      struct: resource.code,
      actions: resource.actions,
      description: resource.description,
    };
    if (availability.isValid === true) {
      const created = await app.call(global, {
        method: "POST",
        path: "/api/v3/create-string-data-resource",
        body,
        headers: idempotencyHeaders(),
      });
      requestIds.push(created.requestId);
      resources.push({ resource_code: resource.code, status: "created" });
      continue;
    }
    const existingResult = await app.call(global, {
      method: "GET",
      path: "/api/v3/get-data-resource",
      query: {
        namespaceCode: parsed.namespace.code,
        resourceCode: resource.code,
      },
    });
    requestIds.push(existingResult.requestId);
    const existing = decodeResponseData<Record<string, unknown>>(
      existingResult.data,
    );
    if (!sameStrings(stringList(existing.actions), resource.actions)) {
      const updated = await app.call(global, {
        method: "POST",
        path: "/api/v3/update-data-resource",
        body,
        headers: idempotencyHeaders(),
      });
      requestIds.push(updated.requestId);
      resources.push({ resource_code: resource.code, status: "reconciled" });
    } else {
      resources.push({ resource_code: resource.code, status: "reused" });
    }
  }

  const policies: Array<{
    key: string;
    policy_id: string;
    name: string;
    status: "created" | "reconciled";
  }> = [];
  for (const policy of parsed.policies) {
    const availabilityResult = await app.call(global, {
      method: "GET",
      path: "/api/v3/check-data-policy-exists",
      query: { policyName: policy.name },
    });
    requestIds.push(availabilityResult.requestId);
    const availability = decodeResponseData<Record<string, unknown>>(
      availabilityResult.data,
    );
    const statementList = [
      { effect: "ALLOW", permissions: policy.permissions },
    ];
    if (availability.isValid === true) {
      const createdResult = await app.call(global, {
        method: "POST",
        path: "/api/v3/create-data-policy",
        body: {
          policyName: policy.name,
          description: policy.description,
          statementList,
        },
        headers: idempotencyHeaders(),
      });
      requestIds.push(createdResult.requestId);
      const created = decodeResponseData<Record<string, unknown>>(
        createdResult.data,
      );
      policies.push({
        key: policy.key,
        policy_id: requiredResponseText(
          created.policyId,
          "policyId",
          createdResult.requestId,
        ),
        name: policy.name,
        status: "created",
      });
      continue;
    }
    const listResult = await app.call(global, {
      method: "GET",
      path: "/api/v3/list-data-policies",
      query: { page: 1, limit: 50, query: policy.name },
    });
    requestIds.push(listResult.requestId);
    const list = decodeResponseData<Record<string, unknown>>(listResult.data);
    const candidates = Array.isArray(list.list)
      ? list.list
      : Array.isArray(list.data)
        ? list.data
        : [];
    const existing = candidates.find(
      (candidate) =>
        isRecord(candidate) && candidate.policyName === policy.name,
    );
    if (!isRecord(existing)) {
      throw new CliError({
        code: "INVALID_SERVER_RESPONSE",
        message: `policy ${policy.name} exists but exact details were not returned`,
        requestId: listResult.requestId,
        exitCode: 9,
      });
    }
    const policyId = requiredResponseText(
      existing.policyId,
      "policyId",
      listResult.requestId,
    );
    const updated = await app.call(global, {
      method: "POST",
      path: "/api/v3/update-data-policy",
      body: {
        policyId,
        policyName: policy.name,
        description: policy.description,
        statementList,
      },
      headers: idempotencyHeaders(),
    });
    requestIds.push(updated.requestId);
    policies.push({
      key: policy.key,
      policy_id: policyId,
      name: policy.name,
      status: "reconciled",
    });
  }

  app.success(
    global,
    "PermissionCatalogApply",
    {
      namespace_code: parsed.namespace.code,
      namespace_status: namespaceCreated ? "created" : "reused",
      resources,
      policies,
    },
    requestIds.at(-1) ?? "",
  );
}

function parseCatalog(value: Record<string, unknown>): {
  namespace: { code: string; name: string; description: string };
  resources: CatalogResource[];
  policies: CatalogPolicy[];
} {
  if (
    value.api_version !== "genauth-agent.permissions/v1" ||
    !isRecord(value.namespace)
  ) {
    throw invalidCatalog(
      "api_version must be genauth-agent.permissions/v1 and namespace is required",
    );
  }
  const namespace = {
    code: manifestText(
      value.namespace.code,
      "namespace.code",
      /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u,
    ),
    name: manifestText(value.namespace.name, "namespace.name"),
    description: optionalManifestText(value.namespace.description),
  };
  if (
    !Array.isArray(value.resources) ||
    value.resources.length === 0 ||
    value.resources.length > 50
  ) {
    throw invalidCatalog("resources must contain between 1 and 50 entries");
  }
  const resources = value.resources.map((raw, index): CatalogResource => {
    if (!isRecord(raw))
      throw invalidCatalog(`resources[${index}] must be an object`);
    const actions = stringList(raw.actions);
    if (
      actions.length === 0 ||
      actions.length > 50 ||
      actions.some(
        (action) => !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/u.test(action),
      )
    ) {
      throw invalidCatalog(`resources[${index}].actions is invalid`);
    }
    return {
      code: manifestText(
        raw.code,
        `resources[${index}].code`,
        /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u,
      ),
      name: manifestText(raw.name, `resources[${index}].name`),
      description: optionalManifestText(raw.description),
      actions,
    };
  });
  if (
    !Array.isArray(value.policies) ||
    value.policies.length === 0 ||
    value.policies.length > 50
  ) {
    throw invalidCatalog("policies must contain between 1 and 50 entries");
  }
  const policies = value.policies.map((raw, index): CatalogPolicy => {
    if (!isRecord(raw))
      throw invalidCatalog(`policies[${index}] must be an object`);
    const permissions = stringList(raw.permissions);
    if (
      permissions.length === 0 ||
      permissions.length > 100 ||
      permissions.some(
        (permission) => !permission.startsWith(`${namespace.code}/`),
      )
    ) {
      throw invalidCatalog(
        `policies[${index}].permissions must stay inside namespace ${namespace.code}`,
      );
    }
    return {
      key: manifestText(
        raw.key,
        `policies[${index}].key`,
        /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u,
      ),
      name: manifestText(raw.name, `policies[${index}].name`),
      description: optionalManifestText(raw.description),
      permissions,
    };
  });
  if (
    new Set(resources.map((resource) => resource.code)).size !==
      resources.length ||
    new Set(policies.map((policy) => policy.key)).size !== policies.length
  ) {
    throw invalidCatalog("resource codes and policy keys must be unique");
  }
  return { namespace, resources, policies };
}

function manifestText(value: unknown, name: string, pattern?: RegExp): string {
  const result = text(value);
  if (
    result === "" ||
    result.length > 256 ||
    (pattern && !pattern.test(result))
  )
    throw invalidCatalog(`${name} is invalid`);
  return result;
}

function optionalManifestText(value: unknown): string {
  const result = text(value);
  if (result.length > 1024)
    throw invalidCatalog("description exceeds 1024 characters");
  return result;
}

function invalidCatalog(message: string): CliError {
  return new CliError({
    code: "INVALID_PERMISSION_CATALOG",
    message,
    exitCode: 2,
  });
}

function requiredResponseText(
  value: unknown,
  name: string,
  requestId: string,
): string {
  const result = text(value);
  if (result === "")
    throw new CliError({
      code: "INVALID_SERVER_RESPONSE",
      message: `${name} is missing`,
      requestId,
      exitCode: 9,
    });
  return result;
}

function sameStrings(left: string[], right: string[]): boolean {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
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
    throw new CliError({
      code: "INVALID_ARGUMENT",
      message: `${name} is required`,
      exitCode: 2,
    });
  }
  return result;
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function list(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is string =>
          typeof item === "string" && item.trim() !== "",
      )
    : [];
}
