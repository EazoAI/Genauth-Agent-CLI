import type { Command } from "commander";
import { OAuthClient, type OAuthToken } from "../../auth/oauth.js";
import { discoverLoginConfig } from "../../auth/login-config.js";
import { tokenSubject } from "../../core/jwt.js";
import { CliError } from "../../core/errors.js";
import { readLimitedStdin } from "../../core/input.js";
import { ApiClient } from "../../http/client.js";
import { InvalidCaFileError, InvalidProxyError } from "../../http/errors.js";
import { validateProfileName, type Profile } from "../../storage/profile-store.js";
import type { AppContext, GlobalOptions } from "../context.js";
import { validateCliEndpoint } from "../context.js";
import type { CommandRegistry } from "../manifest.js";
import {
  decodeManageableUserPools,
  selectedUserPoolFields,
  userPoolLabel,
  type ManageableUserPool
} from "../user-pools.js";

export function registerAuthCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const auth = registry.group(parent, "auth", "Authenticate and select the current user pool");

  registry.leaf(auth, {
    path: "auth login",
    description: "Login as a tenant administrator",
    options: [
      { flags: "--user-pool-id <id>", description: "optional manageable user pool to select after login" },
      { flags: "--profile-name <name>", description: "profile to create", defaultValue: "default" },
      { flags: "--session-token-stdin", description: "read an existing GenAuth session token from stdin" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const profileName = text(options.profileName) || "default";
    const userPoolId = text(options.userPoolId);
    try {
      validateProfileName(profileName);
    } catch {
      throw new CliError({ code: "INVALID_ARGUMENT", message: "profile is required", exitCode: 2 });
    }
    if (global.endpoint === "") {
      throw new CliError({ code: "INVALID_ENDPOINT", message: "endpoint must be provided for login", exitCode: 2 });
    }
    validateCliEndpoint(global.endpoint, global.allowInsecureLocalhost);
    await app.probeSecretStore();
    const secretRef = `keychain://genauth-agent/session/${profileName}`;
    let transport: ApiClient;
    try {
      transport = await ApiClient.create({
        endpoint: global.endpoint,
        timeoutMs: global.timeoutMs,
        proxyUrl: global.proxy,
        caFile: global.caFile,
        ...(app.dispatcher === undefined ? {} : { dispatcher: app.dispatcher })
      });
    } catch (error) {
      if (error instanceof InvalidCaFileError) throw new CliError({ code: "INVALID_CA_FILE", message: error.message, exitCode: 2 });
      if (error instanceof InvalidProxyError) throw new CliError({ code: "INVALID_PROXY", message: error.message, exitCode: 2 });
      throw error;
    }
    const discovered = await discoverLoginConfig(transport);
    const clientId = discovered.clientId;
    const loginConfigRequestId = discovered.requestId;
    let token: OAuthToken;
    if (options.sessionTokenStdin) {
      const value = await readLimitedStdin(app.io.input);
      if (value === "") {
        throw new CliError({ code: "INVALID_SESSION", message: "a session token is required on stdin", exitCode: 2 });
      }
      token = { access_token: value };
    } else {
      if (global.nonInteractive) {
        throw new CliError({
          code: "LOGIN_INTERACTION_REQUIRED",
          message: "browser login cannot run in non-interactive mode; use session-token-stdin",
          exitCode: 2
        });
      }
      const controller = AbortSignal.timeout(5 * 60_000);
      try {
        token = await new OAuthClient({
          endpoint: global.endpoint,
          clientId,
          dispatcher: transport.dispatcher,
          timeoutMs: global.timeoutMs
        }).login({
          noBrowser: global.noBrowser,
          signal: controller,
          notify: url => {
            if (!global.quiet) {
              app.io.error.write(`Open this GenAuth login URL:\n${url}\n`);
            }
          }
        });
      } catch (error) {
        throw new CliError({ code: "LOGIN_FAILED", message: error instanceof Error ? error.message : "login failed", exitCode: 3 });
      }
    }
    const profile: Profile = {
      endpoint: global.endpoint,
      ...(clientId === "" ? {} : { client_id: clientId }),
      login_type: "tenant_admin",
      ...(tokenSubject(token.access_token) === "" ? {} : { subject_id: tokenSubject(token.access_token) }),
      selected_user_pool_id: userPoolId,
      secret_ref: secretRef
    };
    let requestId = loginConfigRequestId;
    const selected = await selectAdminUserPool(global, token.access_token, userPoolId, transport);
    profile.selected_user_pool_id = selected.userPoolId;
    requestId = selected.requestId;
    await app.secrets.set(secretRef, JSON.stringify(token));
    const config = await app.profiles.load();
    config.profiles[profileName] = profile;
    config.current_profile = profileName;
    try {
      await app.profiles.save(config);
    } catch (error) {
      await app.secrets.delete(secretRef).catch(() => undefined);
      throw error;
    }
    app.success(global, "LoginSession", {
      profile: profileName,
      login_type: profile.login_type,
      subject_id: profile.subject_id ?? "",
      ...selectedUserPoolFields(profile.selected_user_pool_id, selected.userPool),
      secret_ref: secretRef
    }, requestId);
  });

  registry.leaf(auth, {
    path: "auth list-user-pools",
    description: "List manageable user pools with names and IDs",
    options: []
  }, async (_options, command) => {
    const global = app.global(command);
    const loaded = await app.loadClient(global);
    if (loaded.profile.login_type !== "tenant_admin") {
      throw new CliError({ code: "ADMIN_LOGIN_REQUIRED", message: "listing manageable user pools requires a tenant administrator profile", exitCode: 2 });
    }
    const result = await app.call(global, { method: "GET", path: "/api/v3/agent-identity/admin/user-pools" });
    const pools = decodeManageableUserPools(result.data);
    app.success(global, "UserPoolList", {
      selected_user_pool_id: loaded.profile.selected_user_pool_id,
      list: pools.map(pool => ({ ...pool, selected: pool.id === loaded.profile.selected_user_pool_id })),
      total_count: pools.length
    }, result.requestId);
  });

  registry.leaf(auth, {
    path: "auth status",
    description: "Show the current authenticated context",
    options: []
  }, async (_options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    const path = current.profile.login_type === "tenant_admin"
      ? "/api/v3/agent-identity/admin/context"
      : "/api/v3/agent-identity/me";
    const result = await app.call(global, { method: "GET", path });
    let selectedPool: ManageableUserPool | undefined;
    if (current.profile.login_type === "tenant_admin") {
      const poolsResult = await app.call(global, { method: "GET", path: "/api/v3/agent-identity/admin/user-pools" });
      selectedPool = decodeManageableUserPools(poolsResult.data)
        .find(pool => pool.id === current.profile.selected_user_pool_id);
    }
    app.success(global, "AuthStatus", {
      authenticated: true,
      profile: current.name,
      login_type: current.profile.login_type,
      subject_id: current.profile.subject_id ?? "",
      ...selectedUserPoolFields(current.profile.selected_user_pool_id, selectedPool),
      server_context: result.data
    }, result.requestId);
  });

  registry.leaf(auth, {
    path: "auth refresh",
    description: "Refresh the current login session",
    options: []
  }, async (_options, command) => {
    const global = app.global(command);
    const loaded = await app.loadClient(global);
    if (!loaded.token.refresh_token || !loaded.profile.client_id) {
      throw new CliError({ code: "SESSION_REFRESH_FAILED", message: "client ID and refresh token are required", exitCode: 3 });
    }
    await app.probeSecretStore();
    try {
      const refreshed = await new OAuthClient({
        endpoint: loaded.profile.endpoint,
        clientId: loaded.profile.client_id,
        dispatcher: loaded.client.dispatcher,
        timeoutMs: global.timeoutMs
      }).refresh(loaded.token.refresh_token);
      await app.secrets.set(loaded.profile.secret_ref, JSON.stringify(refreshed));
    } catch (error) {
      throw new CliError({ code: "SESSION_REFRESH_FAILED", message: error instanceof Error ? error.message : "session refresh failed", exitCode: 3 });
    }
    app.success(global, "LoginSession", {
      profile: loaded.name,
      refreshed: true,
      selected_user_pool_id: loaded.profile.selected_user_pool_id
    });
  });

  registry.leaf(auth, {
    path: "auth logout",
    description: "Revoke the remote session and remove the local profile",
    options: []
  }, async (_options, command) => {
    const global = app.global(command);
    const loaded = await app.loadClient(global);
    if (!loaded.profile.client_id) {
      throw new CliError({ code: "LOGOUT_REVOKE_FAILED", message: "client ID is required", exitCode: 3 });
    }
    try {
      await new OAuthClient({
        endpoint: loaded.profile.endpoint,
        clientId: loaded.profile.client_id,
        dispatcher: loaded.client.dispatcher,
        timeoutMs: 10_000
      }).revoke(loaded.token);
    } catch (error) {
      throw new CliError({ code: "LOGOUT_REVOKE_FAILED", message: error instanceof Error ? error.message : "logout revoke failed", exitCode: 3 });
    }
    const config = await app.profiles.load();
    delete config.profiles[loaded.name];
    if (config.current_profile === loaded.name) {
      config.current_profile = "";
    }
    await app.profiles.save(config);
    const warnings: string[] = [];
    await app.secrets.delete(loaded.profile.secret_ref).catch(() => {
      warnings.push("remote session was revoked and the local profile was removed, but its OS secret-store entry could not be removed");
    });
    app.success(global, "Logout", { profile: loaded.name }, "", warnings);
  });

  registry.leaf(auth, {
    path: "auth select-user-pool",
    description: "Select a manageable user pool for an administrator profile",
    aliases: ["switch-user-pool"],
    options: [{ flags: "--user-pool-id <id>", description: "user pool ID" }]
  }, async (options, command) => {
    const global = app.global(command);
    const loaded = await app.loadClient(global);
    const requested = text(options.userPoolId);
    if (loaded.profile.login_type !== "tenant_admin" || requested === "") {
      throw new CliError({ code: "TENANT_CONTEXT_REQUIRED", message: "tenant admin and user-pool-id are required", exitCode: 2 });
    }
    const selected = await selectAdminUserPool(global, loaded.token.access_token, requested, loaded.client);
    const config = await app.profiles.load();
    config.profiles[loaded.name] = { ...loaded.profile, selected_user_pool_id: selected.userPoolId };
    await app.profiles.save(config);
    app.success(global, "UserPoolContext", {
      profile: loaded.name,
      ...selectedUserPoolFields(selected.userPoolId, selected.userPool)
    }, selected.requestId);
  });
}

async function selectAdminUserPool(
  global: GlobalOptions,
  accessToken: string,
  requested: string,
  transport: ApiClient
): Promise<{ userPoolId: string; requestId: string; userPool: ManageableUserPool }> {
  const client = await ApiClient.create({
    endpoint: transport.endpoint,
    sessionToken: accessToken,
    requestId: global.requestId,
    timeoutMs: global.timeoutMs,
    dispatcher: transport.dispatcher
  });
  const result = await client.do({ method: "GET", path: "/api/v3/agent-identity/admin/user-pools" });
  const pools = decodeManageableUserPools(result.data);
  if (requested !== "") {
    const selected = pools.find(pool => pool.id === requested);
    if (selected === undefined) {
      throw new CliError({
        code: "USER_POOL_NOT_MANAGEABLE",
        message: pools.length === 0
          ? "the selected user pool is not manageable by this administrator"
          : `the selected user pool is not manageable by this administrator; choose one: ${pools.map(userPoolLabel).join(", ")}`,
        exitCode: 2,
        requestId: result.requestId,
        ...(pools.length === 0 ? {} : {
          remediation: {
            action: "retry_with_user_pool",
            option: "--user-pool-id",
            manageable_user_pools: pools
          }
        })
      });
    }
    return { userPoolId: requested, requestId: result.requestId, userPool: selected };
  }
  if (pools.length === 1) {
    const selected = pools[0];
    if (selected !== undefined) {
      return { userPoolId: selected.id, requestId: result.requestId, userPool: selected };
    }
  }
  if (pools.length === 0) {
    throw new CliError({ code: "NO_MANAGEABLE_USER_POOL", message: "this administrator has no manageable user pool", exitCode: 2, requestId: result.requestId });
  }
  throw new CliError({
    code: "USER_POOL_SELECTION_REQUIRED",
    message: `multiple manageable user pools found; choose one and retry with --user-pool-id: ${pools.map(userPoolLabel).join(", ")}`,
    exitCode: 2,
    requestId: result.requestId,
    remediation: {
      action: "retry_with_user_pool",
      option: "--user-pool-id",
      manageable_user_pools: pools
    }
  });
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}
