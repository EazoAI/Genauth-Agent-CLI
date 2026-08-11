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
import { decodeResponseData, validateCliEndpoint } from "../context.js";
import type { CommandRegistry } from "../manifest.js";

export function registerAuthCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const auth = registry.group(parent, "auth", "Authenticate and select the current user pool");

  registry.leaf(auth, {
    path: "auth login",
    description: "Login as a user or tenant administrator",
    options: [
      { flags: "--user-pool-id <id>", description: "selected user pool ID" },
      { flags: "--profile-name <name>", description: "profile to create", defaultValue: "default" },
      { flags: "--client-id <id>", description: "override the discovered GenAuth OIDC client ID", hidden: true },
      { flags: "--admin", description: "login as tenant administrator" },
      { flags: "--session-token-stdin", description: "read an existing GenAuth session token from stdin" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const profileName = text(options.profileName) || "default";
    const userPoolId = text(options.userPoolId);
    const admin = Boolean(options.admin);
    try {
      validateProfileName(profileName);
    } catch {
      throw new CliError({ code: "INVALID_ARGUMENT", message: "profile is required", exitCode: 2 });
    }
    if (!admin && userPoolId === "") {
      throw new CliError({ code: "INVALID_ARGUMENT", message: "user-pool-id is required for user login", exitCode: 2 });
    }
    if (global.endpoint === "") {
      throw new CliError({ code: "INVALID_ENDPOINT", message: "endpoint must be provided for login", exitCode: 2 });
    }
    validateCliEndpoint(global.endpoint, global.allowInsecureLocalhost);
    await app.probeSecretStore();
    let clientId = text(options.clientId);
    const warnings: string[] = [];
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
    let token: OAuthToken;
    let loginConfigRequestId = "";
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
      if (clientId === "") {
        const discovered = await discoverLoginConfig(transport);
        clientId = discovered.clientId;
        loginConfigRequestId = discovered.requestId;
      } else {
        warnings.push("--client-id is deprecated; GenAuth login configuration is normally discovered from the endpoint");
      }
      const controller = AbortSignal.timeout(5 * 60_000);
      try {
        token = await new OAuthClient({
          endpoint: global.endpoint,
          clientId,
          dispatcher: transport.dispatcher,
          timeoutMs: global.timeoutMs
        }).login({
          userPoolId,
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
      login_type: admin ? "tenant_admin" : "user",
      ...(tokenSubject(token.access_token) === "" ? {} : { subject_id: tokenSubject(token.access_token) }),
      selected_user_pool_id: userPoolId,
      secret_ref: secretRef
    };
    let requestId = loginConfigRequestId;
    if (admin) {
      const selected = await selectAdminUserPool(global, token.access_token, userPoolId, transport);
      profile.selected_user_pool_id = selected.userPoolId;
      requestId = selected.requestId;
    }
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
      selected_user_pool_id: profile.selected_user_pool_id,
      secret_ref: secretRef
    }, requestId, warnings);
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
    app.success(global, "AuthStatus", {
      authenticated: true,
      profile: current.name,
      login_type: current.profile.login_type,
      subject_id: current.profile.subject_id ?? "",
      selected_user_pool_id: current.profile.selected_user_pool_id,
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
    app.success(global, "UserPoolContext", { profile: loaded.name, selected_user_pool_id: selected.userPoolId }, selected.requestId);
  });
}

async function selectAdminUserPool(
  global: GlobalOptions,
  accessToken: string,
  requested: string,
  transport: ApiClient
): Promise<{ userPoolId: string; requestId: string }> {
  const client = await ApiClient.create({
    endpoint: transport.endpoint,
    sessionToken: accessToken,
    requestId: global.requestId,
    timeoutMs: global.timeoutMs,
    dispatcher: transport.dispatcher
  });
  const result = await client.do({ method: "GET", path: "/api/v3/agent-identity/admin/user-pools" });
  const data = decodeResponseData<{ list?: Array<{ id?: string }> }>(result.data);
  const ids = (data.list ?? []).flatMap(item => item.id ? [item.id] : []);
  if (requested !== "") {
    if (!ids.includes(requested)) {
      throw new CliError({ code: "USER_POOL_NOT_MANAGEABLE", message: "the selected user pool is not manageable by this administrator", exitCode: 2, requestId: result.requestId });
    }
    return { userPoolId: requested, requestId: result.requestId };
  }
  if (ids.length === 1) {
    return { userPoolId: ids[0] ?? "", requestId: result.requestId };
  }
  if (ids.length === 0) {
    throw new CliError({ code: "NO_MANAGEABLE_USER_POOL", message: "this administrator has no manageable user pool", exitCode: 2, requestId: result.requestId });
  }
  throw new CliError({
    code: "USER_POOL_SELECTION_REQUIRED",
    message: `multiple manageable user pools found; retry with --user-pool-id (${ids.join(", ")})`,
    exitCode: 2,
    requestId: result.requestId
  });
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}
