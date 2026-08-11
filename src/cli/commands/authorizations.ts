import type { Command, OptionValues } from "commander";
import { openBrowser } from "../../auth/browser.js";
import { createPkce } from "../../auth/pkce.js";
import { listenAuthorizationCallback, reserveLoopbackRedirectUri } from "../../auth/authorization-callback.js";
import { CliError } from "../../core/errors.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import { readLimitedStdin } from "../../core/input.js";
import type { AppContext, GlobalOptions } from "../context.js";
import { decodeResponseData } from "../context.js";
import type { CommandRegistry, OptionContract } from "../manifest.js";
import { confirmation, integerOption, requiredText, stringOptions, text } from "./common.js";

const authorizationId: OptionContract = { flags: "--authorization-id <id>", description: "authorization request ID" };

export function registerAuthorizationCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const authorizations = registry.group(parent, "authorizations", "Create and complete Agent user authorization requests");
  registry.leaf(authorizations, {
    path: "authorizations create",
    description: "Create an explicit or policy-allowed silent authorization request",
    options: [
      { flags: "--agent-id <id>", description: "Agent ID" },
      { flags: "--user-id <id>", description: "target user ID (administrator only)" },
      { flags: "--audience <audience>", description: "ResourceServer audience" },
      { flags: "--permission-id <id>", description: "DataPolicy ID (repeatable)", collect: true },
      { flags: "--mode <mode>", description: "explicit or silent", defaultValue: "explicit" },
      { flags: "--redirect-uri <uri>", description: "authorization callback URI" },
      { flags: "--open-browser", description: "open the authorization link and wait for consent" },
      { flags: "--grant-ttl-seconds <seconds>", description: "UserGrant TTL", defaultValue: "3600" },
      { flags: "--yes", description: "confirm silent authorization" }
    ]
  }, async (options, command) => createAuthorization(app, options, command));

  registry.leaf(authorizations, { path: "authorizations get", description: "Get an authorization request", options: [authorizationId] }, async (options, command) => {
    const global = app.global(command);
    await app.simple(global, { method: "GET", path: await authorizationPath(app, global, requiredText(options.authorizationId, "authorization-id")) }, "AuthorizationRequest");
  });
  registry.leaf(authorizations, {
    path: "authorizations wait",
    description: "Wait for consent and complete the PKCE exchange",
    options: [authorizationId, { flags: "--open-browser", description: "open the stored authorization URL while polling" }]
  }, async (options, command) => waitAuthorization(app, app.global(command), requiredText(options.authorizationId, "authorization-id"), Boolean(options.openBrowser)));
  registry.leaf(authorizations, {
    path: "authorizations consent",
    description: "Record consent as the target user",
    options: [authorizationId, { flags: "--show-code", description: "include the one-time code for secure handoff" }]
  }, async (options, command) => consentAuthorization(app, options, command));
  registry.leaf(authorizations, {
    path: "authorizations deny",
    description: "Deny authorization as the target user",
    options: [authorizationId, { flags: "--reason <reason>", description: "denial reason" }, { flags: "--yes", description: "confirm denial" }]
  }, async (options, command) => {
    confirmation(options, "deny authorization");
    const global = app.global(command);
    const current = await app.currentProfile(global);
    if (current.profile.login_type !== "user") throw new CliError({ code: "USER_LOGIN_REQUIRED", message: "denial requires the target user profile", exitCode: 2 });
    await app.simple(global, {
      method: "POST",
      path: `/api/v3/agent-identity/me/authorization-requests/${escape(requiredText(options.authorizationId, "authorization-id"))}/deny`,
      body: { reason: requiredText(options.reason, "reason") }
    }, "AuthorizationRequest");
  });
  registry.leaf(authorizations, {
    path: "authorizations cancel",
    description: "Cancel an authorization request",
    options: [authorizationId, { flags: "--yes", description: "confirm cancellation" }]
  }, async (options, command) => {
    confirmation(options, "cancel authorization request");
    const global = app.global(command);
    await app.simple(global, {
      method: "POST",
      path: `${await authorizationPath(app, global, requiredText(options.authorizationId, "authorization-id"))}/cancel`,
      headers: idempotencyHeaders()
    }, "AuthorizationRequest");
  });
  registry.leaf(authorizations, {
    path: "authorizations exchange",
    description: "Exchange a consent result using the locally stored PKCE verifier",
    options: [authorizationId, { flags: "--code-stdin", description: "read a one-time authorization code from stdin" }]
  }, async (options, command) => {
    const requestId = requiredText(options.authorizationId, "authorization-id");
    const code = options.codeStdin ? await readLimitedStdin(app.io.input, 4096) : await app.secrets.get(secretRef(requestId, "code")).catch(() => "");
    await exchangeAuthorization(app, app.global(command), requestId, code);
  });

  registerGrantCommands(parent, registry, app);
}

function registerGrantCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const grants = registry.group(parent, "grants", "Inspect and revoke Agent UserGrants");
  registry.leaf(grants, { path: "grants list", description: "List UserGrants visible to the current profile", options: [] }, async (_options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    const path = current.profile.login_type === "user" ? "/api/v3/agent-identity/me/agent-user-grants" : "/api/v3/agent-identity/admin/agent-user-grants";
    await app.simple(global, { method: "GET", path }, "UserGrantList");
  });
  registry.leaf(grants, {
    path: "grants revoke",
    description: "Revoke one UserGrant",
    options: [
      { flags: "--grant-id <id>", description: "UserGrant ID" },
      { flags: "--version <number>", description: "expected UserGrant version" },
      { flags: "--reason <reason>", description: "revocation reason" },
      { flags: "--yes", description: "confirm revocation" }
    ]
  }, async (options, command) => {
    confirmation(options, "revoke user grant");
    const version = integerOption(options.version, "version");
    if (version <= 0) throw invalid("version must be greater than zero");
    const global = app.global(command);
    const current = await app.currentProfile(global);
    await app.simple(global, {
      method: "POST",
      path: `${app.managementPrefix(current.profile)}/agent-user-grants/${escape(requiredText(options.grantId, "grant-id"))}/revoke`,
      body: { version, reason: requiredText(options.reason, "reason") },
      headers: idempotencyHeaders()
    }, "UserGrant");
  });
}

async function createAuthorization(app: AppContext, options: OptionValues, command: Command): Promise<void> {
  const global = app.global(command);
  const current = await app.currentProfile(global);
  const permissions = stringOptions(options.permissionId);
  if (permissions.length === 0) throw invalid("at least one permission-id is required");
  const mode = (text(options.mode) || "explicit").toUpperCase();
  if (mode !== "EXPLICIT" && mode !== "SILENT") throw invalid("mode must be explicit or silent");
  const userId = text(options.userId);
  if (current.profile.login_type === "user" && (userId !== "" || mode === "SILENT")) {
    throw new CliError({ code: "FORBIDDEN_USER_AUTHORIZATION_MODE", message: "user profiles can authorize only themselves with explicit consent", exitCode: 2 });
  }
  if (mode === "SILENT") confirmation(options, "request silent authorization");
  const agentId = requiredText(options.agentId, "agent-id");
  const body: Record<string, unknown> = {
    target_user_id: userId,
    audience: requiredText(options.audience, "audience"),
    permission_ids: permissions,
    mode,
    user_grant_ttl_seconds: integerOption(options.grantTtlSeconds, "grant-ttl-seconds", 3600)
  };
  let verifier = "";
  let redirectUri = text(options.redirectUri);
  if (mode === "EXPLICIT") {
    if (!redirectUri) {
      try { redirectUri = await reserveLoopbackRedirectUri(); }
      catch { throw new CliError({ code: "CALLBACK_UNAVAILABLE", message: "could not reserve a loopback authorization callback", exitCode: 2 }); }
    }
    const pkce = createPkce();
    verifier = pkce.verifier;
    body.redirect_uri = redirectUri;
    body.pkce_challenge = pkce.challenge;
  }
  const created = await app.call(global, {
    method: "POST",
    path: `${app.managementPrefix(current.profile)}/agents/${escape(agentId)}/authorization-requests`,
    body,
    headers: idempotencyHeaders()
  });
  const result = decodeResponseData<{ request?: { request_id?: string } }>(created.data);
  const requestId = result.request?.request_id ?? "";
  if (!requestId) throw serverResponse("authorization response is invalid", created.requestId);
  const output: Record<string, unknown> = { authorization: created.data };
  if (mode === "EXPLICIT") {
    const authorizationUrl = new URL(`${current.profile.endpoint.replace(/\/$/u, "")}/agent-identity/authorize`);
    authorizationUrl.searchParams.set("request_id", requestId);
    authorizationUrl.searchParams.set("user_pool_id", current.profile.selected_user_pool_id);
    try {
      await app.secrets.set(secretRef(requestId, "pkce"), verifier);
      await app.secrets.set(secretRef(requestId, "callback"), redirectUri);
      await app.secrets.set(secretRef(requestId, "url"), authorizationUrl.toString());
    } catch {
      await compensateAuthorization(app, global, requestId);
      throw new CliError({ code: "SECRET_STORE_UNAVAILABLE", message: "OS secret store is unavailable; the new authorization request was cancelled where possible", requestId: created.requestId, exitCode: 9 });
    }
    output.authorization_url = authorizationUrl.toString();
    output.pkce_ref = secretRef(requestId, "pkce");
    if (options.openBrowser && !global.noBrowser) {
      await waitAuthorization(app, global, requestId, true);
      return;
    }
  }
  app.success(global, "AuthorizationRequest", output, created.requestId);
}

async function consentAuthorization(app: AppContext, options: OptionValues, command: Command): Promise<void> {
  const global = app.global(command);
  const current = await app.currentProfile(global);
  if (current.profile.login_type !== "user") throw new CliError({ code: "USER_LOGIN_REQUIRED", message: "consent requires a user profile", exitCode: 2 });
  await app.probeSecretStore();
  const requestId = requiredText(options.authorizationId, "authorization-id");
  const response = await app.call(global, { method: "POST", path: `/api/v3/agent-identity/me/authorization-requests/${escape(requestId)}/consent` });
  const result = decodeResponseData<{ authorization_code?: string; redirect_uri?: string }>(response.data);
  if (!result.authorization_code) throw serverResponse("consent response is invalid", response.requestId);
  const codeRef = secretRef(requestId, "code");
  await app.secrets.set(codeRef, result.authorization_code);
  app.success(global, "AuthorizationConsent", {
    request_id: requestId,
    redirect_uri: result.redirect_uri ?? "",
    code_ref: codeRef,
    ...(options.showCode ? { authorization_code: result.authorization_code } : {})
  }, response.requestId);
}

async function waitAuthorization(app: AppContext, global: GlobalOptions, requestId: string, shouldOpenBrowser: boolean): Promise<void> {
  const signal = AbortSignal.timeout(global.timeoutMs);
  let callback: Awaited<ReturnType<typeof listenAuthorizationCallback>> | undefined;
  const callbackUri = await app.secrets.get(secretRef(requestId, "callback")).catch(() => "");
  if (callbackUri) callback = await listenAuthorizationCallback(callbackUri, requestId, signal).catch(() => undefined);
  try {
    if (shouldOpenBrowser && !global.noBrowser) {
      const target = await app.secrets.get(secretRef(requestId, "url")).catch(() => "");
      if (!target) throw new CliError({ code: "AUTHORIZATION_URL_NOT_FOUND", message: "the authorization URL is unavailable in the OS secret store", exitCode: 2 });
      openBrowser(target);
    }
    let delay = 1_000;
    while (!signal.aborted) {
      let response: Awaited<ReturnType<AppContext["call"]>> | undefined;
      try { response = await app.call(global, { method: "GET", path: await authorizationPath(app, global, requestId), signal }); }
      catch (error) {
        if (!(error instanceof CliError) || !error.retryable) throw error;
      }
      if (response) {
        const item = decodeResponseData<{ status?: string; poll_after?: number }>(response.data);
        if (item.poll_after && item.poll_after > 0) delay = item.poll_after * 1_000;
        if (item.status === "APPROVED") { app.success(global, "AuthorizationRequest", response.data, response.requestId); return; }
        if (item.status === "CONSENTED") { await exchangeAuthorization(app, global, requestId, ""); return; }
        if (item.status === "DENIED") throw new CliError({ code: "AUTHORIZATION_DENIED", message: "authorization was denied", exitCode: 4, requestId: response.requestId });
        if (item.status === "EXPIRED" || item.status === "CANCELLED") throw new CliError({ code: `AUTHORIZATION_${item.status}`, message: `authorization reached ${item.status.toLowerCase()}`, exitCode: 5, requestId: response.requestId });
      }
      const callbackRace = callback?.event.then(event => ({ type: "callback" as const, event }));
      const timer = sleep(delay, signal).then(() => ({ type: "timer" as const }));
      const next = callbackRace ? await Promise.race([callbackRace, timer]) : await timer;
      if (next.type === "callback") {
        if (next.event.error) throw new CliError({ code: "AUTHORIZATION_DENIED", message: "authorization was denied", exitCode: 4 });
        await exchangeAuthorization(app, global, requestId, next.event.code);
        return;
      }
      delay = Math.min(15_000, Math.round(delay * 1.5));
    }
  } catch (error) {
    if (signal.aborted && !(error instanceof CliError)) throw new CliError({ code: "AUTHORIZATION_PENDING", message: "authorization is still pending", exitCode: 6 });
    throw error;
  } finally {
    await callback?.close();
  }
  throw new CliError({ code: "AUTHORIZATION_PENDING", message: "authorization is still pending", exitCode: 6 });
}

async function exchangeAuthorization(app: AppContext, global: GlobalOptions, requestId: string, code: string): Promise<void> {
  const verifierRef = secretRef(requestId, "pkce");
  const verifier = await app.secrets.get(verifierRef).catch(() => "");
  if (!verifier) throw new CliError({ code: "PKCE_NOT_FOUND", message: "PKCE verifier is unavailable in the OS secret store", exitCode: 2 });
  const result = await app.call(global, {
    method: "POST",
    path: `${await authorizationPath(app, global, requestId)}/exchange`,
    body: { code_verifier: verifier, ...(code ? { authorization_code: code } : {}) },
    headers: idempotencyHeaders()
  });
  const warnings = await cleanupAuthorization(app, requestId);
  app.success(global, "UserGrant", result.data, result.requestId, warnings);
}

async function cleanupAuthorization(app: AppContext, requestId: string): Promise<string[]> {
  let failed = false;
  for (const suffix of ["pkce", "code", "callback", "url"]) {
    await app.secrets.delete(secretRef(requestId, suffix)).catch(() => { failed = true; });
  }
  return failed ? ["authorization exchange succeeded, but one or more one-time values could not be removed from the OS secret store"] : [];
}

async function compensateAuthorization(app: AppContext, global: GlobalOptions, requestId: string): Promise<void> {
  await cleanupAuthorization(app, requestId);
  await app.call(global, { method: "POST", path: `${await authorizationPath(app, global, requestId)}/cancel`, headers: idempotencyHeaders() }).catch(() => undefined);
}

async function authorizationPath(app: AppContext, global: GlobalOptions, requestId: string): Promise<string> {
  const current = await app.currentProfile(global);
  const prefix = current.profile.login_type === "user" ? "/api/v3/agent-identity/me" : "/api/v3/agent-identity/admin";
  return `${prefix}/authorization-requests/${escape(requestId)}`;
}

function secretRef(requestId: string, suffix: string): string { return `keychain://agent-identity/authorization/${requestId}/${suffix}`; }
function escape(value: string): string { return encodeURIComponent(value); }
function invalid(message: string): CliError { return new CliError({ code: "INVALID_ARGUMENT", message, exitCode: 2 }); }
function serverResponse(message: string, requestId: string): CliError { return new CliError({ code: "INVALID_SERVER_RESPONSE", message, requestId, exitCode: 9 }); }
function sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal.addEventListener("abort", () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
  });
}
