import { spawn } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import type { Command, OptionValues } from "commander";
import { inspectJwt } from "../../core/jwt.js";
import { CliError } from "../../core/errors.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import { readJsonFile, readLimitedStdin } from "../../core/input.js";
import { ApiError } from "../../http/errors.js";
import type { AppContext, GlobalOptions } from "../context.js";
import { classifyApiError, decodeResponseData } from "../context.js";
import type { CommandRegistry, OptionContract } from "../manifest.js";
import { compactQuery, confirmation, integerOption, requiredText, stringOptions, text } from "./common.js";

const credentialOptions: OptionContract[] = [
  { flags: "--credential <reference>", description: "Keychain Credential reference" },
  { flags: "--grant-id <id>", description: "UserGrant ID" },
  { flags: "--audience <audience>", description: "ResourceServer audience" }
];

export function registerRuntimeCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  registerTokenCommands(parent, registry, app);
  registerProviderCommands(parent, registry, app);
  registerAuditCommands(parent, registry, app);
}

function registerTokenCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const tokens = registry.group(parent, "tokens", "Issue, inspect, list, and revoke Agent access Tokens");
  registry.leaf(tokens, {
    path: "tokens issue",
    description: "Issue a short-lived Agent access Token",
    options: [
      ...credentialOptions,
      { flags: "--permission-id <id>", description: "requested DataPolicy ID", collect: true },
      { flags: "--ttl-seconds <seconds>", description: "requested Token TTL", defaultValue: "0" },
      { flags: "--show-token", description: "include the access Token in output" },
      { flags: "--exec <program>", description: "execute a program with a process-lifetime Token" },
      { flags: "--exec-arg <argument>", description: "argument passed directly to --exec", collect: true }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const result = await issueToken(app, global, options);
    const item = decodeResponseData<Record<string, unknown>>(result.data);
    const accessToken = typeof item.access_token === "string" ? item.access_token : "";
    const executable = text(options.exec);
    if (executable) {
      if (!accessToken) throw serverResponse("runtime Token response is invalid", result.requestId);
      const status = await runChild(app, executable, stringOptions(options.execArg), accessToken);
      if (status !== 0) throw new CliError({ code: "EXEC_COMMAND_FAILED", message: "Token consumer command failed", requestId: result.requestId, exitCode: 5 });
      return;
    }
    const output = { ...item };
    if (!options.showToken) delete output.access_token;
    app.success(global, "AgentAccessToken", output, result.requestId);
  });
  registry.leaf(tokens, {
    path: "tokens list",
    description: "List Token lifecycle metadata for an Agent",
    options: [{ flags: "--agent-id <id>", description: "Agent ID" }]
  }, async (options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    await app.simple(global, { method: "GET", path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/tokens` }, "AgentTokenList");
  });
  registry.leaf(tokens, {
    path: "tokens revoke",
    description: "Revoke a Token JTI",
    options: [
      { flags: "--agent-id <id>", description: "Agent ID required for user profiles" },
      { flags: "--jti <jti>", description: "Token JTI" },
      { flags: "--reason <reason>", description: "revocation reason" },
      { flags: "--yes", description: "confirm Token revocation" }
    ]
  }, async (options, command) => {
    confirmation(options, "revoke token");
    const global = app.global(command);
    const current = await app.currentProfile(global);
    const jti = requiredText(options.jti, "jti");
    const path = current.profile.login_type === "user"
      ? `/api/v3/agent-identity/me/agents/${escape(requiredText(options.agentId, "agent-id"))}/tokens/${escape(jti)}/revoke`
      : `/api/v3/agent-identity/admin/runtime/tokens/${escape(jti)}/revoke`;
    await app.simple(global, {
      method: "POST",
      path,
      body: { reason: requiredText(options.reason, "reason") },
      headers: idempotencyHeaders()
    }, "AgentToken");
  });
  registry.leaf(tokens, {
    path: "tokens inspect",
    description: "Decode local JWT header and claims without verification",
    options: [{ flags: "--token-stdin", description: "read Token from stdin" }]
  }, async (options, command) => {
    if (!options.tokenStdin) throw invalid("token-stdin is required");
    const global = app.global(command);
    let inspection;
    try { inspection = inspectJwt(await readLimitedStdin(app.io.input)); }
    catch (error) { throw new CliError({ code: "INVALID_TOKEN", message: error instanceof Error ? error.message : "invalid Token", exitCode: 2 }); }
    app.success(global, "AgentTokenClaims", { ...inspection, signature_verified: false });
  });
}

function registerProviderCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const providers = registry.group(parent, "providers", "Call approved fixed Provider routes through GenAuth");
  registry.leaf(providers, {
    path: "providers call",
    description: "Issue an in-memory Token and call one fixed Provider route",
    options: [
      ...credentialOptions,
      { flags: "--provider <key>", description: "fixed Provider key" },
      { flags: "--method <method>", description: "HTTP method", defaultValue: "GET" },
      { flags: "--path <path>", description: "normalized Provider path" },
      { flags: "--body-file <path>", description: "JSON request body file" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const provider = requiredText(options.provider, "provider");
    const providerPath = requiredText(options.path, "path");
    if (!providerPath.startsWith("/") || providerPath.startsWith("//") || providerPath.includes("..")) {
      throw invalid("path must be an absolute normalized provider path");
    }
    const tokenResult = await issueToken(app, global, options);
    const token = decodeResponseData<{ access_token?: string }>(tokenResult.data).access_token ?? "";
    if (!token) throw serverResponse("runtime Token response is invalid", tokenResult.requestId);
    const loaded = await app.loadClient(global);
    const bodyFile = text(options.bodyFile);
    const body = bodyFile ? await readJsonFile(bodyFile) : undefined;
    let response;
    try {
      response = await loaded.client.do<Buffer>({
        method: (text(options.method) || "GET").toUpperCase(),
        path: `/api/v3/agent-runtime/providers/${escape(provider)}${providerPath}`,
        ...(body === undefined ? {} : { body }),
        headers: { Authorization: `Bearer ${token}` },
        responseType: "buffer"
      });
    } catch (error) {
      throw classifyApiError(error);
    }
    const content = response.data;
    let output: unknown;
    try { output = JSON.parse(content.toString("utf8")) as unknown; }
    catch { output = { content_base64: content.toString("base64"), encoding: "base64" }; }
    app.success(global, "ProviderResponse", output, response.requestId);
  });
}

function registerAuditCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const audit = registry.group(parent, "audit", "Inspect Agent Identity audit events");
  registry.leaf(audit, {
    path: "audit list",
    description: "List audit events",
    options: [
      { flags: "--agent-id <id>", description: "optional Agent ID filter" },
      { flags: "--action <action>", description: "optional audit action filter" }
    ]
  }, async (options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    await app.simple(global, {
      method: "GET",
      path: `${app.managementPrefix(current.profile)}/audit-events`,
      query: compactQuery({ agent_id: text(options.agentId), action: text(options.action) })
    }, "AuditEventList");
  });
}

async function issueToken(app: AppContext, global: GlobalOptions, options: OptionValues): Promise<{ data: unknown; requestId: string }> {
  const reference = requiredText(options.credential, "credential");
  const grantId = requiredText(options.grantId, "grant-id");
  const audience = requiredText(options.audience, "audience");
  let stored: string;
  try { stored = await app.secrets.get(reference); }
  catch { throw new CliError({ code: "CREDENTIAL_NOT_FOUND", message: "credential is unavailable in the OS secret store", exitCode: 3 }); }
  let credential: { credential_id?: string; client_secret?: string };
  try { credential = JSON.parse(stored) as typeof credential; }
  catch { throw new CliError({ code: "INVALID_CREDENTIAL_REFERENCE", message: "stored credential is invalid", exitCode: 2 }); }
  if (!credential.credential_id || !credential.client_secret) throw new CliError({ code: "INVALID_CREDENTIAL_REFERENCE", message: "stored credential is invalid", exitCode: 2 });
  const loaded = await app.loadClient(global);
  try {
    return await loaded.client.runtimeToken({
      credentialId: credential.credential_id,
      secret: credential.client_secret,
      userGrantId: grantId,
      audience,
      permissionIds: stringOptions(options.permissionId),
      ttlSeconds: integerOption(options.ttlSeconds, "ttl-seconds", 0)
    });
  } catch (error) {
    if (error instanceof ApiError) throw classifyApiError(error);
    throw error;
  }
}

async function runChild(app: AppContext, executable: string, arguments_: string[], accessToken: string): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const child = spawn(executable, arguments_, {
      env: { ...process.env, AGENT_IDENTITY_ACCESS_TOKEN: accessToken },
      stdio: [app.io.input as Readable, app.io.output as Writable, app.io.error as Writable],
      shell: false
    });
    child.once("error", reject);
    child.once("exit", code => resolve(code ?? 1));
  });
}

function escape(value: string): string { return encodeURIComponent(value); }
function invalid(message: string): CliError { return new CliError({ code: "INVALID_ARGUMENT", message, exitCode: 2 }); }
function serverResponse(message: string, requestId: string): CliError { return new CliError({ code: "INVALID_SERVER_RESPONSE", message, requestId, exitCode: 9 }); }
