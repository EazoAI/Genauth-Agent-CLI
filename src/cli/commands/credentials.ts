import { randomUUID } from "node:crypto";
import type { Command, OptionValues } from "commander";
import { CliError } from "../../core/errors.js";
import { idempotencyHeaders } from "../../core/idempotency.js";
import type { AppContext, GlobalOptions } from "../context.js";
import { decodeResponseData } from "../context.js";
import type { CommandRegistry, OptionContract } from "../manifest.js";
import { confirmation, requiredText } from "./common.js";

const agentId: OptionContract = { flags: "--agent-id <id>", description: "Agent ID" };
const secretOptions: OptionContract[] = [
  { flags: "--store-keychain", description: "store the delivered secret in the OS secret store", defaultValue: true },
  { flags: "--no-store-keychain", description: "do not store the delivered secret" },
  { flags: "--show-secret", description: "show the one-time secret after explicit acknowledgement" },
  { flags: "--allow-secret-output", description: "allow secret material in machine-readable output" }
];

export function registerCredentialCommands(parent: Command, registry: CommandRegistry, app: AppContext): void {
  const credentials = registry.group(parent, "credentials", "Manage Agent Credentials and one-time delivery");
  registry.leaf(credentials, {
    path: "credentials list",
    description: "List Agent Credentials",
    options: [agentId]
  }, async (options, command) => {
    const global = app.global(command);
    const current = await app.currentProfile(global);
    await app.simple(global, { method: "GET", path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/credentials` }, "CredentialList");
  });
  registry.leaf(credentials, {
    path: "credentials create",
    description: "Create and consume an Agent Credential delivery",
    options: [agentId, ...secretOptions]
  }, async (options, command) => createCredential(app, options, command, false));
  registry.leaf(credentials, {
    path: "credentials rotate",
    description: "Rotate and consume an Agent Credential delivery",
    options: [
      agentId,
      { flags: "--credential-id <id>", description: "Credential ID" },
      { flags: "--yes", description: "confirm credential rotation" },
      ...secretOptions
    ]
  }, async (options, command) => {
    confirmation(options, "rotate credential");
    await createCredential(app, options, command, true);
  });
  registry.leaf(credentials, {
    path: "credentials revoke",
    description: "Revoke an Agent Credential and remove its local secret",
    options: [
      agentId,
      { flags: "--credential-id <id>", description: "Credential ID" },
      { flags: "--yes", description: "confirm credential revocation" }
    ]
  }, async (options, command) => {
    confirmation(options, "revoke credential");
    const global = app.global(command);
    const current = await app.currentProfile(global);
    const credentialId = requiredText(options.credentialId, "credential-id");
    const result = await app.call(global, {
      method: "POST",
      path: `${app.managementPrefix(current.profile)}/agents/${escape(requiredText(options.agentId, "agent-id"))}/credentials/${escape(credentialId)}/revoke`,
      headers: idempotencyHeaders()
    });
    const warnings: string[] = [];
    await app.secrets.delete(`keychain://genauth-agent/credential/${credentialId}`).catch(() => {
      warnings.push("credential was revoked, but its local OS secret-store entry could not be removed");
    });
    app.success(global, "Credential", result.data, result.requestId, warnings);
  });
}

async function createCredential(app: AppContext, options: OptionValues, command: Command, rotate: boolean): Promise<void> {
  const global = app.global(command);
  const current = await app.currentProfile(global);
  const agentIdValue = requiredText(options.agentId, "agent-id");
  const credentialId = rotate ? requiredText(options.credentialId, "credential-id") : "";
  const storeKeychain = options.storeKeychain !== false;
  const showSecret = Boolean(options.showSecret);
  if (!storeKeychain && !showSecret) {
    throw new CliError({ code: "SECRET_DESTINATION_REQUIRED", message: "enable --store-keychain or explicitly use --show-secret", exitCode: 2 });
  }
  if (showSecret && global.output !== "table" && !options.allowSecretOutput) {
    throw new CliError({ code: "SECRET_OUTPUT_ACKNOWLEDGEMENT_REQUIRED", message: "--show-secret with machine-readable output also requires --allow-secret-output", exitCode: 2 });
  }
  const humanSession = randomUUID();
  const base = `${app.managementPrefix(current.profile)}/agents/${escape(agentIdValue)}/credentials`;
  const created = await app.call(global, {
    method: "POST",
    path: rotate ? `${base}/${escape(credentialId)}/rotate` : base,
    headers: { ...idempotencyHeaders(), "X-Human-Session-Id": humanSession }
  });
  const delivery = decodeResponseData<{
    credential?: { credential_id?: string; expires_at?: string };
    delivery?: { delivery_id?: string; delivery_code?: string };
  }>(created.data);
  if (!delivery.delivery?.delivery_id || !delivery.delivery.delivery_code) {
    throw serverResponse("credential delivery response is invalid", created.requestId);
  }
  const consumed = await app.call(global, {
    method: "POST",
    path: `${app.managementPrefix(current.profile)}/credential-deliveries/${escape(delivery.delivery.delivery_id)}/consume`,
    body: { delivery_code: delivery.delivery.delivery_code },
    headers: { "X-Human-Session-Id": humanSession }
  });
  const secret = decodeResponseData<{ credential_id?: string; client_secret?: string }>(consumed.data);
  if (!secret.credential_id || !secret.client_secret) {
    await bestEffortRevoke(app, global, agentIdValue, delivery.credential?.credential_id ?? "");
    throw serverResponse("credential secret response is invalid", consumed.requestId);
  }
  let secretRef = "";
  if (storeKeychain) {
    secretRef = `keychain://genauth-agent/credential/${secret.credential_id}`;
    try {
      await app.secrets.set(secretRef, JSON.stringify({ credential_id: secret.credential_id, client_secret: secret.client_secret }));
    } catch {
      await bestEffortRevoke(app, global, agentIdValue, secret.credential_id);
      throw new CliError({ code: "SECRET_STORE_UNAVAILABLE", message: "OS secret store is unavailable", exitCode: 9 });
    }
  }
  const output: Record<string, unknown> = {
    credential_id: secret.credential_id,
    expires_at: delivery.credential?.expires_at ?? ""
  };
  if (secretRef) output.secret_ref = secretRef;
  if (showSecret) {
    if (!global.quiet) app.io.error.write("WARNING: the one-time Agent Credential secret is now visible to terminal history and screen recording.\n");
    output.client_secret = secret.client_secret;
  }
  app.success(global, "AgentCredential", output, consumed.requestId);
  delete output.client_secret;
}

async function bestEffortRevoke(app: AppContext, global: GlobalOptions, agentIdValue: string, credentialId: string): Promise<void> {
  if (!agentIdValue || !credentialId) return;
  const current = await app.currentProfile(global);
  await app.call(global, {
    method: "POST",
    path: `${app.managementPrefix(current.profile)}/agents/${escape(agentIdValue)}/credentials/${escape(credentialId)}/revoke`,
    headers: idempotencyHeaders()
  }).catch(() => undefined);
}

function serverResponse(message: string, requestId: string): CliError {
  return new CliError({ code: "INVALID_SERVER_RESPONSE", message, exitCode: 9, requestId });
}

function escape(value: string): string { return encodeURIComponent(value); }
