import { randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import { CLI_API_VERSION } from "../core/output.js";
import { userConfigDirectory } from "./paths.js";

const profileNamePattern = /^[A-Za-z0-9._-]{1,64}$/;
const secretReferencePrefix = "keychain://agent-identity/";

const profileSchema = z.object({
  endpoint: z.string(),
  client_id: z.string().optional(),
  login_type: z.enum(["user", "tenant_admin"]),
  subject_id: z.string().optional(),
  selected_user_pool_id: z.string().min(1),
  secret_ref: z.string().refine(isSecretReference)
});

const configSchema = z.object({
  api_version: z.literal(CLI_API_VERSION),
  current_profile: z.string(),
  profiles: z.record(z.string(), profileSchema)
});

export type Profile = z.infer<typeof profileSchema>;
export type ProfileConfig = z.infer<typeof configSchema>;

export class InvalidProfileError extends Error {
  constructor(message = "invalid CLI profile") {
    super(message);
    this.name = "InvalidProfileError";
  }
}

export class ProfileStore {
  readonly filePath: string;

  constructor(filePath = path.join(userConfigDirectory(), "config.json")) {
    this.filePath = filePath;
  }

  async load(): Promise<ProfileConfig> {
    let content: string;
    try {
      content = await readFile(this.filePath, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return { api_version: CLI_API_VERSION, current_profile: "", profiles: {} };
      }
      throw error;
    }
    try {
      const config = configSchema.parse(JSON.parse(content));
      validateConfig(config);
      return config;
    } catch (error) {
      throw new InvalidProfileError(error instanceof Error ? error.message : undefined);
    }
  }

  async save(config: ProfileConfig): Promise<void> {
    const normalized: ProfileConfig = {
      api_version: CLI_API_VERSION,
      current_profile: config.current_profile,
      profiles: config.profiles
    };
    validateConfig(normalized);
    const directory = path.dirname(this.filePath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700).catch(() => undefined);
    const temporaryPath = path.join(directory, `.config-${randomUUID()}`);
    const handle = await open(temporaryPath, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify(normalized, null, 2), "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await rename(temporaryPath, this.filePath);
      await chmod(this.filePath, 0o600).catch(() => undefined);
    } finally {
      await rm(temporaryPath, { force: true }).catch(() => undefined);
    }
  }

  async current(override = ""): Promise<{ name: string; profile: Profile; config: ProfileConfig }> {
    const config = await this.load();
    const name = override.trim() || config.current_profile;
    const profile = config.profiles[name];
    if (!profile) {
      throw new InvalidProfileError("current profile does not exist");
    }
    return { name, profile, config };
  }
}

export function validateProfileName(value: string): void {
  if (!profileNamePattern.test(value)) {
    throw new InvalidProfileError("profile name must contain only letters, digits, dot, underscore, or hyphen");
  }
}

export function validateEndpoint(value: string): void {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw new InvalidProfileError();
  }
  const localHttp = endpoint.protocol === "http:" && (endpoint.hostname === "127.0.0.1" || endpoint.hostname === "localhost");
  if (
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.search !== "" ||
    endpoint.hash !== "" ||
    (endpoint.pathname !== "" && endpoint.pathname !== "/") ||
    (endpoint.protocol !== "https:" && !localHttp)
  ) {
    throw new InvalidProfileError();
  }
}

export function validateProfile(profile: Profile): void {
  profileSchema.parse(profile);
  validateEndpoint(profile.endpoint);
}

function validateConfig(config: ProfileConfig): void {
  configSchema.parse(config);
  for (const [name, profile] of Object.entries(config.profiles)) {
    validateProfileName(name);
    validateProfile(profile);
  }
  if (config.current_profile !== "" && !config.profiles[config.current_profile]) {
    throw new InvalidProfileError();
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function isSecretReference(value: string): boolean {
  const hasControl = [...value].some(character => {
    const code = character.charCodeAt(0);
    return code === 0 || code === 10 || code === 13;
  });
  return value.startsWith(secretReferencePrefix)
    && value.length > secretReferencePrefix.length
    && value.length <= 256
    && !hasControl;
}
