import { Entry } from "@napi-rs/keyring";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";

const service = "agent-identity-cli";
const referencePrefix = "keychain://agent-identity/";

export interface SecretStore {
  set(reference: string, value: string): Promise<void>;
  get(reference: string): Promise<string>;
  delete(reference: string): Promise<void>;
}

export class InvalidSecretReferenceError extends Error {
  constructor() {
    super("invalid secret reference");
    this.name = "InvalidSecretReferenceError";
  }
}

export class KeychainSecretStore implements SecretStore {
  private readonly implementation: SecretStore;

  constructor(platform: NodeJS.Platform = process.platform) {
    this.implementation = platform === "darwin" ? new MacOsKeychainSecretStore() : new NativeKeychainSecretStore();
  }

  async set(reference: string, value: string): Promise<void> {
    await this.implementation.set(reference, value);
  }

  async get(reference: string): Promise<string> {
    return this.implementation.get(reference);
  }

  async delete(reference: string): Promise<void> {
    await this.implementation.delete(reference);
  }
}

class NativeKeychainSecretStore implements SecretStore {
  async set(reference: string, value: string): Promise<void> {
    if (value === "") throw new InvalidSecretReferenceError();
    new Entry(service, secretAccount(reference)).setPassword(value);
  }

  async get(reference: string): Promise<string> {
    const value = new Entry(service, secretAccount(reference)).getPassword();
    if (!value) throw new Error("secret not found");
    return value;
  }

  async delete(reference: string): Promise<void> {
    new Entry(service, secretAccount(reference)).deleteCredential();
  }
}

class MacOsKeychainSecretStore implements SecretStore {
  async set(reference: string, value: string): Promise<void> {
    if (value === "") throw new InvalidSecretReferenceError();
    const account = secretAccount(reference);
    const encoded = encodeGoKeyringValue(value);
    const command = `add-generic-password -U -s ${shellQuote(service)} -a ${shellQuote(account)} -w ${shellQuote(encoded)}\n`;
    await runSecurityInteractive(command);
  }

  async get(reference: string): Promise<string> {
    const account = secretAccount(reference);
    const { stdout } = await execFileAsync("/usr/bin/security", ["find-generic-password", "-s", service, "-wa", account], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 15_000
    });
    return decodeGoKeyringValue(stdout.trim());
  }

  async delete(reference: string): Promise<void> {
    const account = secretAccount(reference);
    await execFileAsync("/usr/bin/security", ["delete-generic-password", "-s", service, "-a", account], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: 15_000
    });
  }
}

const execFileAsync = promisify(execFile);
const goBase64Prefix = "go-keyring-base64:";
const goHexPrefix = "go-keyring-encoded:";

export function encodeGoKeyringValue(value: string): string {
  return `${goBase64Prefix}${Buffer.from(value, "utf8").toString("base64")}`;
}

export function decodeGoKeyringValue(value: string): string {
  if (value.startsWith(goBase64Prefix)) return Buffer.from(value.slice(goBase64Prefix.length), "base64").toString("utf8");
  if (value.startsWith(goHexPrefix)) return Buffer.from(value.slice(goHexPrefix.length), "hex").toString("utf8");
  return value;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

async function runSecurityInteractive(input: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("/usr/bin/security", ["-i"], { stdio: ["pipe", "ignore", "pipe"], shell: false });
    let errorOutput = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); }, 15_000);
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", chunk => { errorOutput += String(chunk); });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(errorOutput.trim() || `security exited with ${code ?? 1}`));
    });
    child.stdin.end(input);
  });
}

export function secretAccount(reference: string): string {
  if (
    !reference.startsWith(referencePrefix) ||
    reference.length <= referencePrefix.length ||
    reference.length > 256 ||
    /[\r\n\0]/u.test(reference)
  ) {
    throw new InvalidSecretReferenceError();
  }
  return reference.slice(referencePrefix.length);
}

export class MemorySecretStore implements SecretStore {
  readonly values = new Map<string, string>();

  async set(reference: string, value: string): Promise<void> {
    secretAccount(reference);
    if (value === "") {
      throw new InvalidSecretReferenceError();
    }
    this.values.set(reference, value);
  }

  async get(reference: string): Promise<string> {
    secretAccount(reference);
    const value = this.values.get(reference);
    if (!value) {
      throw new Error("secret not found");
    }
    return value;
  }

  async delete(reference: string): Promise<void> {
    secretAccount(reference);
    this.values.delete(reference);
  }
}
