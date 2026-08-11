import { Entry } from "@napi-rs/keyring";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  decodeGoKeyringValue,
  encodeGoKeyringValue,
  InvalidSecretReferenceError,
  secretAccount,
  type SecretStore
} from "./secret-store.js";

const service = "agent-identity-cli";
const execFileAsync = promisify(execFile);

export function createPlatformSecretStore(platform: NodeJS.Platform): SecretStore {
  return platform === "darwin" ? new MacOsKeychainSecretStore() : new NativeKeychainSecretStore();
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
