import { Entry } from "@napi-rs/keyring";
import { InvalidSecretReferenceError, secretAccount, type SecretStore } from "./secret-store.js";

const service = "genauth-agent-cli";

export function createPlatformSecretStore(_platform: NodeJS.Platform): SecretStore {
  return new NativeKeychainSecretStore();
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
