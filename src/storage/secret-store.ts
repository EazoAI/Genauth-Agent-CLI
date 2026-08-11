import { createPlatformSecretStore } from "./native-keychain.js";

const referencePrefix = "keychain://genauth-agent/";

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
    this.implementation = createPlatformSecretStore(platform);
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
