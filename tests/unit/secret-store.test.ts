import { describe, expect, it } from "vitest";
import { MemorySecretStore, secretAccount } from "../../src/storage/secret-store.js";

describe("secret references", () => {
  it("extracts the keychain service account suffix", () => {
    expect(secretAccount("keychain://genauth-agent/session/acme")).toBe("session/acme");
  });

  it.each([
    "plain-text",
    "keychain://genauth-agent/",
    `keychain://genauth-agent/${"a".repeat(300)}`,
    "keychain://genauth-agent/bad\nref"
  ])("rejects invalid reference %s", reference => {
    expect(() => secretAccount(reference)).toThrow("invalid secret reference");
  });

  it("supports set, get, and delete without exposing values", async () => {
    const store = new MemorySecretStore();
    const reference = "keychain://genauth-agent/session/acme";
    await store.set(reference, "secret-value");
    expect(await store.get(reference)).toBe("secret-value");
    await store.delete(reference);
    await expect(store.get(reference)).rejects.toThrow("secret not found");
  });
});
