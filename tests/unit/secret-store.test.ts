import { describe, expect, it } from "vitest";
import { decodeGoKeyringValue, encodeGoKeyringValue, MemorySecretStore, secretAccount } from "../../src/storage/secret-store.js";

describe("secret references", () => {
  it("keeps the Go keychain service account suffix", () => {
    expect(secretAccount("keychain://agent-identity/session/acme")).toBe("session/acme");
  });

  it.each([
    "plain-text",
    "keychain://agent-identity/",
    `keychain://agent-identity/${"a".repeat(300)}`,
    "keychain://agent-identity/bad\nref"
  ])("rejects invalid reference %s", reference => {
    expect(() => secretAccount(reference)).toThrow("invalid secret reference");
  });

  it("supports set, get, and delete without exposing values", async () => {
    const store = new MemorySecretStore();
    const reference = "keychain://agent-identity/session/acme";
    await store.set(reference, "secret-value");
    expect(await store.get(reference)).toBe("secret-value");
    await store.delete(reference);
    await expect(store.get(reference)).rejects.toThrow("secret not found");
  });

  it("matches the Go macOS keyring base64 encoding", () => {
    const encoded = encodeGoKeyringValue("line one\nline two 中文");
    expect(encoded).toBe("go-keyring-base64:bGluZSBvbmUKbGluZSB0d28g5Lit5paH");
    expect(decodeGoKeyringValue(encoded)).toBe("line one\nline two 中文");
  });

  it("decodes the legacy Go hex keyring prefix", () => {
    expect(decodeGoKeyringValue("go-keyring-encoded:736563726574")).toBe("secret");
  });
});
