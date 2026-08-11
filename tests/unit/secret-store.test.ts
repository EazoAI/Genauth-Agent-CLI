import { describe, expect, it } from "vitest";
import { decodeGoKeyringValue, encodeGoKeyringValue, MemorySecretStore, secretAccount } from "../../src/storage/secret-store.js";
import {
  windowsCredentialPowerShell,
  WindowsCredentialManagerSecretStore,
  windowsCredentialTarget,
  type WindowsCredentialRunner
} from "../../src/storage/native-keychain.js";

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

  it("uses the exact Go Windows target and raw UTF-8 value contract", async () => {
    const calls: Array<{ action: string; payload: Record<string, string | undefined> }> = [];
    const value = "Windows compatibility 中文 ✓";
    const runner: WindowsCredentialRunner = async (action, payload) => {
      calls.push({ action, payload });
      return action === "get" ? Buffer.from(value, "utf8").toString("base64") : "";
    };
    const store = new WindowsCredentialManagerSecretStore(runner);
    const reference = "keychain://agent-identity/session/admin";

    await store.set(reference, value);
    expect(await store.get(reference)).toBe(value);
    await store.delete(reference);

    expect(windowsCredentialTarget("session/admin")).toBe("agent-identity-cli:session/admin");
    expect(calls).toEqual([
      {
        action: "set",
        payload: {
          target: "agent-identity-cli:session/admin",
          username: "session/admin",
          value_base64: Buffer.from(value, "utf8").toString("base64")
        }
      },
      {
        action: "get",
        payload: { target: "agent-identity-cli:session/admin", username: "session/admin" }
      },
      {
        action: "delete",
        payload: { target: "agent-identity-cli:session/admin", username: "session/admin" }
      }
    ]);
  });

  it("keeps Windows Credential Manager secrets off the PowerShell command text", () => {
    expect(windowsCredentialPowerShell).toContain("CredWriteW");
    expect(windowsCredentialPowerShell).toContain("System.Text.UTF8Encoding");
    expect(windowsCredentialPowerShell).toContain("Persist = 2");
    expect(windowsCredentialPowerShell).not.toContain("credential-secret");
  });
});
