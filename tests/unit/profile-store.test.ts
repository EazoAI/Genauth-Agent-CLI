import { mkdtemp, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ProfileStore, validateEndpoint, validateProfileName } from "../../src/storage/profile-store.js";
import { userConfigDirectory } from "../../src/storage/paths.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(temporaryDirectories.splice(0).map(directory => rm(directory, { recursive: true, force: true })));
});

describe("profile store", () => {
  it("round trips a Go-compatible profile with private permissions", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "agent-identity-profile-"));
    temporaryDirectories.push(directory);
    const store = new ProfileStore(path.join(directory, "config.json"));
    await store.save({
      api_version: "agent-identity.cli/v1",
      current_profile: "acme",
      profiles: {
        acme: {
          endpoint: "https://genauth.example.com",
          login_type: "tenant_admin",
          selected_user_pool_id: "pool-1",
          secret_ref: "keychain://agent-identity/session/acme"
        }
      }
    });
    expect((await store.load()).profiles.acme?.selected_user_pool_id).toBe("pool-1");
    if (process.platform !== "win32") {
      expect((await stat(store.filePath)).mode & 0o777).toBe(0o600);
    }
  });

  it("returns an empty config when the file is absent", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "agent-identity-profile-"));
    temporaryDirectories.push(directory);
    const config = await new ProfileStore(path.join(directory, "missing.json")).load();
    expect(config).toEqual({ api_version: "agent-identity.cli/v1", current_profile: "", profiles: {} });
  });

  it.each([
    "http://public.example.com",
    "https://example.com/path",
    "https://user:secret@example.com",
    "file:///tmp/socket"
  ])("rejects invalid endpoint %s", endpoint => {
    expect(() => validateEndpoint(endpoint)).toThrow();
  });

  it.each(["default", "tenant.admin", "pool_1", "a-b"])("accepts profile name %s", name => {
    expect(() => validateProfileName(name)).not.toThrow();
  });

  it("matches Go user config directory rules", () => {
    expect(userConfigDirectory({}, "darwin", "/Users/alice")).toBe("/Users/alice/Library/Application Support/agent-identity");
    expect(userConfigDirectory({}, "linux", "/home/alice")).toBe("/home/alice/.config/agent-identity");
    expect(userConfigDirectory({ XDG_CONFIG_HOME: "/config" }, "linux", "/home/alice")).toBe("/config/agent-identity");
    expect(userConfigDirectory({ APPDATA: "C:\\Users\\alice\\AppData\\Roaming" }, "win32", "C:\\Users\\alice")).toContain("agent-identity");
  });
});
