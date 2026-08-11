import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      include: ["src/**/*.ts"],
      // Platform launch/browser/keyring adapters are exercised by npm and real
      // Keychain smoke gates; unit coverage focuses on deterministic logic.
      exclude: ["src/bin/**", "src/auth/browser.ts", "src/storage/native-keychain.ts"],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 75
      }
    }
  }
});
