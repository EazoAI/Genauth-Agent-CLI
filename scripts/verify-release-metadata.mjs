#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = (await readFile(path.join(repositoryRoot, "VERSION"), "utf8")).trim();
assert.match(version, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/, "VERSION must contain a semantic version");

const manifestPaths = [
  "npm/package.json",
  "npm/agent-identity-cli/package.json",
  "npm/platforms/darwin-arm64/package.json",
  "npm/platforms/darwin-x64/package.json",
  "npm/platforms/linux-arm64/package.json",
  "npm/platforms/linux-x64/package.json",
  "npm/platforms/win32-x64/package.json"
];

for (const relativePath of manifestPaths) {
  const manifest = JSON.parse(await readFile(path.join(repositoryRoot, relativePath), "utf8"));
  assert.equal(manifest.version, version, `${relativePath} version must match VERSION`);
}

const launcher = JSON.parse(await readFile(path.join(repositoryRoot, "npm/agent-identity-cli/package.json"), "utf8"));
for (const [packageName, dependencyVersion] of Object.entries(launcher.optionalDependencies)) {
  assert.equal(dependencyVersion, version, `${packageName} version must match VERSION`);
}

const rootSource = await readFile(path.join(repositoryRoot, "internal/cli/command/root.go"), "utf8");
assert.match(rootSource, new RegExp(`var Version = ["']${version.replaceAll(".", "\\.")}["']`), "Go development version must match VERSION");

console.log(`release metadata is synchronized at ${version}`);
