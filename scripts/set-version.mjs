#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = (process.argv[2] || "").replace(/^v/, "");
if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error("usage: node scripts/set-version.mjs <semantic-version>");
}

await writeFile(path.join(repositoryRoot, "VERSION"), `${version}\n`);

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
  const manifestPath = path.join(repositoryRoot, relativePath);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.version = version;
  if (manifest.optionalDependencies) {
    for (const packageName of Object.keys(manifest.optionalDependencies)) {
      manifest.optionalDependencies[packageName] = version;
    }
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

const rootPath = path.join(repositoryRoot, "internal/cli/command/root.go");
const rootSource = await readFile(rootPath, "utf8");
const versionPattern = /var Version = "[^"]+"/;
if (!versionPattern.test(rootSource)) {
  throw new Error("unable to find the Go development Version variable");
}
const updatedRootSource = rootSource.replace(versionPattern, `var Version = "${version}"`);
await writeFile(rootPath, updatedRootSource);

console.log(`updated release metadata to ${version}`);
