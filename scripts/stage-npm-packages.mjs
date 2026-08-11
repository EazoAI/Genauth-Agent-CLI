#!/usr/bin/env node

import { chmod, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = (process.argv[2] || await readFile(path.join(repositoryRoot, "VERSION"), "utf8"))
  .trim()
  .replace(/^v/, "");

if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error(`invalid semantic version: ${version}`);
}

const targets = [
  ["darwin-arm64", "agent-identity"],
  ["darwin-x64", "agent-identity"],
  ["linux-arm64", "agent-identity"],
  ["linux-x64", "agent-identity"],
  ["win32-x64", "agent-identity.exe"]
];

async function updateManifest(manifestPath, mutate) {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.version = version;
  mutate?.(manifest);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

const launcherManifest = path.join(repositoryRoot, "npm", "agent-identity-cli", "package.json");
await updateManifest(launcherManifest, manifest => {
  for (const packageName of Object.keys(manifest.optionalDependencies)) {
    manifest.optionalDependencies[packageName] = version;
  }
});

await updateManifest(path.join(repositoryRoot, "npm", "package.json"));

for (const [platform, executable] of targets) {
  const packageDirectory = path.join(repositoryRoot, "npm", "platforms", platform);
  const binaryDirectory = path.join(packageDirectory, "bin");
  await updateManifest(path.join(packageDirectory, "package.json"));
  await mkdir(binaryDirectory, { recursive: true });
  await copyFile(
    path.join(repositoryRoot, "dist", platform, executable),
    path.join(binaryDirectory, executable)
  );
  await copyFile(
    path.join(repositoryRoot, "npm", "platforms", "README.md"),
    path.join(packageDirectory, "README.md")
  );
  if (platform !== "win32-x64") {
    await chmod(path.join(binaryDirectory, executable), 0o755);
  }
}

console.log(`staged npm packages for ${version}`);
