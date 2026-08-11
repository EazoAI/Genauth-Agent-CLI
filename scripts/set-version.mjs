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

for (const relativePath of ["package.json", "package-lock.json"]) {
  const manifestPath = path.join(repositoryRoot, relativePath);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.version = version;
  if (relativePath === "package-lock.json" && manifest.packages?.[""]) manifest.packages[""].version = version;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

const rootPath = path.join(repositoryRoot, "src/cli/commands/system.ts");
const rootSource = await readFile(rootPath, "utf8");
const versionPattern = /CLI_VERSION = "[^"]+"/;
if (!versionPattern.test(rootSource)) {
  throw new Error("unable to find the Node CLI_VERSION constant");
}
const updatedRootSource = rootSource.replace(versionPattern, `CLI_VERSION = "${version}"`);
await writeFile(rootPath, updatedRootSource);

console.log(`updated release metadata to ${version}`);
