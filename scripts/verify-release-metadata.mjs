#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = (await readFile(path.join(repositoryRoot, "VERSION"), "utf8")).trim();
assert.match(version, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/, "VERSION must contain a semantic version");

const manifest = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
const lock = JSON.parse(await readFile(path.join(repositoryRoot, "package-lock.json"), "utf8"));
assert.equal(manifest.name, "@eazo/genauth-agent-cli", "package.json must use the public npm package name");
assert.equal(lock.name, manifest.name, "package-lock package name must match package.json");
assert.equal(lock.packages?.[""]?.name, manifest.name, "package-lock root package name must match package.json");
assert.equal(manifest.version, version, "package.json version must match VERSION");
assert.equal(lock.version, version, "package-lock.json version must match VERSION");
assert.equal(lock.packages?.[""]?.version, version, "package-lock root version must match VERSION");
assert.equal(manifest.type, "module", "package must remain ESM");
assert.equal(manifest.bin?.["genauth-agent"], "dist/bin/genauth-agent.js", "package must expose the Node CLI");
assert.match(manifest.engines?.node ?? "", />=22/u, "Node 22 or newer must be required");

const rootSource = await readFile(path.join(repositoryRoot, "src/cli/commands/system.ts"), "utf8");
assert.match(rootSource, new RegExp(`CLI_VERSION = ["']${version.replaceAll(".", "\\.")}["']`), "Node CLI version must match VERSION");

console.log(`Node release metadata is synchronized at ${version}`);
