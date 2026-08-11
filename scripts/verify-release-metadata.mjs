#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
assert.match(manifest.version ?? "", /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/, "package.json must contain a semantic version");
assert.equal(manifest.name, "@eazo/genauth-agent-cli", "package.json must use the public npm package name");
assert.equal(manifest.type, "module", "package must remain ESM");
assert.equal(manifest.bin?.["genauth-agent"], "dist/bin/genauth-agent.js", "package must expose the Node CLI");
assert.match(manifest.engines?.node ?? "", />=22/u, "Node 22 or newer must be required");

console.log(`Node release metadata is valid at ${manifest.version}`);
