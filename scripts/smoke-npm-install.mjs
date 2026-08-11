#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = (await readFile(path.join(repositoryRoot, "VERSION"), "utf8")).trim();
const platform = `${process.platform}-${process.arch}`;
const supported = new Set(["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-x64"]);
if (!supported.has(platform)) {
  throw new Error(`npm smoke test does not support ${platform}`);
}

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "agent-identity-npm-smoke-"));
try {
  const packDirectory = path.join(temporaryRoot, "packs");
  const installDirectory = path.join(temporaryRoot, "install");
  await mkdir(packDirectory, { recursive: true });
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const run = (command, args, options = {}) => {
    const result = spawnSync(command, args, { encoding: "utf8", ...options });
    if (result.status !== 0) {
      throw new Error(`${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`);
    }
    return result.stdout.trim();
  };

  run(npm, ["pack", path.join(repositoryRoot, "npm", "platforms", platform), "--pack-destination", packDirectory, "--silent"]);
  run(npm, ["pack", path.join(repositoryRoot, "npm", "agent-identity-cli"), "--pack-destination", packDirectory, "--silent"]);

  const platformArchive = path.join(packDirectory, `authing-agent-identity-cli-${platform}-${version}.tgz`);
  const launcherArchive = path.join(packDirectory, `authing-agent-identity-cli-${version}.tgz`);
  run(npm, ["install", "--global", "--prefix", installDirectory, "--omit=optional", platformArchive, launcherArchive]);

  const command = process.platform === "win32"
    ? path.join(installDirectory, "agent-identity.cmd")
    : path.join(installDirectory, "bin", "agent-identity");
  const output = run(command, ["--output", "json", "version"]);
  const envelope = JSON.parse(output);
  assert.equal(envelope.kind, "Version");
  assert.equal(envelope.data.cli_version, version);
  console.log(`npm install smoke test passed for ${platform} (${version})`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
