#!/usr/bin/env node

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(repositoryRoot, "package.json"), "utf8"));
const version = manifest.version;

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "agent-identity-npm-smoke-"));
try {
  const packDirectory = path.join(temporaryRoot, "packs");
  const installDirectory = path.join(temporaryRoot, "install");
  await mkdir(packDirectory, { recursive: true });
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const execute = (command, args, options = {}) => spawnSync(command, args, { encoding: "utf8", ...options });
  const run = (command, args, options = {}) => {
    const result = execute(command, args, options);
    if (result.status !== 0) {
      throw new Error(`${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`);
    }
    return result.stdout.trim();
  };

  const archiveName = run(npm, ["pack", repositoryRoot, "--pack-destination", packDirectory, "--silent"]);
  const archive = path.join(packDirectory, archiveName.split(/\r?\n/u).at(-1));
  run(npm, ["install", "--global", "--prefix", installDirectory, archive]);

  const command = process.platform === "win32"
    ? path.join(installDirectory, "agent-identity.cmd")
    : path.join(installDirectory, "bin", "agent-identity");
  const output = run(command, ["--output", "json", "version"]);
  const envelope = JSON.parse(output);
  assert.equal(envelope.kind, "Version");
  assert.equal(envelope.data.cli_version, version);
  assert.equal(envelope.data.runtime, "node");
  assert.equal(envelope.data.command_contract, "agent-identity.commands/v2");
  const help = run(command, ["--help"]);
  assert.match(help, /GenAuth Agent Identity/u);
  for (const shell of ["bash", "zsh", "fish", "powershell"]) {
    assert.ok(run(command, ["completion", shell]).length > 20, `${shell} completion must be generated`);
  }
  const invalid = execute(command, ["--output", "json", "completion", "invalid"]);
  assert.equal(invalid.status, 2);
  assert.equal(JSON.parse(invalid.stderr).error.code, "INVALID_ARGUMENT");
  console.log(`npm pack/install smoke test passed for ${process.platform}-${process.arch} (${version})`);
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
