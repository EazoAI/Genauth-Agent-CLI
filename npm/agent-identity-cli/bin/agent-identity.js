#!/usr/bin/env node

"use strict";

const { spawnSync } = require("node:child_process");

const PLATFORM_PACKAGES = Object.freeze({
  "darwin-arm64": "@authing/agent-identity-cli-darwin-arm64",
  "darwin-x64": "@authing/agent-identity-cli-darwin-x64",
  "linux-arm64": "@authing/agent-identity-cli-linux-arm64",
  "linux-x64": "@authing/agent-identity-cli-linux-x64",
  "win32-x64": "@authing/agent-identity-cli-win32-x64"
});

function platformPackage(platform = process.platform, arch = process.arch) {
  return PLATFORM_PACKAGES[`${platform}-${arch}`];
}

function binaryName(platform = process.platform) {
  return platform === "win32" ? "agent-identity.exe" : "agent-identity";
}

function resolveBinary(options = {}) {
  const platform = options.platform || process.platform;
  const arch = options.arch || process.arch;
  const resolver = options.resolver || require.resolve;
  const packageName = platformPackage(platform, arch);
  if (!packageName) {
    throw new Error(
      `unsupported platform: ${platform}-${arch}; supported platforms: ${Object.keys(PLATFORM_PACKAGES).join(", ")}`
    );
  }
  return resolver(`${packageName}/bin/${binaryName(platform)}`);
}

function launch(options = {}) {
  const stderr = options.stderr || process.stderr;
  let executable;
  try {
    executable = resolveBinary(options);
  } catch (error) {
    stderr.write(
      `agent-identity: ${error.message}\n` +
        "Reinstall without --omit=optional so npm can install the platform binary package.\n"
    );
    return 1;
  }

  const spawn = options.spawn || spawnSync;
  const args = options.args || process.argv.slice(2);
  const result = spawn(executable, args, { stdio: "inherit" });
  if (result.error) {
    stderr.write(`agent-identity: unable to start ${executable}: ${result.error.message}\n`);
    return 1;
  }
  if (result.signal) {
    stderr.write(`agent-identity: process terminated by ${result.signal}\n`);
    return 1;
  }
  return Number.isInteger(result.status) ? result.status : 1;
}

if (require.main === module) {
  process.exitCode = launch();
}

module.exports = { PLATFORM_PACKAGES, binaryName, launch, platformPackage, resolveBinary };
