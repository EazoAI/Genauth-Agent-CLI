"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  binaryName,
  launch,
  platformPackage,
  resolveBinary
} = require("../bin/agent-identity.js");

test("maps every supported npm platform to its binary package", () => {
  assert.equal(platformPackage("darwin", "arm64"), "@authing/agent-identity-cli-darwin-arm64");
  assert.equal(platformPackage("darwin", "x64"), "@authing/agent-identity-cli-darwin-x64");
  assert.equal(platformPackage("linux", "arm64"), "@authing/agent-identity-cli-linux-arm64");
  assert.equal(platformPackage("linux", "x64"), "@authing/agent-identity-cli-linux-x64");
  assert.equal(platformPackage("win32", "x64"), "@authing/agent-identity-cli-win32-x64");
  assert.equal(platformPackage("freebsd", "x64"), undefined);
});

test("uses the Windows executable suffix only on Windows", () => {
  assert.equal(binaryName("win32"), "agent-identity.exe");
  assert.equal(binaryName("linux"), "agent-identity");
});

test("resolves the executable from the selected platform package", () => {
  let requested;
  const resolved = resolveBinary({
    platform: "linux",
    arch: "x64",
    resolver(specifier) {
      requested = specifier;
      return "/tmp/platform-package/bin/agent-identity";
    }
  });
  assert.equal(requested, "@authing/agent-identity-cli-linux-x64/bin/agent-identity");
  assert.equal(resolved, "/tmp/platform-package/bin/agent-identity");
});

test("forwards arguments and preserves the child exit code", () => {
  let invocation;
  const status = launch({
    platform: "darwin",
    arch: "arm64",
    args: ["agents", "list", "--output", "json"],
    resolver: () => "/tmp/agent-identity",
    spawn(executable, args, options) {
      invocation = { executable, args, options };
      return { status: 23 };
    }
  });
  assert.deepEqual(invocation, {
    executable: "/tmp/agent-identity",
    args: ["agents", "list", "--output", "json"],
    options: { stdio: "inherit" }
  });
  assert.equal(status, 23);
});

test("reports an actionable error when optional platform packages are missing", () => {
  let message = "";
  const status = launch({
    platform: "linux",
    arch: "x64",
    resolver() {
      throw new Error("module not found");
    },
    stderr: { write(value) { message += value; } }
  });
  assert.equal(status, 1);
  assert.match(message, /module not found/);
  assert.match(message, /--omit=optional/);
});
