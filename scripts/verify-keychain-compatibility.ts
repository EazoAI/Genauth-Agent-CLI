import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { KeychainSecretStore } from "../src/storage/secret-store.js";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "agent-identity-keychain-compat-"));
const reference = `keychain://agent-identity/compat/platform-${process.platform}-${process.pid}`;
const secrets = new KeychainSecretStore();

try {
  const baseline = path.join(temporaryRoot, "go-baseline");
  const archive = path.join(temporaryRoot, "go-baseline.tar");
  await run("git", ["archive", "--format=tar", "-o", archive, "go-baseline-v0.1.0"], repositoryRoot);
  await mkdir(baseline);
  await run("tar", ["-xf", archive, "-C", baseline]);
  const probeDirectory = path.join(baseline, "cmd", "keychain-compat-probe");
  await mkdir(probeDirectory, { recursive: true });
  await writeFile(path.join(probeDirectory, "main.go"), goProbeSource());
  const probe = path.join(temporaryRoot, process.platform === "win32" ? "keychain-compat-probe.exe" : "keychain-compat-probe");
  await run("go", ["build", "-trimpath", "-o", probe, "./cmd/keychain-compat-probe"], baseline);

  const nodeValue = JSON.stringify({ source: "node", platform: process.platform, value: "UTF-8 中文 ✓" });
  const goValue = JSON.stringify({ source: "go", platform: process.platform, value: "upgrade-and-rollback" });
  await secrets.set(reference, nodeValue);
  const readByGo = await run(probe, ["get", reference]);
  assertEqual(readByGo.stdout, nodeValue, "Go did not read the value written by Node");

  await run(probe, ["set", reference, goValue]);
  const readByNode = await secrets.get(reference);
  assertEqual(readByNode, goValue, "Node did not read the value written by Go");
  process.stdout.write(`Go/Node Keychain compatibility passed for ${process.platform}-${process.arch}\n`);
} finally {
  await secrets.delete(reference).catch(() => undefined);
  await rm(temporaryRoot, { recursive: true, force: true });
}

function assertEqual(actual: string, expected: string, message: string): void {
  if (actual !== expected) throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

async function run(command: string, arguments_: string[], cwd?: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, arguments_, { cwd, stdio: ["ignore", "pipe", "pipe"], shell: false, windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", chunk => { stdout += String(chunk); });
    child.stderr.on("data", chunk => { stderr += String(chunk); });
    child.once("error", reject);
    child.once("exit", code => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${command} ${arguments_.join(" ")} exited with ${code ?? 1}\n${stdout}\n${stderr}`));
    });
  });
}

function goProbeSource(): string {
  return `package main

import (
	"fmt"
	"os"

	"github.com/Authing/genauth-agent-cli/internal/cli/secretstore"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: keychain-compat-probe get <reference> | set <reference> <value>")
		os.Exit(2)
	}
	store := secretstore.New()
	var err error
	switch os.Args[1] {
	case "get":
		var value string
		value, err = store.Get(os.Args[2])
		if err == nil {
			fmt.Print(value)
		}
	case "set":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		err = store.Set(os.Args[2], os.Args[3])
	default:
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`;
}
