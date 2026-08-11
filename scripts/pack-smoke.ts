import { execFile } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const manifest = JSON.parse(await readFile(path.resolve("package.json"), "utf8")) as { bin?: Record<string, string> };
const binary = manifest.bin?.["genauth-agent"];
if (!binary) {
  throw new Error("package.json does not expose genauth-agent");
}
await access(path.resolve(binary));
const { stdout } = await execFileAsync(npmCommand(), ["pack", "--dry-run", "--json", "--ignore-scripts"], {
  cwd: path.resolve("."),
  encoding: "utf8",
  maxBuffer: 8 * 1024 * 1024
});
const report = JSON.parse(stdout) as Array<{ files?: Array<{ path?: string }> }>;
const files = new Set((report[0]?.files ?? []).flatMap(item => item.path ? [item.path] : []));
for (const required of ["package.json", "README.md", "dist/bin/genauth-agent.js", "dist/contracts/commands-v2.json"]) {
  if (!files.has(required)) throw new Error(`npm tarball is missing ${required}`);
}
for (const forbidden of files) {
  if (forbidden.endsWith(".go") || forbidden === "go.mod" || forbidden.startsWith("npm/platforms/")) {
    throw new Error(`npm tarball contains obsolete Go/platform artifact ${forbidden}`);
  }
}
process.stdout.write(`npm tarball manifest verified (${files.size} files)\n`);

function npmCommand(): string {
  return process.platform === "win32" ? "npm.cmd" : "npm";
}
