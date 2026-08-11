import { access, readFile } from "node:fs/promises";
import path from "node:path";

const manifest = JSON.parse(await readFile(path.resolve("package.json"), "utf8")) as { bin?: Record<string, string> };
const binary = manifest.bin?.["agent-identity"];
if (!binary) {
  throw new Error("package.json does not expose agent-identity");
}
await access(path.resolve(binary));
process.stdout.write("package metadata and built CLI entrypoint are present\n");
