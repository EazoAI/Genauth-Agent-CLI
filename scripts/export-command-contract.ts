import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { createProgram } from "../src/cli/create-program.js";

const { registry } = createProgram();
const target = path.resolve("dist", "contracts", "commands-v2.json");
await mkdir(path.dirname(target), { recursive: true });
await writeFile(target, `${JSON.stringify(registry.export(), null, 2)}\n`, "utf8");
process.stdout.write(`${target}\n`);
