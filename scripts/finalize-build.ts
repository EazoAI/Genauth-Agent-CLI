import { chmod } from "node:fs/promises";
import path from "node:path";

await chmod(path.resolve("dist/bin/genauth-agent.js"), 0o755);
