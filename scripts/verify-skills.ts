import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { createProgram } from "../src/cli/create-program.js";

const skillRoot = path.resolve(process.argv[2] ?? "../genauth-agent-skill");
const markdownFiles = (await walk(skillRoot)).filter(file => file.endsWith(".md"));
const contract = createProgram().registry.export();
const commands = new Map(contract.commands.map(command => [command.path, command]));
const globalValueFlags = new Set(["--profile", "--timeout", "--endpoint", "--output", "--request-id", "--correlation-id", "--proxy", "--ca-file"]);
const globalBooleanFlags = new Set(["--no-browser", "--non-interactive", "--quiet", "--debug", "--allow-insecure-localhost", "--help", "-h"]);
const failures: string[] = [];
let invocationCount = 0;
const coveredCommands = new Set<string>();

for (const file of markdownFiles) {
  const relative = path.relative(skillRoot, file);
  const content = await readFile(file, "utf8");
  if (relative.endsWith("SKILL.md")) {
    const directory = path.basename(path.dirname(file));
    const name = /^name:\s*(.+)$/mu.exec(content)?.[1]?.trim();
    const version = /^version:\s*(.+)$/mu.exec(content)?.[1]?.trim();
    if (name !== directory) failures.push(`${relative}: metadata name ${name ?? "missing"} does not match ${directory}`);
    if (version !== "2.0.0") failures.push(`${relative}: version must be 2.0.0`);
  }
  if (/(^|\s)curl\s|\/api\/v3\/agent-identity|\/api\/v3\/agent-runtime/mu.test(content)) {
    failures.push(`${relative}: direct API invocation or route is forbidden`);
  }
  for (const invocation of extractInvocations(content)) {
    invocationCount += 1;
    const result = validateInvocation(invocation);
    if (result.error) failures.push(`${relative}: ${result.error}: ${invocation}`);
    if (result.command) coveredCommands.add(result.command);
  }
}

if (invocationCount < 70) failures.push(`only ${invocationCount} CLI invocations were parsed; expected at least 70`);
if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`FAIL ${failure}\n`);
  process.stderr.write(`SUMMARY files=${markdownFiles.length} invocations=${invocationCount} covered=${coveredCommands.size} failures=${failures.length}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`SUMMARY files=${markdownFiles.length} invocations=${invocationCount} covered=${coveredCommands.size} failures=0\n`);
}

function validateInvocation(invocation: string): { command?: string; error?: string } {
  const tokens = tokenize(invocation);
  if (tokens[0] !== "genauth-agent") return { error: "could not tokenize CLI invocation" };
  const remaining: string[] = [];
  const flags: string[] = [];
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index] ?? "";
    if (globalValueFlags.has(token)) { index += 1; continue; }
    if (globalBooleanFlags.has(token)) continue;
    if (token.startsWith("--")) {
      flags.push(token.split("=")[0] ?? token);
      if (!token.includes("=") && index + 1 < tokens.length && !(tokens[index + 1] ?? "").startsWith("--")) index += 1;
      continue;
    }
    if (/^[|;&]/u.test(token)) break;
    remaining.push(token.replace(/[.,:;)]$/u, ""));
  }
  if (remaining.length === 0 || remaining[0] === "--help") return {};
  const command = [...commands.keys()]
    .sort((left, right) => right.split(" ").length - left.split(" ").length)
    .find(pathValue => remaining.slice(0, pathValue.split(" ").length).join(" ") === pathValue);
  if (!command) return { error: `unknown commands/v2 path beginning with ${remaining.slice(0, 3).join(" ")}` };
  const allowed = new Set(commands.get(command)?.options.map(option => option.flags.match(/--[a-z0-9-]+/u)?.[0]).filter(Boolean));
  for (const flag of flags) {
    if (!allowed.has(flag)) return { command, error: `flag ${flag} is not declared for ${command}` };
  }
  return { command };
}

function extractInvocations(content: string): string[] {
  const segments: string[] = [];
  for (const match of content.matchAll(/```([^\n]*)\n([\s\S]*?)```/gu)) {
    const language = (match[1] ?? "").trim().split(/\s+/u)[0]?.toLowerCase() ?? "";
    if (["", "bash", "sh", "shell", "console"].includes(language)) segments.push(match[2] ?? "");
  }
  for (const match of content.matchAll(/`([^`\n]*genauth-agent[^`\n]*)`/gu)) segments.push(match[1] ?? "");
  const invocations: string[] = [];
  for (const segment of segments) {
    const normalized = segment.replace(/\\\s*\n\s*/gu, " ");
    for (const line of normalized.split("\n")) {
      const match = /(?<![-/A-Za-z0-9])genauth-agent(?=\s|$)(.*)$/u.exec(line);
      if (match) invocations.push(`genauth-agent${match[1] ?? ""}`.trim());
    }
  }
  return invocations;
}

function tokenize(value: string): string[] {
  const result: string[] = [];
  for (const match of value.matchAll(/"(?:\\.|[^"\\])*"|'(?:'\\''|[^'])*'|[^\s]+/gu)) {
    result.push((match[0] ?? "").replace(/^['"]|['"]$/gu, ""));
  }
  return result;
}

async function walk(directory: string): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...await walk(target));
    else result.push(target);
  }
  return result;
}
