import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { parseDurationMs, durationSeconds } from "../../src/core/duration.js";
import { asCliError, CliError, internalError, invalidInput } from "../../src/core/errors.js";
import { isRecord, permissionIds, readJsonFile, readLimitedStdin, readObjectFile, stringList, uniqueStrings } from "../../src/core/input.js";
import { inspectJwt, tokenSubject } from "../../src/core/jwt.js";
import { promptIfEmpty } from "../../src/core/prompt.js";
import { userConfigDirectory } from "../../src/storage/paths.js";

const directories: string[] = [];
afterEach(async () => Promise.all(directories.splice(0).map(directory => rm(directory, { recursive: true, force: true }))));

describe("core validation helpers", () => {
  it.each([
    ["1ms", 1], ["1.5s", 1_500], ["2m", 120_000], ["1h", 3_600_000]
  ] as const)("parses %s", (value, expected) => expect(parseDurationMs(value)).toBe(expected));

  it.each(["", "0s", "-1s", "1d", "999999999999999999999h"])("rejects duration %s", value => {
    expect(() => parseDurationMs(value)).toThrow();
  });

  it("converts duration to seconds", () => expect(durationSeconds("1500ms")).toBe(2));

  it("normalizes lists, permissions, and records", () => {
    expect(uniqueStrings([" read ", "", "read", "write"])).toEqual(["read", "write"]);
    expect(stringList(["a", 1, " a ", "b"])).toEqual(["a", "b"]);
    expect(stringList("a")).toEqual([]);
    expect(permissionIds([{ permission_id: "p1" }, null, { permission_id: 2 }, { permission_id: "p1" }])).toEqual(["p1"]);
    expect(permissionIds({})).toEqual([]);
    expect(isRecord({})).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
  });

  it("reads valid JSON/YAML objects and rejects invalid inputs", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "agent-identity-input-"));
    directories.push(directory);
    const json = path.join(directory, "input.json");
    const yaml = path.join(directory, "input.yaml");
    const invalid = path.join(directory, "invalid.txt");
    const scalar = path.join(directory, "scalar.yaml");
    await writeFile(json, '{"value":1}', "utf8");
    await writeFile(yaml, "value: 2\n", "utf8");
    await writeFile(invalid, "{", "utf8");
    await writeFile(scalar, "- one\n- two\n", "utf8");
    await expect(readJsonFile(json)).resolves.toEqual({ value: 1 });
    await expect(readObjectFile(yaml)).resolves.toEqual({ value: 2 });
    await expect(readJsonFile(invalid)).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(readObjectFile(scalar)).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("reads bounded stdin and rejects overflow", async () => {
    await expect(readLimitedStdin(Readable.from([" value \n"]), 20)).resolves.toBe("value");
    await expect(readLimitedStdin(Readable.from([Buffer.from("12345")]), 4)).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("prompts only for missing values", async () => {
    const output = new Collector();
    await expect(promptIfEmpty(Readable.from([]), output, "Name", "existing")).resolves.toBe("existing");
    await expect(promptIfEmpty(Readable.from(["answer\n"]), output, "Name", "")).resolves.toBe("answer");
    await expect(promptIfEmpty(Readable.from(["\n"]), output, "Name", "")).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("classifies known, Error, and unknown failures", () => {
    const known = new CliError({ code: "KNOWN", message: "known", exitCode: 2 });
    expect(asCliError(known)).toBe(known);
    expect(asCliError(new Error("boom"))).toMatchObject({ code: "CLI_INTERNAL_ERROR", message: "boom" });
    expect(asCliError(1)).toMatchObject({ code: "CLI_INTERNAL_ERROR", message: "unexpected CLI failure" });
    expect(invalidInput("bad", { next: "retry" })).toMatchObject({ remediation: { next: "retry" } });
    expect(internalError("internal")).toMatchObject({ exitCode: 9 });
  });

  it("rejects malformed JWT variants", () => {
    expect(() => inspectJwt("opaque")).toThrow("compact JWT");
    expect(() => inspectJwt("e30.W10.signature")).toThrow("invalid JSON");
    expect(tokenSubject(`${Buffer.from("{}").toString("base64url")}.${Buffer.from('{"sub":1}').toString("base64url")}.x`)).toBe("");
  });

  it("covers config directory overrides and missing Windows APPDATA", () => {
    expect(userConfigDirectory({ AGENT_IDENTITY_CONFIG_DIR: " /custom " }, "linux", "/home/a")).toBe("/custom");
    expect(() => userConfigDirectory({}, "win32", "C:\\Users\\a")).toThrow("APPDATA");
  });
});

class Collector extends Writable {
  override _write(_chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    callback();
  }
}
