import { describe, expect, it } from "vitest";
import {
  CLI_API_VERSION,
  parseOutputFormat,
  serializeFailure,
  serializeSuccess
} from "../../src/core/output.js";

describe("output contract", () => {
  it.each(["json", "yaml", "table"] as const)("serializes %s success", format => {
    const output = serializeSuccess(format, "Agent", { id: "agt-1", status: "ACTIVE" }, "req-1");
    expect(output).toContain("Agent");
    expect(output).toContain("agt-1");
    if (format === "json") {
      expect(JSON.parse(output)).toEqual({
        api_version: CLI_API_VERSION,
        kind: "Agent",
        data: { id: "agt-1", status: "ACTIVE" },
        request_id: "req-1",
        warnings: []
      });
    }
  });

  it("sorts table object keys", () => {
    const output = serializeSuccess("table", "Agent", { z: 1, a: 2 });
    expect(output.indexOf("A\t2")).toBeLessThan(output.indexOf("Z\t1"));
  });

  it("emits failure as stable JSON without absent remediation", () => {
    expect(JSON.parse(serializeFailure("FORBIDDEN", "not allowed", "req-1"))).toEqual({
      api_version: CLI_API_VERSION,
      error: { code: "FORBIDDEN", message: "not allowed" },
      request_id: "req-1"
    });
  });

  it("rejects an unknown output format", () => {
    expect(() => parseOutputFormat("xml")).toThrow("output must be table, json, or yaml");
  });
});
