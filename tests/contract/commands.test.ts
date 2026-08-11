import { describe, expect, it } from "vitest";
import { createProgram } from "../../src/cli/create-program.js";
import { COMMAND_CONTRACT } from "../../src/cli/manifest.js";

describe("commands/v2 manifest", () => {
  const contract = createProgram().registry.export();
  const paths = contract.commands.map(command => command.path);

  it("exports the v2 contract", () => expect(contract.command_contract).toBe(COMMAND_CONTRACT));
  it("contains 52 canonical leaf commands", () => expect(paths).toHaveLength(52));
  it("has no duplicate command path", () => expect(new Set(paths).size).toBe(paths.length));
  it.each([
    "profiles list",
    "auth select-user-pool",
    "agents capability submit",
    "agents lifecycle archive",
    "grants list",
    "providers call"
  ])("contains canonical command %s", path => expect(paths).toContain(path));
  it.each([
    "config list-profiles",
    "auth switch-user-pool",
    "agents submit",
    "agents delete",
    "authorizations list-grants",
    "api call"
  ])("does not publish legacy command %s", path => expect(paths).not.toContain(path));
  it("declares every option with long flags", () => {
    for (const command of contract.commands) {
      for (const option of command.options) expect(option.flags).toMatch(/^--[a-z]/u);
    }
  });
});
