import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  addSuppression,
  listSuppressions,
  removeSuppression,
  resolveConfigPath
} from "../src/core/config-editor.js";
import { tempProject } from "./helpers.js";

describe("config-editor", () => {
  it("creates the default config file when none exists", async () => {
    const cwd = await tempProject();
    expect(resolveConfigPath(cwd)).toBe(join(cwd, "gha-security-checks.yml"));

    const file = addSuppression(cwd, { id: "a", reason: "why" });
    expect(listSuppressions(cwd)).toEqual([{ id: "a", reason: "why" }]);
    expect(file).toBe(join(cwd, "gha-security-checks.yml"));
  });

  it("preserves comments and other settings when editing", async () => {
    const cwd = await tempProject({
      ".gha-security-checks.yml": "# keep me\nmode: strict\n"
    });
    addSuppression(cwd, { id: "x" });
    const text = readFileSync(join(cwd, ".gha-security-checks.yml"), "utf8");
    expect(text).toContain("# keep me");
    expect(text).toContain("mode: strict");
    expect(text).toContain("id: x");
  });

  it("removes suppressions by id and reports how many were removed", async () => {
    const cwd = await tempProject();
    addSuppression(cwd, { id: "a" });
    addSuppression(cwd, { id: "b" });
    addSuppression(cwd, { id: "a", path: "x/**" });

    const result = removeSuppression(cwd, "a");
    expect(result.removed).toBe(2);
    expect(listSuppressions(cwd)).toEqual([{ id: "b" }]);
    expect(removeSuppression(cwd, "missing").removed).toBe(0);
  });

  it("honours an explicit config path and tolerates a missing file", async () => {
    const cwd = await tempProject();
    expect(listSuppressions(cwd, "nope.yml")).toEqual([]);
    expect(removeSuppression(cwd, "a", "nope.yml").removed).toBe(0);

    writeFileSync(join(cwd, "custom.yml"), "suppressions:\n  - id: z\n");
    expect(listSuppressions(cwd, "custom.yml")).toEqual([{ id: "z" }]);
  });
});
