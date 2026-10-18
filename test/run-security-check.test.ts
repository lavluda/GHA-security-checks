import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runSecurityCheck } from "../src/index.js";
import { runnerReturning, tempProject } from "./helpers.js";

describe("runSecurityCheck", () => {
  it("runs scanners, applies policy and writes all three reports", async () => {
    const cwd = await tempProject({ ".env": "TOKEN=abc\n" });

    const { result, reports } = await runSecurityCheck({
      cwd,
      toolRunner: runnerReturning(127),
      overrides: { mode: "strict" }
    });

    expect(result.failed).toBe(true);
    expect(result.findings.some((f) => f.id === "secret.file..env")).toBe(true);
    for (const path of Object.values(reports)) {
      expect(existsSync(path as string)).toBe(true);
    }
    const sarif = JSON.parse(readFileSync(join(cwd, "security-results.sarif"), "utf8"));
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it("can skip writing reports and honours output overrides", async () => {
    const cwd = await tempProject({ ".env": "TOKEN=abc\n" });

    const none = await runSecurityCheck({ cwd, toolRunner: runnerReturning(127), writeReports: false });
    expect(none.reports).toEqual({});
    expect(existsSync(join(cwd, "security-results.json"))).toBe(false);

    const onlyJson = await runSecurityCheck({
      cwd,
      toolRunner: runnerReturning(127),
      overrides: { outputs: { json: "out/r.json", markdown: false, sarif: false } }
    });
    expect(Object.keys(onlyJson.reports)).toEqual(["json"]);
    expect(existsSync(join(cwd, "out", "r.json"))).toBe(true);
  });

  it("only enables the scanners the config asks for", async () => {
    const cwd = await tempProject({ ".env": "TOKEN=abc\n", "package.json": "{}" });
    const toolRunner = runnerReturning(0, "{}");

    const { result } = await runSecurityCheck({
      cwd,
      toolRunner,
      writeReports: false,
      overrides: { scanners: { php: false, node: false, osv: false, githubActions: false } }
    });

    expect(toolRunner.calls).toHaveLength(0);
    expect(result.findings.every((f) => f.scanner === "secret-scanner")).toBe(true);
  });
});
