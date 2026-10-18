import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config.js";
import { OsvScanner } from "../src/scanners/osv/osv-scanner.js";
import { runnerReturning, tempProject } from "./helpers.js";

// Shape produced by `osv-scanner scan source --format=json` (v2).
function osvOutput(cwd: string) {
  return {
    results: [
      {
        source: { path: `${cwd}/package-lock.json`, type: "lockfile" },
        packages: [
          {
            package: { name: "lodash", version: "4.17.20", ecosystem: "npm" },
            vulnerabilities: [
              {
                id: "GHSA-35jh-r3h4-6jhm",
                aliases: ["CVE-2021-23337"],
                summary: "Command Injection in lodash",
                details: "Details",
                database_specific: { severity: "HIGH" },
                severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
                affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }]
              }
            ],
            groups: [{ ids: ["GHSA-35jh-r3h4-6jhm"], aliases: ["CVE-2021-23337"], max_severity: "7.2" }]
          }
        ]
      }
    ]
  };
}

describe("OsvScanner", () => {
  it("parses osv-scanner v2 output and uses the numeric group severity", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });
    const toolRunner = runnerReturning(1, osvOutput(cwd));

    const findings = await new OsvScanner().scan({ cwd, config, toolRunner });

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: "osv.lodash.GHSA-35jh-r3h4-6jhm",
      ruleId: "osv.GHSA-35jh-r3h4-6jhm",
      severity: "high",
      packageName: "lodash",
      installedVersion: "4.17.20",
      fixedVersion: "4.17.21",
      status: "open",
      location: { file: "package-lock.json" }
    });
  });

  it("maps CVSS scores to severities", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });
    const severities: Record<string, string> = { "9.8": "critical", "7.0": "high", "5.0": "medium", "2.1": "low" };

    for (const [score, expected] of Object.entries(severities)) {
      const output = osvOutput(cwd);
      output.results[0]!.packages[0]!.groups[0]!.max_severity = score;
      const findings = await new OsvScanner().scan({ cwd, config, toolRunner: runnerReturning(1, output) });
      expect(findings[0]?.severity).toBe(expected);
    }
  });

  it("falls back to the database severity label, then medium", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });

    const noGroups = osvOutput(cwd);
    noGroups.results[0]!.packages[0]!.groups = [];
    expect(
      (await new OsvScanner().scan({ cwd, config, toolRunner: runnerReturning(1, noGroups) }))[0]?.severity
    ).toBe("high");

    const nothing = osvOutput(cwd);
    nothing.results[0]!.packages[0]!.groups = [];
    nothing.results[0]!.packages[0]!.vulnerabilities[0]!.database_specific = {};
    expect(
      (await new OsvScanner().scan({ cwd, config, toolRunner: runnerReturning(1, nothing) }))[0]?.severity
    ).toBe("medium");
  });

  it("de-duplicates the same vulnerability reported from several lockfiles", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });
    const output = osvOutput(cwd);
    output.results.push(structuredClone(output.results[0]!));

    const findings = await new OsvScanner().scan({ cwd, config, toolRunner: runnerReturning(1, output) });
    expect(findings).toHaveLength(1);
  });

  it("returns no findings when osv-scanner finds no sources (exit 128)", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });
    const findings = await new OsvScanner().scan({
      cwd,
      config,
      toolRunner: runnerReturning(128, "", "No package sources found")
    });
    expect(findings).toEqual([]);
  });

  it("reports skipped tooling findings for missing, timed-out and garbled runs", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });
    const run = (exit: number, out = "") =>
      new OsvScanner().scan({ cwd, config, toolRunner: runnerReturning(exit, out, "stderr text") });

    expect((await run(127))[0]).toMatchObject({ id: "tooling.osv-scanner.missing", status: "skipped" });
    expect((await run(124))[0]).toMatchObject({ id: "tooling.osv-scanner.timeout", status: "skipped" });
    expect((await run(1, "not json"))[0]).toMatchObject({
      id: "tooling.osv-scanner.parse-failed",
      description: "stderr text"
    });
  });

  it("in diff mode only runs when a lockfile (at any depth) changed", async () => {
    const cwd = await tempProject();
    const config = loadConfig({ cwd });

    const skipped = runnerReturning(1, osvOutput(cwd));
    await new OsvScanner().scan({ cwd, config, toolRunner: skipped, changedFiles: new Set(["src/a.ts"]) });
    expect(skipped.calls).toHaveLength(0);

    const ran = runnerReturning(1, osvOutput(cwd));
    await new OsvScanner().scan({
      cwd,
      config,
      toolRunner: ran,
      changedFiles: new Set(["packages/web/package-lock.json"])
    });
    expect(ran.calls).toHaveLength(1);
  });
});
