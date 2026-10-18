import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config.js";
import type { Finding } from "../src/core/finding.js";
import type { Scanner } from "../src/core/scanner.js";
import { ScannerEngine } from "../src/core/scanner-engine.js";
import { applySuppressions } from "../src/core/suppressions.js";
import { runnerReturning } from "./helpers.js";

const base: Finding = {
  id: "workflow.pull-request-target..github/workflows/a.yml",
  title: "t",
  description: "d",
  category: "workflow-risk",
  severity: "high",
  scanner: "s",
  status: "open",
  location: { file: ".github/workflows/a.yml" }
};

describe("applySuppressions", () => {
  it("suppresses by exact id and records the reason", () => {
    const [result] = applySuppressions([base], [{ id: base.id, reason: "accepted" }]);
    expect(result?.status).toBe("suppressed");
    expect(result?.metadata).toMatchObject({ suppressed: true, suppressionReason: "accepted" });
  });

  it("suppresses by category and by path glob", () => {
    const secret: Finding = { ...base, id: "s1", category: "secret", location: { file: "docs/sample/.env" } };
    const result = applySuppressions(
      [base, secret],
      [{ category: "secret" }, { path: ".github/**/*.yml" }]
    );
    expect(result.map((f) => f.status)).toEqual(["suppressed", "suppressed"]);
  });

  it("requires every specified field to match", () => {
    const result = applySuppressions([base], [{ id: base.id, category: "secret" }]);
    expect(result[0]?.status).toBe("open");
  });

  it("ignores empty entries and non-open findings", () => {
    const skipped: Finding = { ...base, status: "skipped" };
    expect(applySuppressions([base], [{ reason: "no selector" }])[0]?.status).toBe("open");
    expect(applySuppressions([skipped], [{ id: skipped.id }])[0]?.status).toBe("skipped");
  });
});

describe("ScannerEngine with suppressions", () => {
  it("suppressed findings no longer fail the policy", async () => {
    const scanner: Scanner = { name: "fake", scan: async () => [base] };
    const run = async (suppressions: Array<{ id?: string }>) => {
      const config = loadConfig({ cwd: process.cwd(), overrides: { mode: "fail-on-high", suppressions } });
      return new ScannerEngine([scanner]).run({ cwd: process.cwd(), config, toolRunner: runnerReturning(0) });
    };

    expect((await run([])).failed).toBe(true);
    const suppressed = await run([{ id: base.id }]);
    expect(suppressed.failed).toBe(false);
    expect(suppressed.findings[0]?.status).toBe("suppressed");
  });
});
