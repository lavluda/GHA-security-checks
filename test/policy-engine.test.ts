import { describe, expect, it } from "vitest";
import { loadConfig, type PolicyMode } from "../src/core/config.js";
import { evaluatePolicy } from "../src/core/policy-engine.js";
import type { Finding } from "../src/core/finding.js";

function make(overrides: Partial<Finding>): Finding {
  return {
    id: "test.finding",
    title: "Finding",
    description: "A finding.",
    category: "vulnerability",
    severity: "high",
    scanner: "test",
    status: "open",
    ...overrides
  };
}

function decide(mode: PolicyMode, findings: Finding[], failOn?: { severity?: Finding["severity"]; categories?: Finding["category"][] }) {
  const config = loadConfig({ cwd: process.cwd(), overrides: { mode, failOn } });
  return evaluatePolicy(findings, config);
}

describe("evaluatePolicy", () => {
  it("never fails in audit, warn or diff mode", () => {
    for (const mode of ["audit", "warn", "diff"] as const) {
      expect(decide(mode, [make({ severity: "critical" })]).failed).toBe(false);
    }
  });

  it("fail-on-high fails on high and critical only", () => {
    expect(decide("fail-on-high", [make({ severity: "high" })]).failed).toBe(true);
    expect(decide("fail-on-high", [make({ severity: "critical" })]).failed).toBe(true);
    expect(decide("fail-on-high", [make({ severity: "medium" })]).failed).toBe(false);
  });

  it("fail-on-critical fails on critical only", () => {
    expect(decide("fail-on-critical", [make({ severity: "high" })]).failed).toBe(false);
    expect(decide("fail-on-critical", [make({ severity: "critical" })]).failed).toBe(true);
  });

  it("strict fails on medium+ and on any secret or workflow-risk finding", () => {
    expect(decide("strict", [make({ severity: "medium" })]).failed).toBe(true);
    expect(decide("strict", [make({ severity: "low" })]).failed).toBe(false);
    expect(decide("strict", [make({ severity: "info", category: "secret" })]).failed).toBe(true);
    expect(decide("strict", [make({ severity: "low", category: "workflow-risk" })]).failed).toBe(true);
  });

  it("custom honours the severity threshold and category filter", () => {
    const outdated = make({ severity: "medium", category: "outdated-dependency" });
    expect(decide("custom", [outdated], { severity: "medium" }).failed).toBe(true);
    expect(decide("custom", [outdated], { severity: "high" }).failed).toBe(false);
    expect(decide("custom", [outdated], { severity: "low", categories: ["secret"] }).failed).toBe(false);
    expect(decide("custom", [outdated], { severity: "low", categories: ["outdated-dependency"] }).failed).toBe(true);
  });

  it("ignores suppressed, skipped and fixed findings", () => {
    for (const status of ["suppressed", "skipped", "fixed"] as const) {
      expect(decide("strict", [make({ status, severity: "critical" })]).failed).toBe(false);
    }
  });

  it("reports the blocking findings and passes with none", () => {
    const decision = decide("fail-on-high", [make({ id: "a" }), make({ id: "b", severity: "low" })]);
    expect(decision.blockingFindings.map((f) => f.id)).toEqual(["a"]);
    expect(decide("strict", []).failed).toBe(false);
  });
});
