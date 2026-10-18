import { mkdtemp } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { toSarif, writeSarifReport } from "../src/reporters/sarif.js";
import type { ScanResult } from "../src/core/finding.js";

const sampleResult: ScanResult = {
  mode: "audit",
  failed: false,
  generatedAt: "2026-01-01T00:00:00.000Z",
  findings: [
    {
      id: "test.high.finding",
      title: "High severity finding",
      description: "This is a high severity vulnerability.",
      category: "vulnerability",
      severity: "high",
      scanner: "test-scanner",
      status: "open",
      location: { file: "src/app.php", startLine: 10 },
      packageName: "vulnerable/package",
      installedVersion: "1.0.0",
      fixedVersion: "2.0.0"
    },
    {
      id: "test.critical.secret",
      title: "Critical secret",
      description: "A private key was detected.",
      category: "secret",
      severity: "critical",
      scanner: "secret-scanner",
      status: "open",
      location: { file: ".env", startLine: 3 }
    },
    {
      id: "test.medium.outdated",
      title: "Outdated dependency",
      description: "Package is outdated.",
      category: "outdated-dependency",
      severity: "medium",
      scanner: "composer-outdated",
      status: "open"
    },
    {
      id: "test.info.tooling",
      title: "Tool skipped",
      description: "A tool was not available.",
      category: "tooling",
      severity: "info",
      scanner: "osv",
      status: "skipped"
    }
  ],
  summary: {
    total: 4,
    bySeverity: { info: 1, low: 0, medium: 1, high: 1, critical: 1 },
    byCategory: {
      vulnerability: 1,
      "outdated-dependency": 1,
      secret: 1,
      "workflow-risk": 0,
      configuration: 0,
      tooling: 1
    }
  }
};

describe("toSarif", () => {
  it("emits SARIF version 2.1.0", () => {
    const sarif = toSarif(sampleResult);
    expect(sarif.version).toBe("2.1.0");
  });

  it("references the SARIF schema", () => {
    const sarif = toSarif(sampleResult);
    expect(sarif.$schema).toContain("sarif-2.1.0");
  });

  it("has exactly one run", () => {
    const sarif = toSarif(sampleResult);
    expect(sarif.runs).toHaveLength(1);
  });

  it("driver is named gha-security-checks", () => {
    const sarif = toSarif(sampleResult);
    expect(sarif.runs[0]?.tool.driver.name).toBe("gha-security-checks");
  });

  it("rules deduplicate by finding ID", () => {
    const sarif = toSarif(sampleResult);
    const ruleIds = sarif.runs[0]?.tool.driver.rules.map((r) => r.id) ?? [];
    // All 4 findings have unique IDs — all 4 should be rules
    expect(ruleIds).toHaveLength(4);
    expect(new Set(ruleIds).size).toBe(4);
  });

  it("maps severity to SARIF levels correctly", () => {
    const sarif = toSarif(sampleResult);
    const results = sarif.runs[0]?.results ?? [];

    const highResult = results.find((r) => r.ruleId === "test.high.finding");
    expect(highResult?.level).toBe("error");

    const criticalResult = results.find((r) => r.ruleId === "test.critical.secret");
    expect(criticalResult?.level).toBe("error");

    const mediumResult = results.find((r) => r.ruleId === "test.medium.outdated");
    expect(mediumResult?.level).toBe("warning");

    const infoResult = results.find((r) => r.ruleId === "test.info.tooling");
    expect(infoResult?.level).toBe("note");
  });

  it("includes physical location and line number when present", () => {
    const sarif = toSarif(sampleResult);
    const results = sarif.runs[0]?.results ?? [];

    const withLocation = results.find((r) => r.ruleId === "test.high.finding");
    expect(withLocation?.locations).toHaveLength(1);
    expect(withLocation?.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe("src/app.php");
    expect(withLocation?.locations?.[0]?.physicalLocation.region?.startLine).toBe(10);
  });

  it("omits locations array when finding has no location", () => {
    const sarif = toSarif(sampleResult);
    const results = sarif.runs[0]?.results ?? [];

    const noLocation = results.find((r) => r.ruleId === "test.medium.outdated");
    expect(noLocation?.locations).toBeUndefined();
  });

  it("includes category, scanner, and status in properties", () => {
    const sarif = toSarif(sampleResult);
    const results = sarif.runs[0]?.results ?? [];

    const result = results.find((r) => r.ruleId === "test.high.finding");
    expect(result?.properties?.category).toBe("vulnerability");
    expect(result?.properties?.scanner).toBe("test-scanner");
    expect(result?.properties?.status).toBe("open");
  });
});

describe("writeSarifReport", () => {
  it("writes valid JSON that parses back to the SARIF structure", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-sarif-test-"));
    const path = join(cwd, "results.sarif");

    writeSarifReport(sampleResult, path);

    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].results).toHaveLength(4);
  });

  it("ends with a newline", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-sarif-test-"));
    const path = join(cwd, "results.sarif");

    writeSarifReport(sampleResult, path);

    const raw = readFileSync(path, "utf8");
    expect(raw.endsWith("\n")).toBe(true);
  });
});

describe("toSarif — rules and GitHub compatibility", () => {
  const findingBase = {
    description: "d",
    category: "secret" as const,
    scanner: "s",
    status: "open" as const,
    location: { file: "a.txt", startLine: 3 }
  };

  const result = {
    findings: [
      { ...findingBase, id: "secret.pattern.aws.a.txt.abc", ruleId: "secret.pattern.aws", title: "AWS key", severity: "high" as const },
      { ...findingBase, id: "secret.pattern.aws.b.txt.def", ruleId: "secret.pattern.aws", title: "AWS key", severity: "high" as const },
      {
        ...findingBase,
        id: "secret.pattern.gh.a.txt.123",
        ruleId: "secret.pattern.gh",
        title: "GitHub token",
        severity: "critical" as const,
        status: "suppressed" as const,
        metadata: { suppressionReason: "test fixture" }
      }
    ],
    summary: { total: 3, bySeverity: { info: 0, low: 0, medium: 0, high: 2, critical: 1 }, byCategory: { vulnerability: 0, "outdated-dependency": 0, secret: 3, "workflow-risk": 0, configuration: 0, tooling: 0 } },
    failed: false,
    mode: "audit",
    generatedAt: "2026-01-01T00:00:00.000Z"
  };

  it("groups instances of the same check under one rule", () => {
    const run = toSarif(result).runs[0]!;
    expect(run.tool.driver.rules.map((r) => r.id)).toEqual(["secret.pattern.aws", "secret.pattern.gh"]);
    expect(run.results.map((r) => r.ruleId)).toEqual([
      "secret.pattern.aws",
      "secret.pattern.aws",
      "secret.pattern.gh"
    ]);
  });

  it("exposes security-severity, a repo-root base id and stable fingerprints", () => {
    const run = toSarif(result).runs[0]!;
    expect(run.tool.driver.rules[0]?.properties["security-severity"]).toBe("8.0");
    expect(run.tool.driver.rules[1]?.properties["security-severity"]).toBe("9.5");
    expect(run.results[0]?.locations?.[0]?.physicalLocation.artifactLocation.uriBaseId).toBe("%SRCROOT%");
    expect(run.results[0]?.partialFingerprints["ghaSecurityChecks/findingId"]).toBe("secret.pattern.aws.a.txt.abc");
    expect(run.tool.driver.informationUri).toBe("https://github.com/lavluda/GHA-security-checks");
  });

  it("marks suppressed results so GitHub does not reopen them", () => {
    const run = toSarif(result).runs[0]!;
    expect(run.results[0]?.suppressions).toBeUndefined();
    expect(run.results[2]?.suppressions).toEqual([{ kind: "external", justification: "test fixture" }]);
  });
});
