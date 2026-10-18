import { mkdtemp, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { loadBaseline, saveBaseline, applyBaseline } from "../src/core/baseline.js";
import type { Finding } from "../src/core/finding.js";

const openFinding: Finding = {
  id: "test.vuln.pkg-a",
  title: "Vulnerable package",
  description: "A known vulnerability.",
  category: "vulnerability",
  severity: "high",
  scanner: "test",
  status: "open"
};

const anotherFinding: Finding = {
  id: "test.secret.file",
  title: "Secret detected",
  description: "A secret was found.",
  category: "secret",
  severity: "critical",
  scanner: "test",
  status: "open"
};

describe("saveBaseline / loadBaseline", () => {
  it("round-trips open findings to a JSON file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-baseline-"));
    saveBaseline(cwd, "baseline.json", [openFinding, anotherFinding]);

    const ids = loadBaseline(cwd, "baseline.json");
    expect(ids.has("test.vuln.pkg-a")).toBe(true);
    expect(ids.has("test.secret.file")).toBe(true);
    expect(ids.size).toBe(2);
  });

  it("only writes open findings (skips suppressed)", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-baseline-"));
    const suppressed: Finding = { ...openFinding, id: "test.suppressed", status: "suppressed" };
    saveBaseline(cwd, "baseline.json", [openFinding, suppressed]);

    const ids = loadBaseline(cwd, "baseline.json");
    expect(ids.has(openFinding.id)).toBe(true);
    expect(ids.has("test.suppressed")).toBe(false);
  });

  it("returns empty Set when file doesn't exist", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-baseline-"));
    const ids = loadBaseline(cwd, "nonexistent.json");
    expect(ids.size).toBe(0);
  });

  it("returns empty Set for invalid JSON", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-baseline-"));
    await writeFile(join(cwd, "bad.json"), "not json", "utf8");
    const ids = loadBaseline(cwd, "bad.json");
    expect(ids.size).toBe(0);
  });

  it("produces a file that ends with a newline", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-baseline-"));
    saveBaseline(cwd, "baseline.json", [openFinding]);
    const raw = readFileSync(join(cwd, "baseline.json"), "utf8");
    expect(raw.endsWith("\n")).toBe(true);
  });
});

describe("applyBaseline", () => {
  it("suppresses findings whose ID is in the baseline", () => {
    const ids = new Set(["test.vuln.pkg-a"]);
    const result = applyBaseline([openFinding, anotherFinding], ids);

    const suppressed = result.find((f) => f.id === "test.vuln.pkg-a");
    expect(suppressed?.status).toBe("suppressed");
    expect(suppressed?.metadata?.baselined).toBe(true);
  });

  it("leaves findings not in the baseline untouched", () => {
    const ids = new Set(["test.vuln.pkg-a"]);
    const result = applyBaseline([openFinding, anotherFinding], ids);

    const unchanged = result.find((f) => f.id === "test.secret.file");
    expect(unchanged?.status).toBe("open");
  });

  it("returns original array unchanged when baseline is empty", () => {
    const result = applyBaseline([openFinding, anotherFinding], new Set());
    expect(result.every((f) => f.status === "open")).toBe(true);
  });
});

describe("baseline integration via ScannerEngine", () => {
  it("suppresses baselined findings during a scan", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-baseline-integration-"));

    // Write a baseline with the finding's ID
    saveBaseline(cwd, "security-baseline.json", [openFinding]);

    // Import at module level to avoid circular issues
    const { loadConfig } = await import("../src/core/config.js");
    const { ScannerEngine } = await import("../src/core/scanner-engine.js");

    const config = loadConfig({
      cwd,
      overrides: {
        mode: "audit",
        baseline: "security-baseline.json",
        scanners: { php: false, node: false, osv: false, secrets: false, githubActions: false }
      }
    });

    const mockScanner = {
      name: "mock",
      scan: async () => [openFinding]
    };

    const toolRunner = {
      run: async (command: string, args: string[]) => ({
        command,
        args,
        exitCode: 0,
        stdout: "",
        stderr: ""
      })
    };

    const engine = new ScannerEngine([mockScanner]);
    const result = await engine.run({ cwd, config, toolRunner });

    expect(result.findings[0]?.status).toBe("suppressed");
    expect(result.findings[0]?.metadata?.baselined).toBe(true);
  });
});
