import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import {
  loadConfig,
  configFileCandidates,
  shouldFailForSeverity
} from "../src/core/config.js";

async function tempDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "gha-cfg-test-"));
}

// ─── defaults ────────────────────────────────────────────────────────────────

describe("loadConfig — defaults (no config file)", () => {
  it("returns default mode: audit", async () => {
    const cwd = await tempDir();
    const config = loadConfig({ cwd });
    expect(config.mode).toBe("audit");
  });

  it("enables all scanners by default", async () => {
    const cwd = await tempDir();
    const config = loadConfig({ cwd });
    expect(config.scanners).toMatchObject({
      php: true,
      node: true,
      osv: true,
      secrets: true,
      githubActions: true
    });
  });

  it("has default secret patterns", async () => {
    const cwd = await tempDir();
    const config = loadConfig({ cwd });
    expect(config.secrets.patterns.length).toBeGreaterThan(0);
    expect(config.secrets.patterns.some((p) => p.id === "github-token")).toBe(true);
  });

  it("has default output paths", async () => {
    const cwd = await tempDir();
    const config = loadConfig({ cwd });
    expect(config.outputs.json).toBe("security-results.json");
    expect(config.outputs.markdown).toBe("security-summary.md");
    expect(config.outputs.sarif).toBe("security-results.sarif");
  });
});

// ─── candidate filenames ──────────────────────────────────────────────────────

describe("loadConfig — config file candidates", () => {
  for (const candidate of configFileCandidates) {
    it(`loads from ${candidate}`, async () => {
      const cwd = await tempDir();
      await writeFile(
        join(cwd, candidate),
        "mode: fail-on-high\n",
        "utf8"
      );
      const config = loadConfig({ cwd });
      expect(config.mode).toBe("fail-on-high");
    });
  }

  it("uses explicit configPath over candidates", async () => {
    const cwd = await tempDir();
    await writeFile(join(cwd, "custom.yml"), "mode: strict\n", "utf8");
    // Also write a candidate that should be ignored
    await writeFile(join(cwd, "gha-security-checks.yml"), "mode: audit\n", "utf8");
    const config = loadConfig({ cwd, configPath: "custom.yml" });
    expect(config.mode).toBe("strict");
  });
});

// ─── nested override merging ──────────────────────────────────────────────────

describe("loadConfig — overrides", () => {
  it("merges top-level overrides with file config", async () => {
    const cwd = await tempDir();
    await writeFile(join(cwd, "gha-security-checks.yml"), "mode: warn\n", "utf8");
    const config = loadConfig({ cwd, overrides: { mode: "strict" } });
    expect(config.mode).toBe("strict");
  });

  it("merges nested scanner overrides without losing defaults", async () => {
    const cwd = await tempDir();
    const config = loadConfig({ cwd, overrides: { scanners: { php: false } } });
    expect(config.scanners.php).toBe(false);
    expect(config.scanners.node).toBe(true); // default preserved
  });

  it("merges nested outputs overrides", async () => {
    const cwd = await tempDir();
    const config = loadConfig({
      cwd,
      overrides: { outputs: { prComment: false } }
    });
    expect(config.outputs.prComment).toBe(false);
    expect(config.outputs.githubSummary).toBe(true); // default preserved
  });
});

// ─── schema validation ────────────────────────────────────────────────────────

describe("loadConfig — schema validation", () => {
  it("throws on an invalid mode value", async () => {
    const cwd = await tempDir();
    await writeFile(
      join(cwd, "gha-security-checks.yml"),
      "mode: not-a-real-mode\n",
      "utf8"
    );
    expect(() => loadConfig({ cwd })).toThrow();
  });
});

// ─── shouldFailForSeverity ────────────────────────────────────────────────────

describe("shouldFailForSeverity", () => {
  it("returns true when finding severity >= threshold", () => {
    expect(shouldFailForSeverity("high", "high")).toBe(true);
    expect(shouldFailForSeverity("critical", "high")).toBe(true);
    expect(shouldFailForSeverity("critical", "medium")).toBe(true);
  });

  it("returns false when finding severity < threshold", () => {
    expect(shouldFailForSeverity("low", "high")).toBe(false);
    expect(shouldFailForSeverity("medium", "high")).toBe(false);
    expect(shouldFailForSeverity("info", "low")).toBe(false);
  });

  it("handles boundary: info >= info", () => {
    expect(shouldFailForSeverity("info", "info")).toBe(true);
  });
});

describe("loadConfig — tools are never read from the config file", () => {
  it("ignores a `tools` section in the repository config", async () => {
    const cwd = await tempDir();
    await writeFile(join(cwd, "gha-security-checks.yml"), "tools:\n  composer: ./evil.sh\n  npm: ./evil.sh\n");
    const config = loadConfig({ cwd });
    expect(config.tools.composer).toBe("composer");
    expect(config.tools.npm).toBe("npm");
  });

  it("still accepts tool overrides passed programmatically", async () => {
    const cwd = await tempDir();
    const config = loadConfig({ cwd, overrides: { tools: { composer: "/usr/local/bin/composer" } } });
    expect(config.tools.composer).toBe("/usr/local/bin/composer");
    expect(config.tools.npm).toBe("npm");
  });
});
