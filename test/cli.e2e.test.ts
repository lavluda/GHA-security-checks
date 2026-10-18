/**
 * CLI e2e tests — spawn the compiled CLI against a real fixture directory.
 *
 * Requires `npm run build` to have been run first (or beforeAll does it).
 * Uses the sample-repo fixture which contains:
 *   - A fake AWS access key (triggers secret scanner)
 *   - A risky workflow (triggers workflow-hardening scanner)
 *   - composer.json without a lockfile (composer scanner skips gracefully)
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtemp, cp } from "node:fs/promises";
import { beforeAll, afterAll, describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const cliPath = join(root, "dist", "cli", "index.js");
const fixtureSrc = join(root, "test", "fixtures", "sample-repo");

let cwd: string;

beforeAll(async () => {
  // Build if dist not present
  if (!existsSync(cliPath)) {
    const result = spawnSync("npm", ["run", "build"], {
      cwd: root,
      encoding: "utf8",
      stdio: "inherit"
    });
    if (result.status !== 0) {
      throw new Error("npm run build failed — cannot run CLI e2e tests");
    }
  }

  // Copy fixture to a temp dir so tests don't mutate the source
  cwd = await mkdtemp(join(tmpdir(), "gha-e2e-"));
  await cp(fixtureSrc, cwd, { recursive: true });
}, 60_000);

afterAll(() => {
  if (cwd && existsSync(cwd)) {
    rmSync(cwd, { recursive: true, force: true });
  }
});

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync("node", [cliPath, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      // Disable reports so tests don't create leftover files
      NO_COLOR: "1"
    }
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr
  };
}

describe("CLI — audit mode", () => {
  it("exits 0 in audit mode even when findings exist", () => {
    const { status } = runCli([
      "--cwd", cwd,
      "--mode", "audit",
      "--no-json",
      "--no-markdown",
      "--no-sarif"
    ]);
    expect(status).toBe(0);
  }, 30_000);

  it("reports the scan as completed", () => {
    const { stdout } = runCli([
      "--cwd", cwd,
      "--mode", "audit",
      "--no-json",
      "--no-markdown",
      "--no-sarif"
    ]);
    expect(stdout).toContain("Security audit completed");
  }, 30_000);
});

describe("CLI — strict mode", () => {
  it("exits 1 in strict mode when findings exist", () => {
    const { status } = runCli([
      "--cwd", cwd,
      "--mode", "strict",
      "--no-json",
      "--no-markdown",
      "--no-sarif"
    ]);
    // The fixture has at least one secret finding (AWS key) and workflow risk,
    // both of which cause strict mode to fail.
    expect(status).toBe(1);
  }, 30_000);
});

describe("CLI — report files", () => {
  it("writes JSON, Markdown, and SARIF reports when enabled", () => {
    const jsonPath = join(cwd, "test-results.json");
    const mdPath = join(cwd, "test-results.md");
    const sarifPath = join(cwd, "test-results.sarif");

    // Clean up any leftovers
    for (const p of [jsonPath, mdPath, sarifPath]) {
      if (existsSync(p)) rmSync(p);
    }

    runCli([
      "--cwd", cwd,
      "--mode", "audit",
      "--json-file", jsonPath,
      "--markdown-file", mdPath,
      "--sarif-file", sarifPath
    ]);

    expect(existsSync(jsonPath)).toBe(true);
    expect(existsSync(mdPath)).toBe(true);
    expect(existsSync(sarifPath)).toBe(true);
  });

  it("skips report files when --no-json, --no-markdown, --no-sarif are set", () => {
    const jsonPath = join(cwd, "skip-test.json");
    if (existsSync(jsonPath)) rmSync(jsonPath);

    runCli([
      "--cwd", cwd,
      "--mode", "audit",
      "--no-json",
      "--no-markdown",
      "--no-sarif",
      "--json-file", jsonPath
    ]);

    expect(existsSync(jsonPath)).toBe(false);
  });
});

describe("CLI — version flag", () => {
  it("prints version and exits 0", () => {
    const { status, stdout } = runCli(["--version"]);
    expect(status).toBe(0);
    // Should print something like "0.3.0 (abc1234)"
    expect(stdout).toMatch(/\d+\.\d+\.\d+/);
  });
});

// ─── baseline & suppressions (regressions) ───────────────────────────────────

describe("CLI: baseline and suppressions", () => {
  async function project(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "gha-e2e-baseline-"));
    writeFileSync(join(dir, ".env"), "TOKEN=abc\n");
    return dir;
  }

  function cli(dir: string, args: string[]) {
    const result = spawnSync("node", [cliPath, ...args, "--cwd", dir], {
      encoding: "utf8",
      timeout: 30_000,
      env: { ...process.env, NO_COLOR: "1" }
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  }

  const baselineIds = (dir: string): string[] =>
    (JSON.parse(readFileSync(join(dir, "security-baseline.json"), "utf8")) as Array<{ id: string }>).map(
      (entry) => entry.id
    );

  it("baseline update keeps previously baselined findings when run again", async () => {
    const dir = await project();
    writeFileSync(join(dir, "gha-security-checks.yml"), "baseline: security-baseline.json\n");

    expect(cli(dir, ["baseline", "update"]).status).toBe(0);
    expect(baselineIds(dir)).toContain("secret.file..env");

    expect(cli(dir, ["baseline", "update"]).status).toBe(0);
    expect(baselineIds(dir)).toContain("secret.file..env");
  });

  it("baseline update writes to the config's baseline path by default", async () => {
    const dir = await project();
    writeFileSync(join(dir, "gha-security-checks.yml"), "baseline: custom-baseline.json\n");
    cli(dir, ["baseline", "update"]);
    expect(existsSync(join(dir, "custom-baseline.json"))).toBe(true);
  });

  it("a baselined finding no longer fails strict mode", async () => {
    const dir = await project();
    expect(cli(dir, ["--mode", "strict", "--no-json", "--no-markdown", "--no-sarif"]).status).toBe(1);

    writeFileSync(join(dir, "gha-security-checks.yml"), "baseline: security-baseline.json\n");
    cli(dir, ["baseline", "update"]);
    expect(cli(dir, ["--mode", "strict", "--no-json", "--no-markdown", "--no-sarif"]).status).toBe(0);
  });

  it("configured suppressions (added via the CLI) are applied during the scan", async () => {
    const dir = await project();
    const added = cli(dir, ["suppress", "secret.file..env", "--reason", "local dev file"]);
    expect(added.status).toBe(0);
    expect(cli(dir, ["--mode", "strict", "--no-json", "--no-markdown", "--no-sarif"]).status).toBe(0);
  });

  it("the suppress alias supports --category", async () => {
    const dir = await project();
    expect(cli(dir, ["suppress", "ignored", "--category", "secret"]).status).toBe(0);
    expect(cli(dir, ["--mode", "strict", "--no-json", "--no-markdown", "--no-sarif"]).status).toBe(0);
  });
});
