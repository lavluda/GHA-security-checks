import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config.js";
import { NpmAuditScanner } from "../src/scanners/node/npm-audit.js";
import { NpmOutdatedScanner } from "../src/scanners/node/npm-outdated.js";
import type { ToolRunner } from "../src/integrations/tool-runner.js";

describe("Node npm scanners", () => {
  it("reports npm audit vulnerabilities", async () => {
    const cwd = await createNodeProject();
    const toolRunner: ToolRunner = {
      async run(command, args) {
        return {
          command,
          args,
          exitCode: 1,
          stdout: JSON.stringify({
            vulnerabilities: {
              lodash: {
                name: "lodash",
                severity: "high",
                range: "<4.17.21",
                via: [
                  {
                    title: "Command Injection in lodash",
                    severity: "high",
                    range: "<4.17.21",
                    url: "https://github.com/advisories/GHSA-test"
                  }
                ],
                fixAvailable: {
                  name: "lodash",
                  version: "4.17.21",
                  isSemVerMajor: false
                }
              }
            }
          }),
          stderr: ""
        };
      }
    };

    const config = loadConfig({ cwd });
    const findings = await new NpmAuditScanner().scan({ cwd, config, toolRunner });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("npm.audit.lodash");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.fixedVersion).toBe("4.17.21");
  });

  it("reports outdated npm packages", async () => {
    const cwd = await createNodeProject();
    const toolRunner: ToolRunner = {
      async run(command, args) {
        return {
          command,
          args,
          exitCode: 1,
          stdout: JSON.stringify({
            express: {
              current: "4.18.0",
              wanted: "4.18.3",
              latest: "5.1.0",
              dependent: "app",
              type: "dependencies"
            }
          }),
          stderr: ""
        };
      }
    };

    const config = loadConfig({ cwd });
    const findings = await new NpmOutdatedScanner().scan({ cwd, config, toolRunner });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("npm.outdated.express");
    expect(findings[0]?.severity).toBe("medium");
    expect(findings[0]?.installedVersion).toBe("4.18.0");
    expect(findings[0]?.fixedVersion).toBe("5.1.0");
  });
});

async function createNodeProject(): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "gha-security-checks-node-"));
  mkdirSync(cwd, { recursive: true });
  mkdirSync(join(cwd, "node_modules"));
  writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: "app" }), "utf8");
  return cwd;
}

describe("Node npm scanners — robustness", () => {
  it("skips npm outdated with a clear finding when node_modules is missing", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-security-checks-node-"));
    writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: "app" }), "utf8");
    const calls: string[][] = [];
    const toolRunner: ToolRunner = {
      async run(command, args) {
        calls.push(args);
        return { command, args, exitCode: 0, stdout: "{}", stderr: "" };
      }
    };

    const findings = await new NpmOutdatedScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner });

    expect(calls).toHaveLength(0);
    expect(findings[0]).toMatchObject({
      id: "tooling.npm.outdated.not-installed",
      status: "skipped"
    });
  });

  it("treats empty npm outdated output as no findings", async () => {
    const cwd = await createNodeProject();
    const toolRunner: ToolRunner = {
      async run(command, args) {
        return { command, args, exitCode: 0, stdout: "", stderr: "" };
      }
    };
    expect(await new NpmOutdatedScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner })).toEqual([]);
  });

  it("surfaces an npm audit error object instead of reporting nothing", async () => {
    const cwd = await createNodeProject();
    const toolRunner: ToolRunner = {
      async run(command, args) {
        return {
          command,
          args,
          exitCode: 1,
          stdout: JSON.stringify({ error: { code: "ENOLOCK", summary: "requires an existing lockfile" } }),
          stderr: ""
        };
      }
    };
    const findings = await new NpmAuditScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner });
    expect(findings[0]).toMatchObject({ id: "tooling.npm.audit.error", status: "skipped" });
    expect(findings[0]?.description).toContain("lockfile");
  });

  it("keeps every advisory and reports the highest severity for a package", async () => {
    const cwd = await createNodeProject();
    const toolRunner: ToolRunner = {
      async run(command, args) {
        return {
          command,
          args,
          exitCode: 1,
          stdout: JSON.stringify({
            vulnerabilities: {
              minimist: {
                name: "minimist",
                severity: "low",
                via: [
                  { title: "Prototype pollution A", severity: "low", url: "https://x/a" },
                  { title: "Prototype pollution B", severity: "critical", url: "https://x/b" }
                ],
                fixAvailable: true
              }
            }
          }),
          stderr: ""
        };
      }
    };
    const [finding] = await new NpmAuditScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner });
    expect(finding?.severity).toBe("critical");
    expect(finding?.references).toEqual(["https://x/a", "https://x/b"]);
    expect(finding?.description).toContain("Prototype pollution B");
  });
});
