import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config.js";
import { ComposerAuditScanner } from "../src/scanners/php/composer-audit.js";
import { ComposerOutdatedScanner } from "../src/scanners/php/composer-outdated.js";
import { runnerReturning, tempProject } from "./helpers.js";

const auditJson = {
  advisories: {
    "symfony/http-foundation": [
      {
        advisoryId: "PKSA-1234",
        packageName: "symfony/http-foundation",
        affectedVersions: ">=5.4.0,<5.4.20",
        title: "Request poisoning",
        cve: "CVE-2023-0001",
        link: "https://symfony.com/cve-2023-0001",
        severity: "high"
      }
    ]
  },
  abandoned: { "old/package": "new/package", "dead/package": null }
};

describe("ComposerAuditScanner", () => {
  it("audits the lock file when composer.lock exists", async () => {
    const cwd = await tempProject({ "composer.json": "{}", "composer.lock": "{}" });
    const toolRunner = runnerReturning(1, auditJson);

    const findings = await new ComposerAuditScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner });

    expect(toolRunner.calls[0]?.args).toContain("--locked");
    expect(findings.find((f) => f.id.startsWith("composer.audit."))).toMatchObject({
      id: "composer.audit.symfony/http-foundation.PKSA-1234",
      ruleId: "composer.audit.PKSA-1234",
      severity: "high"
    });
    expect(findings.filter((f) => f.id.startsWith("composer.abandoned."))).toHaveLength(2);
  });

  it("does not pass --locked without a lock file", async () => {
    const cwd = await tempProject({ "composer.json": "{}" });
    const toolRunner = runnerReturning(0, { advisories: {} });

    await new ComposerAuditScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner });

    expect(toolRunner.calls[0]?.args).not.toContain("--locked");
  });

  it("reports skipped findings when composer is missing or output is garbled", async () => {
    const cwd = await tempProject({ "composer.json": "{}" });
    const config = loadConfig({ cwd });

    const missing = await new ComposerAuditScanner().scan({ cwd, config, toolRunner: runnerReturning(127) });
    expect(missing[0]).toMatchObject({ id: "tooling.composer.audit.missing", status: "skipped" });

    const garbled = await new ComposerAuditScanner().scan({
      cwd,
      config,
      toolRunner: runnerReturning(1, "nope", "composer exploded")
    });
    expect(garbled[0]).toMatchObject({
      id: "tooling.composer.audit.parse-failed",
      description: "composer exploded"
    });
  });
});

describe("ComposerOutdatedScanner", () => {
  it("lists outdated locked packages and uses --locked", async () => {
    const cwd = await tempProject({ "composer.json": "{}", "composer.lock": "{}" });
    const toolRunner = runnerReturning(0, {
      installed: [
        { name: "a/a", version: "1.0.0", latest: "1.0.1", "latest-status": "semver-safe-update" },
        { name: "b/b", version: "1.0.0", latest: "2.0.0", "latest-status": "update-possible" },
        { name: "c/c", version: "1.0.0", latest: "1.0.0", "latest-status": "up-to-date" }
      ]
    });

    const findings = await new ComposerOutdatedScanner().scan({ cwd, config: loadConfig({ cwd }), toolRunner });

    expect(toolRunner.calls[0]?.args).toContain("--locked");
    expect(findings.map((f) => [f.id, f.severity])).toEqual([
      ["composer.outdated.a/a", "low"],
      ["composer.outdated.b/b", "medium"]
    ]);
  });

  it("uses distinct tooling ids from the audit scanner", async () => {
    const cwd = await tempProject({ "composer.json": "{}" });
    const findings = await new ComposerOutdatedScanner().scan({
      cwd,
      config: loadConfig({ cwd }),
      toolRunner: runnerReturning(127)
    });
    expect(findings[0]?.id).toBe("tooling.composer.outdated.missing");
  });
});
