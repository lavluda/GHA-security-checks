#!/usr/bin/env node
import { Command } from "commander";
import { runSecurityCheck, type PolicyMode } from "../index.js";
import { VERSION, COMMIT } from "../core/version.js";
import { saveBaseline } from "../core/baseline.js";
import { loadConfig } from "../core/config.js";
import { addSuppression, listSuppressions, removeSuppression } from "../core/config-editor.js";

const program = new Command();

program
  .name("gha-security-checks")
  .description("Run security audit checks for GitHub Actions and CI workflows.")
  .version(`${VERSION} (${COMMIT})`, "-v, --version");

// ─── Main scan command ────────────────────────────────────────────────────────

program
  .command("scan", { isDefault: true })
  .description("Run security checks (default command).")
  .option("-c, --config <path>", "Path to a security check config file")
  .option("--cwd <path>", "Repository root to scan", process.cwd())
  .option(
    "--mode <mode>",
    "Policy mode: audit, diff, warn, fail-on-high, fail-on-critical, strict, custom"
  )
  .option("--no-json", "Disable JSON report output")
  .option("--no-markdown", "Disable Markdown report output")
  .option("--no-sarif", "Disable SARIF report output")
  .option("--json-file <path>", "JSON report path")
  .option("--markdown-file <path>", "Markdown report path")
  .option("--sarif-file <path>", "SARIF report path")
  .action(async (options) => {
    const outputs = {
      json: options.json === false ? false : options.jsonFile,
      markdown: options.markdown === false ? false : options.markdownFile,
      sarif: options.sarif === false ? false : options.sarifFile
    };

    const { result, reports } = await runSecurityCheck({
      cwd: options.cwd,
      configPath: options.config,
      overrides: {
        mode: options.mode as PolicyMode | undefined,
        outputs
      }
    });

    console.log(`Security audit completed with ${result.summary.total} finding(s).`);
    console.log(`Mode: ${result.mode}`);
    console.log(`Status: ${result.failed ? "failed" : "passed"}`);

    for (const [kind, path] of Object.entries(reports)) {
      console.log(`${kind}: ${path}`);
    }

    if (result.failed) {
      process.exitCode = 1;
    }
  });

// ─── Baseline subcommands ─────────────────────────────────────────────────────

const baselineCmd = program.command("baseline").description("Manage the findings baseline.");

baselineCmd
  .command("update")
  .description(
    "Run a full scan and write all open findings to the baseline file. " +
    "On future runs, these findings will be suppressed."
  )
  .option("-c, --config <path>", "Path to a security check config file")
  .option("--cwd <path>", "Repository root to scan", process.cwd())
  .option("--file <path>", "Baseline file path (defaults to the config's `baseline`, else security-baseline.json)")
  .action(async (options) => {
    const { result } = await runSecurityCheck({
      cwd: options.cwd,
      configPath: options.config,
      // Disable the existing baseline so previously baselined findings are re-recorded, not dropped.
      overrides: {
        mode: "audit",
        baseline: undefined,
        outputs: { json: false, markdown: false, sarif: false }
      }
    });

    const file: string =
      options.file ??
      loadConfig({ cwd: options.cwd, configPath: options.config }).baseline ??
      "security-baseline.json";
    saveBaseline(options.cwd, file, result.findings);

    const openCount = result.findings.filter((f) => f.status === "open").length;
    console.log(`Baseline written to ${file} — ${openCount} finding(s) suppressed.`);
    console.log("Future runs will only surface findings introduced after this baseline.");
  });

// ─── Suppression subcommands ──────────────────────────────────────────────────

const suppressionsCmd = program
  .command("suppressions")
  .description("Manage finding suppressions in the config file.");

suppressionsCmd
  .command("add <id>")
  .alias("suppress")
  .description("Add a suppression for a finding ID to the config file.")
  .option("-c, --config <path>", "Path to the config file to modify")
  .option("--cwd <path>", "Repository root", process.cwd())
  .option("--reason <reason>", "Human-readable reason for suppression")
  .option("--category <category>", "Suppress all findings of this category instead")
  .option("--path <path>", "Suppress findings at this file path only")
  .action((id, options) => {
    const filePath = addSuppression(
      options.cwd,
      {
        id: options.category ? undefined : id,
        category: options.category,
        path: options.path,
        reason: options.reason
      },
      options.config
    );
    console.log(`Suppression added to ${filePath}`);
  });

// Top-level alias: gha-security-checks suppress <id>
program
  .command("suppress <id>")
  .description("Shorthand for suppressions add <id>.")
  .option("-c, --config <path>", "Path to the config file to modify")
  .option("--cwd <path>", "Repository root", process.cwd())
  .option("--reason <reason>", "Human-readable reason for suppression")
  .option("--category <category>", "Suppress all findings of this category instead")
  .option("--path <path>", "Suppress findings at this file path only")
  .action((id, options) => {
    const filePath = addSuppression(
      options.cwd,
      {
        id: options.category ? undefined : id,
        category: options.category,
        path: options.path,
        reason: options.reason
      },
      options.config
    );
    console.log(`Suppression added to ${filePath}`);
  });

suppressionsCmd
  .command("list")
  .description("List all suppressions in the config file.")
  .option("-c, --config <path>", "Path to the config file")
  .option("--cwd <path>", "Repository root", process.cwd())
  .action((options) => {
    const suppressions = listSuppressions(options.cwd, options.config);
    if (suppressions.length === 0) {
      console.log("No suppressions configured.");
      return;
    }
    console.log(`${suppressions.length} suppression(s):\n`);
    for (const s of suppressions) {
      const parts = [];
      if (s.id) parts.push(`id: ${s.id}`);
      if (s.category) parts.push(`category: ${s.category}`);
      if (s.path) parts.push(`path: ${s.path}`);
      if (s.reason) parts.push(`reason: ${s.reason}`);
      console.log(`  - ${parts.join(", ")}`);
    }
  });

suppressionsCmd
  .command("remove <id>")
  .description("Remove suppressions matching the given ID from the config file.")
  .option("-c, --config <path>", "Path to the config file to modify")
  .option("--cwd <path>", "Repository root", process.cwd())
  .action((id, options) => {
    const { filePath, removed } = removeSuppression(options.cwd, id, options.config);
    if (removed === 0) {
      console.log(`No suppression found with id: ${id}`);
    } else {
      console.log(`Removed ${removed} suppression(s) from ${filePath}`);
    }
  });

program.parseAsync().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
