import * as core from "@actions/core";
import { runSecurityCheck, type PolicyMode } from "../index.js";
import { evaluatePolicy } from "../core/policy-engine.js";
import { publishGitHubReport } from "../integrations/github.js";
import { VERSION, COMMIT } from "../core/version.js";

async function main(): Promise<void> {
  core.info(`[gha-security-checks] v${VERSION} (${COMMIT})`);
  const args = parseArgs(process.argv.slice(2));
  const mode = input("mode", args) as PolicyMode | undefined;
  const configPath = input("config", args);
  const cwd = input("cwd", args) || process.cwd();
  const token = input("github-token", args);

  const { config, result, reports } = await runSecurityCheck({
    cwd,
    configPath,
    overrides: {
      mode,
      outputs: {
        json: outputInput("json-report", "security-results.json", args),
        markdown: outputInput("markdown-report", "security-summary.md", args),
        sarif: outputInput("sarif-report", "security-results.sarif", args),
        prComment: booleanInput("comment", true, args),
        githubSummary: booleanInput("summary", true, args),
        annotations: booleanInput("annotations", true, args)
      }
    }
  });

  core.setOutput("failed", String(result.failed));
  core.setOutput("findings", String(result.summary.total));
  core.setOutput("json-report", reports.json ?? "");
  core.setOutput("markdown-report", reports.markdown ?? "");
  core.setOutput("sarif-report", reports.sarif ?? "");

  // Reporting is best effort: a read-only token (e.g. on fork PRs) must not fail the audit itself.
  try {
    await publishGitHubReport(result, {
      token,
      prComment: config.outputs.prComment,
      jobSummary: config.outputs.githubSummary,
      annotations: config.outputs.annotations
    });
  } catch (error) {
    core.warning(
      `Could not publish the GitHub report: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  if (result.failed) {
    const blocking = evaluatePolicy(result.findings, config).blockingFindings.length;
    core.setFailed(
      `Security policy failed: ${blocking} blocking finding(s) of ${result.summary.total} total.`
    );
  }
}

function input(name: string, args: Record<string, string | undefined> = {}): string | undefined {
  const argValue = args[name];
  if (argValue !== undefined && argValue.length > 0) {
    return argValue;
  }
  const value = core.getInput(name);
  return value.length > 0 ? value : undefined;
}

function booleanInput(
  name: string,
  fallback: boolean,
  args: Record<string, string | undefined> = {}
): boolean {
  const value = input(name, args);
  if (value === undefined) {
    return fallback;
  }
  return value.toLowerCase() === "true";
}

function outputInput(
  name: string,
  fallback: string,
  args: Record<string, string | undefined> = {}
): string | false {
  const enabledInput = input(`${name}-enabled`, args);
  if (enabledInput?.toLowerCase() === "false") {
    return false;
  }
  return input(name, args) ?? fallback;
}

function parseArgs(argv: string[]): Record<string, string | undefined> {
  const parsed: Record<string, string | undefined> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (!current?.startsWith("--")) {
      continue;
    }

    const key = current.slice(2);
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--")) {
      parsed[key] = "true";
      continue;
    }

    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

main().catch((error: unknown) => {
  core.setFailed(error instanceof Error ? error.message : String(error));
});
