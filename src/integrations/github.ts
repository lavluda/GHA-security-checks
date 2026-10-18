import * as core from "@actions/core";
import * as github from "@actions/github";
import type { Finding, ScanResult } from "../core/finding.js";
import { renderMarkdownReport } from "../reporters/markdown.js";

const prCommentMarker = "<!-- gha-security-checks-report -->";
// Embedded JSON storing the previous run's finding IDs for delta computation
const idDataPrefix = "<!-- gha-security-checks-ids:";
const idDataSuffix = " -->";
const maxCommentBytes = 60_000;

export interface GitHubReportOptions {
  token?: string;
  prComment: boolean;
  jobSummary: boolean;
  annotations: boolean;
}

export async function publishGitHubReport(
  result: ScanResult,
  options: GitHubReportOptions
): Promise<void> {
  if (options.annotations) {
    annotateFindings(result.findings, result.failed);
  }

  if (options.jobSummary) {
    await core.summary.addRaw(renderMarkdownReport(result)).write();
  }

  if (!options.prComment || !options.token) {
    return;
  }

  const pullRequest = github.context.payload.pull_request;
  if (!pullRequest) {
    return;
  }

  const octokit = github.getOctokit(options.token);
  const owner = github.context.repo.owner;
  const repo = github.context.repo.repo;
  const issueNumber = pullRequest.number;

  // Find our existing comment. The marker alone is not trusted: anyone can paste it into a comment,
  // so only comments authored by a bot account are considered.
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100
  });

  const existing = comments.find(
    (comment) => comment.user?.type === "Bot" && comment.body?.includes(prCommentMarker)
  );

  // Extract previous finding IDs for delta computation
  const previousIds = extractPreviousIds(existing?.body);
  const currentIds = new Set(
    result.findings.filter((f) => f.status === "open").map((f) => f.id)
  );

  const body = buildDeltaComment(result, previousIds, currentIds, runUrl());

  if (existing) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body
    });
    return;
  }

  await octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body
  });
}

function runUrl(): string {
  const { serverUrl, runId } = github.context;
  const { owner, repo } = github.context.repo;
  return `${serverUrl}/${owner}/${repo}/actions/runs/${runId}`;
}

function buildDeltaComment(
  result: ScanResult,
  previousIds: Set<string>,
  currentIds: Set<string>,
  workflowRunUrl: string
): string {
  const openFindings = result.findings.filter((f) => f.status === "open");

  const newIds = [...currentIds].filter((id) => !previousIds.has(id));
  const fixedIds = [...previousIds].filter((id) => !currentIds.has(id));
  const stillOpenIds = [...currentIds].filter((id) => previousIds.has(id));

  const newFindings = openFindings.filter((f) => newIds.includes(f.id));
  const stillOpen = openFindings.filter((f) => stillOpenIds.includes(f.id));

  const isFirstRun = previousIds.size === 0;

  const lines: string[] = [
    prCommentMarker,
    "# Security Audit Report",
    "",
    `**Mode:** ${result.mode} · **Status:** ${result.failed ? "❌ failed" : "✅ passed"} · **Total findings:** ${result.summary.total}`,
    ""
  ];

  // New findings (always expanded)
  if (newFindings.length > 0) {
    lines.push(`## 🆕 New (${newFindings.length})`);
    lines.push("");
    for (const f of newFindings) {
      lines.push(...renderFindingLine(f));
    }
  } else if (!isFirstRun) {
    lines.push("## 🆕 New");
    lines.push("");
    lines.push("No new findings introduced in this PR. ✅");
    lines.push("");
  }

  // Fixed findings
  if (fixedIds.length > 0 && !isFirstRun) {
    lines.push(`<details><summary>✅ Fixed since last run (${fixedIds.length})</summary>`);
    lines.push("");
    for (const id of fixedIds) {
      lines.push(`- ~~\`${id}\`~~`);
    }
    lines.push("");
    lines.push("</details>");
    lines.push("");
  }

  // Still open (collapsed by default)
  if (stillOpen.length > 0) {
    lines.push(
      `<details><summary>⚠️ Still open from earlier runs (${stillOpen.length})</summary>`
    );
    lines.push("");
    for (const f of stillOpen) {
      lines.push(...renderFindingLine(f));
    }
    lines.push("</details>");
    lines.push("");
  }

  // First run: show everything
  if (isFirstRun && openFindings.length > 0) {
    lines.push(`## Findings (${openFindings.length})`);
    lines.push("");
    for (const f of openFindings) {
      lines.push(...renderFindingLine(f));
    }
  }

  const suppressedCount = result.findings.filter((f) => f.status === "suppressed").length;
  if (suppressedCount > 0) {
    lines.push(`<details><summary>🔕 Baselined / suppressed (${suppressedCount})</summary>`);
    lines.push("");
    lines.push(
      "These findings are covered by the baseline or by a configured suppression and are not shown."
    );
    lines.push("");
    lines.push("</details>");
    lines.push("");
  }

  // Embed current IDs for next run's delta
  const idsJson = JSON.stringify([...currentIds]);
  lines.push(`${idDataPrefix}${idsJson}${idDataSuffix}`);

  const body = lines.join("\n");

  // Truncate if over GitHub's limit
  if (Buffer.byteLength(body, "utf8") > maxCommentBytes) {
    const truncated = [
      prCommentMarker,
      "# Security Audit Report",
      "",
      `**Mode:** ${result.mode} · **Status:** ${result.failed ? "❌ failed" : "✅ passed"} · **Total findings:** ${result.summary.total}`,
      "",
      `> ⚠️ Full report truncated (exceeded 60KB). See the [workflow run](${workflowRunUrl}) for the full report.`,
      "",
      `${idDataPrefix}${idsJson}${idDataSuffix}`
    ].join("\n");
    return truncated;
  }

  return body;
}

function renderFindingLine(finding: Finding): string[] {
  const sev = finding.severity.toUpperCase();
  const loc = finding.location
    ? ` — \`${finding.location.file}${finding.location.startLine ? `:${finding.location.startLine}` : ""}\``
    : "";
  const pkg = finding.packageName ? ` (\`${finding.packageName}\`)` : "";
  return [
    `- **[${sev}]** ${finding.title}${pkg}${loc}`,
    `  ${finding.description}`,
    ""
  ];
}

function extractPreviousIds(body: string | undefined | null): Set<string> {
  if (!body) return new Set();
  const start = body.indexOf(idDataPrefix);
  if (start === -1) return new Set();
  const end = body.indexOf(idDataSuffix, start + idDataPrefix.length);
  if (end === -1) return new Set();
  try {
    const json = body.slice(start + idDataPrefix.length, end);
    const parsed = JSON.parse(json) as string[];
    return new Set(parsed);
  } catch {
    return new Set();
  }
}

function annotateFindings(findings: Finding[], useErrorAnnotations: boolean): void {
  for (const finding of findings) {
    if (finding.status !== "open") continue;

    const annotation = finding.location
      ? {
          file: finding.location.file,
          startLine: finding.location.startLine,
          endLine: finding.location.endLine
        }
      : undefined;

    const message = `${finding.title}: ${finding.description}`;

    const severe = finding.severity === "critical" || finding.severity === "high";
    if (severe && useErrorAnnotations) {
      core.error(message, annotation);
    } else if (severe || finding.severity === "medium" || finding.severity === "low") {
      core.warning(message, annotation);
    } else {
      core.notice(message, annotation);
    }
  }
}
