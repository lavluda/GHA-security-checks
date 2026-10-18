import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanResult } from "../src/core/finding.js";

const mocks = vi.hoisted(() => ({
  core: {
    error: vi.fn(),
    warning: vi.fn(),
    notice: vi.fn(),
    summary: { addRaw: vi.fn(), write: vi.fn() }
  },
  octokit: {
    paginate: vi.fn(),
    rest: { issues: { listComments: vi.fn(), createComment: vi.fn(), updateComment: vi.fn() } }
  },
  context: {
    payload: { pull_request: { number: 7 } } as Record<string, unknown>,
    repo: { owner: "acme", repo: "app" },
    serverUrl: "https://github.com",
    runId: 4242
  }
}));

vi.mock("@actions/core", () => mocks.core);
vi.mock("@actions/github", () => ({
  context: mocks.context,
  getOctokit: () => mocks.octokit
}));

const { publishGitHubReport } = await import("../src/integrations/github.js");

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    title: "Title",
    description: "Description",
    category: "vulnerability",
    severity: "high",
    scanner: "s",
    status: "open",
    ...overrides
  };
}

function scanResult(findings: Finding[], failed = false): ScanResult {
  return {
    findings,
    summary: {
      total: findings.length,
      bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
      byCategory: { vulnerability: 0, "outdated-dependency": 0, secret: 0, "workflow-risk": 0, configuration: 0, tooling: 0 }
    },
    failed,
    mode: "audit",
    generatedAt: "2026-01-01T00:00:00.000Z"
  };
}

const options = { token: "t", prComment: true, jobSummary: false, annotations: false };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.context.payload = { pull_request: { number: 7 } };
  mocks.core.summary.addRaw.mockReturnValue(mocks.core.summary);
  mocks.octokit.paginate.mockResolvedValue([]);
});

describe("publishGitHubReport — PR comment", () => {
  it("creates a comment on the first run", async () => {
    await publishGitHubReport(scanResult([finding({})]), options);

    expect(mocks.octokit.paginate).toHaveBeenCalled();
    expect(mocks.octokit.rest.issues.createComment).toHaveBeenCalledTimes(1);
    const body = mocks.octokit.rest.issues.createComment.mock.calls[0]![0].body as string;
    expect(body).toContain("<!-- gha-security-checks-report -->");
    expect(body).toContain("gha-security-checks-ids:[\"f1\"]");
  });

  it("updates the bot's existing comment and reports the delta", async () => {
    mocks.octokit.paginate.mockResolvedValue([
      {
        id: 99,
        user: { type: "Bot" },
        body: '<!-- gha-security-checks-report -->\n<!-- gha-security-checks-ids:["gone","f1"] -->'
      }
    ]);

    await publishGitHubReport(scanResult([finding({}), finding({ id: "f2", title: "Brand new" })]), options);

    expect(mocks.octokit.rest.issues.createComment).not.toHaveBeenCalled();
    const call = mocks.octokit.rest.issues.updateComment.mock.calls[0]![0];
    expect(call.comment_id).toBe(99);
    expect(call.body).toContain("Brand new");
    expect(call.body).toContain("Fixed since last run (1)");
    expect(call.body).toContain("Still open from earlier runs (1)");
  });

  it("ignores marker text posted by a non-bot user", async () => {
    mocks.octokit.paginate.mockResolvedValue([
      {
        id: 5,
        user: { type: "User" },
        body: '<!-- gha-security-checks-report -->\n<!-- gha-security-checks-ids:["f1"] -->'
      }
    ]);

    await publishGitHubReport(scanResult([finding({})]), options);

    expect(mocks.octokit.rest.issues.updateComment).not.toHaveBeenCalled();
    const body = mocks.octokit.rest.issues.createComment.mock.calls[0]![0].body as string;
    // The forged "previous ids" must not be used for the delta.
    expect(body).toContain("## Findings (1)");
  });

  it("links to the workflow run when the comment is truncated", async () => {
    const many = Array.from({ length: 400 }, (_, i) =>
      finding({ id: `f${i}`, description: "x".repeat(300) })
    );

    await publishGitHubReport(scanResult(many), options);

    const body = mocks.octokit.rest.issues.createComment.mock.calls[0]![0].body as string;
    expect(body).toContain("https://github.com/acme/app/actions/runs/4242");
    expect(body).not.toContain("$SUMMARY_URL");
  });

  it("counts config suppressions as well as baselined findings", async () => {
    await publishGitHubReport(
      scanResult([finding({}), finding({ id: "s1", status: "suppressed", metadata: { suppressed: true } })]),
      options
    );
    const body = mocks.octokit.rest.issues.createComment.mock.calls[0]![0].body as string;
    expect(body).toContain("Baselined / suppressed (1)");
  });

  it("does nothing for comments outside pull requests or without a token", async () => {
    mocks.context.payload = {};
    await publishGitHubReport(scanResult([finding({})]), options);
    await publishGitHubReport(scanResult([finding({})]), { ...options, token: undefined });
    expect(mocks.octokit.paginate).not.toHaveBeenCalled();
  });
});

describe("publishGitHubReport — annotations and summary", () => {
  it("maps severity to annotation levels", async () => {
    const findings = [
      finding({ id: "c", severity: "critical" }),
      finding({ id: "m", severity: "medium" }),
      finding({ id: "i", severity: "info" }),
      finding({ id: "x", severity: "high", status: "suppressed" })
    ];

    await publishGitHubReport(scanResult(findings, true), { ...options, prComment: false, annotations: true });
    expect(mocks.core.error).toHaveBeenCalledTimes(1);
    expect(mocks.core.warning).toHaveBeenCalledTimes(1);
    expect(mocks.core.notice).toHaveBeenCalledTimes(1);

    vi.clearAllMocks();
    await publishGitHubReport(scanResult(findings, false), { ...options, prComment: false, annotations: true });
    expect(mocks.core.error).not.toHaveBeenCalled();
    expect(mocks.core.warning).toHaveBeenCalledTimes(2);
  });

  it("writes the job summary when enabled", async () => {
    await publishGitHubReport(scanResult([]), { ...options, prComment: false, jobSummary: true });
    expect(mocks.core.summary.addRaw).toHaveBeenCalled();
    expect(mocks.core.summary.write).toHaveBeenCalled();
  });
});
