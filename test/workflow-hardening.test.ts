import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config.js";
import { WorkflowHardeningScanner } from "../src/scanners/github-actions/workflow-hardening.js";
import type { ToolRunner } from "../src/integrations/tool-runner.js";
import { runnerReturning, tempProject } from "./helpers.js";

const toolRunner: ToolRunner = {
  async run(command, args) {
    return { command, args, exitCode: 0, stdout: "", stderr: "" };
  }
};

describe("WorkflowHardeningScanner", () => {
  it("reports risky workflow settings", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-security-checks-"));
    mkdirSync(join(cwd, ".github", "workflows"), { recursive: true });
    writeFileSync(
      join(cwd, ".github", "workflows", "ci.yml"),
      [
        "on: pull_request_target",
        "permissions: write-all",
        "jobs:",
        "  test:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: third-party/action@v1",
        "      - run: echo \"${{ github.event.pull_request.title }}\""
      ].join("\n"),
      "utf8"
    );

    const config = loadConfig({ cwd });
    const scanner = new WorkflowHardeningScanner();
    const findings = await scanner.scan({ cwd, config, toolRunner });

    expect(findings.some((finding) => finding.id.includes("pull-request-target"))).toBe(true);
    expect(findings.some((finding) => finding.id.includes("write-all"))).toBe(true);
    expect(findings.some((finding) => finding.id.includes("action-unpinned"))).toBe(true);
    expect(findings.some((finding) => finding.id.includes("untrusted-expression"))).toBe(true);
  });

  it("allows scoped write permissions", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-security-checks-"));
    mkdirSync(join(cwd, ".github", "workflows"), { recursive: true });
    writeFileSync(
      join(cwd, ".github", "workflows", "security-audit.yml"),
      [
        "on: pull_request",
        "permissions:",
        "  contents: read",
        "  pull-requests: write",
        "  issues: write",
        "  security-events: write",
        "jobs:",
        "  audit:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4"
      ].join("\n"),
      "utf8"
    );

    const config = loadConfig({ cwd });
    const scanner = new WorkflowHardeningScanner();
    const findings = await scanner.scan({ cwd, config, toolRunner });

    expect(findings.some((finding) => finding.id.includes("write-all"))).toBe(false);
  });
});


async function scanWorkflow(yaml: string, name = "ci.yml") {
  const cwd = await tempProject({ [`.github/workflows/${name}`]: yaml });
  return new WorkflowHardeningScanner().scan({
    cwd,
    config: loadConfig({ cwd }),
    toolRunner: runnerReturning(0)
  });
}

const sha = "a".repeat(40);

describe("WorkflowHardeningScanner — details", () => {
  it("flags workflow_run triggers", async () => {
    const findings = await scanWorkflow(
      ["on:", "  workflow_run:", "    workflows: [CI]", "permissions: read-all", "jobs: {}"].join("\n")
    );
    expect(findings.map((f) => f.ruleId)).toContain("workflow.workflow-run");
  });

  it("does not report missing permissions when every job declares its own", async () => {
    const findings = await scanWorkflow(
      [
        "on: push",
        "jobs:",
        "  a:",
        "    permissions: { contents: read }",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: echo }]",
        "  b:",
        "    permissions: {}",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: echo }]"
      ].join("\n")
    );
    expect(findings.some((f) => f.id.includes("permissions.missing"))).toBe(false);
  });

  it("reports missing permissions when only some jobs declare them", async () => {
    const findings = await scanWorkflow(
      [
        "on: push",
        "jobs:",
        "  a:",
        "    permissions: { contents: read }",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: echo }]",
        "  b:",
        "    runs-on: ubuntu-latest",
        "    steps: [{ run: echo }]"
      ].join("\n")
    );
    expect(findings.some((f) => f.id.includes("permissions.missing"))).toBe(true);
  });

  it("flags unpinned reusable workflows but not pinned or local ones", async () => {
    const findings = await scanWorkflow(
      [
        "on: push",
        "permissions: read-all",
        "jobs:",
        "  unpinned:",
        "    uses: org/repo/.github/workflows/x.yml@main",
        "  pinned:",
        `    uses: org/repo/.github/workflows/x.yml@${sha}`,
        "  local:",
        "    uses: ./.github/workflows/y.yml"
      ].join("\n")
    );
    const unpinned = findings.filter((f) => f.ruleId === "workflow.action-unpinned");
    expect(unpinned).toHaveLength(1);
    expect(unpinned[0]?.id).toContain(".unpinned.");
  });

  it("accepts SHA-pinned actions and official tags when allowed", async () => {
    const findings = await scanWorkflow(
      [
        "on: push",
        "permissions: read-all",
        "jobs:",
        "  a:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        `      - uses: third/party@${sha}`,
        "      - uses: actions/checkout@v4"
      ].join("\n")
    );
    expect(findings.some((f) => f.ruleId === "workflow.action-unpinned")).toBe(false);
  });

  it("detects a wider range of untrusted expressions, including github-script", async () => {
    const expressions = [
      "${{ github.head_ref }}",
      "${{ github.event.issue.title }}",
      "${{ github.event.comment.body }}",
      "${{ github.event.head_commit.message }}",
      "${{ github.event.pull_request.head.ref }}",
      "${{ github.event.workflow_run.head_branch }}"
    ];
    for (const expression of expressions) {
      const findings = await scanWorkflow(
        ["on: push", "permissions: read-all", "jobs:", "  a:", "    runs-on: x", "    steps:", `      - run: echo "${expression}"`].join("\n")
      );
      expect(findings.some((f) => f.ruleId === "workflow.untrusted-expression"), expression).toBe(true);
    }

    const script = await scanWorkflow(
      [
        "on: push",
        "permissions: read-all",
        "jobs:",
        "  a:",
        "    runs-on: x",
        "    steps:",
        "      - uses: actions/github-script@v7",
        "        with:",
        "          script: console.log('${{ github.event.issue.body }}')"
      ].join("\n")
    );
    expect(script.some((f) => f.ruleId === "workflow.untrusted-expression")).toBe(true);

    const safe = await scanWorkflow(
      ["on: push", "permissions: read-all", "jobs:", "  a:", "    runs-on: x", "    steps:", "      - run: echo \"${{ github.sha }}\""].join("\n")
    );
    expect(safe.some((f) => f.ruleId === "workflow.untrusted-expression")).toBe(false);
  });

  it("reports an unparsable workflow without losing findings from other files", async () => {
    const cwd = await tempProject({
      ".github/workflows/broken.yml": "on: [unclosed\n  jobs: : :",
      ".github/workflows/ok.yml": "on: pull_request_target\npermissions: read-all\njobs: {}\n"
    });
    const findings = await new WorkflowHardeningScanner().scan({
      cwd,
      config: loadConfig({ cwd }),
      toolRunner: runnerReturning(0)
    });
    expect(findings.some((f) => f.id.startsWith("tooling.workflow.parse-failed."))).toBe(true);
    expect(findings.some((f) => f.ruleId === "workflow.pull-request-target")).toBe(true);
  });
});
