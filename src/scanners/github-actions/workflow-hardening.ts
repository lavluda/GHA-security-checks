import { readFileSync } from "node:fs";
import { join } from "node:path";
import YAML from "yaml";
import { listWorkflowFiles } from "../../core/filesystem.js";
import type { Finding } from "../../core/finding.js";
import type { Scanner, ScannerContext } from "../../core/scanner.js";

interface WorkflowJob {
  permissions?: unknown;
  uses?: unknown;
  steps?: Array<Record<string, unknown>>;
}

interface WorkflowDocument {
  on?: unknown;
  permissions?: unknown;
  jobs?: Record<string, WorkflowJob>;
}

const fullShaPattern = /^[a-f0-9]{40}$/i;

// Context values an outside contributor controls (titles, bodies, branch names, commit messages, ...).
const untrustedExpressionPattern = new RegExp(
  String.raw`\$\{\{[^}]*\b(?:` +
    [
      String.raw`github\.head_ref`,
      String.raw`github\.event\.(?:issue|pull_request|discussion)\.(?:title|body)`,
      String.raw`github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)`,
      String.raw`github\.event\.(?:comment|review|review_comment)\.body`,
      String.raw`github\.event\.pages\.[^.}]*\.page_name`,
      String.raw`github\.event\.commits\.[^.}]*\.(?:message|author\.(?:name|email))`,
      String.raw`github\.event\.head_commit\.(?:message|author\.(?:name|email))`,
      String.raw`github\.event\.workflow_run\.(?:head_branch|head_commit\.message|head_repository\.description|pull_requests\.[^.}]*\.head\.ref)`
    ].join("|") +
    String.raw`)`,
  "i"
);

export class WorkflowHardeningScanner implements Scanner {
  readonly name = "github-actions-hardening";

  async scan(context: ScannerContext): Promise<Finding[]> {
    if (!context.config.scanners.githubActions) {
      return [];
    }

    const allFiles = listWorkflowFiles(context.cwd, context.config.githubActions.workflowDir);

    // In diff mode, only check workflow files that were changed
    const files =
      context.changedFiles !== undefined
        ? allFiles.filter((f) => context.changedFiles!.has(f))
        : allFiles;

    const findings: Finding[] = [];

    for (const file of files) {
      let workflow: WorkflowDocument | null;
      try {
        workflow = YAML.parse(readFileSync(join(context.cwd, file), "utf8")) as WorkflowDocument | null;
      } catch (error) {
        findings.push({
          id: `tooling.workflow.parse-failed.${file}`,
          title: `Workflow could not be parsed: ${file}`,
          description: error instanceof Error ? error.message.split("\n")[0] ?? "Invalid YAML." : "Invalid YAML.",
          category: "tooling",
          severity: "info",
          scanner: this.name,
          status: "skipped",
          location: { file }
        });
        continue;
      }
      if (!workflow || typeof workflow !== "object") {
        continue;
      }

      findings.push(...checkWorkflowTriggers(file, workflow));
      findings.push(...checkPermissions(file, workflow));
      findings.push(...checkSteps(file, workflow, context.config.githubActions.allowUnpinnedOfficialActions));
    }

    return findings;
  }
}

function checkWorkflowTriggers(file: string, workflow: WorkflowDocument): Finding[] {
  const events = normalizeEvents(workflow.on);
  const findings: Finding[] = [];

  if (events.includes("pull_request_target")) {
    findings.push({
      id: `workflow.pull-request-target.${file}`,
      ruleId: "workflow.pull-request-target",
      title: "Workflow uses pull_request_target",
      description:
        "pull_request_target runs with elevated repository context. Review checkout and script steps carefully.",
      category: "workflow-risk",
      severity: "high",
      scanner: "github-actions-hardening",
      status: "open",
      location: { file }
    });
  }

  if (events.includes("workflow_run")) {
    findings.push({
      id: `workflow.workflow-run.${file}`,
      ruleId: "workflow.workflow-run",
      title: "Workflow uses workflow_run",
      description:
        "workflow_run runs with repository secrets and write access even when triggered by a fork's workflow. Never check out or execute artifacts from the triggering run without validating them.",
      category: "workflow-risk",
      severity: "medium",
      scanner: "github-actions-hardening",
      status: "open",
      location: { file }
    });
  }

  return findings;
}

function checkPermissions(file: string, workflow: WorkflowDocument): Finding[] {
  const findings: Finding[] = [];

  const jobs = Object.values(workflow.jobs ?? {});
  const everyJobSetsPermissions = jobs.length > 0 && jobs.every((job) => job.permissions !== undefined);

  if (workflow.permissions === undefined && !everyJobSetsPermissions) {
    findings.push({
      id: `workflow.permissions.missing.${file}`,
      ruleId: "workflow.permissions.missing",
      title: "Workflow does not set top-level permissions",
      description: "Set least-privilege GITHUB_TOKEN permissions at workflow or job level.",
      category: "workflow-risk",
      severity: "medium",
      scanner: "github-actions-hardening",
      status: "open",
      location: { file }
    });
  }

  if (hasWriteAllPermissions(workflow.permissions)) {
    findings.push({
      id: `workflow.permissions.write-all.${file}`,
      ruleId: "workflow.permissions.write-all",
      title: "Workflow grants broad write permissions",
      description: "Avoid write-all permissions unless every permission is required.",
      category: "workflow-risk",
      severity: "high",
      scanner: "github-actions-hardening",
      status: "open",
      location: { file }
    });
  }

  for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
    if (hasWriteAllPermissions(job.permissions)) {
      findings.push({
        id: `workflow.job-permissions.write-all.${file}.${jobName}`,
        ruleId: "workflow.job-permissions.write-all",
        title: `Job grants broad write permissions: ${jobName}`,
        description: "Avoid write-all job permissions unless every permission is required.",
        category: "workflow-risk",
        severity: "high",
        scanner: "github-actions-hardening",
        status: "open",
        location: { file }
      });
    }
  }

  return findings;
}

function checkSteps(file: string, workflow: WorkflowDocument, allowOfficialTags: boolean): Finding[] {
  const findings: Finding[] = [];

  for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
    // Reusable workflows are referenced at job level and carry the same supply-chain risk.
    if (typeof job.uses === "string" && shouldFlagActionRef(job.uses, allowOfficialTags)) {
      findings.push({
        id: `workflow.action-unpinned.${file}.${jobName}.job`,
        ruleId: "workflow.action-unpinned",
        title: `Reusable workflow is not pinned to a full commit SHA: ${job.uses}`,
        description: "Pin reusable workflows to a full commit SHA to reduce supply-chain risk.",
        category: "workflow-risk",
        severity: "medium",
        scanner: "github-actions-hardening",
        status: "open",
        location: { file }
      });
    }

    for (const [index, step] of (job.steps ?? []).entries()) {
      const uses = typeof step.uses === "string" ? step.uses : undefined;
      if (uses && shouldFlagActionRef(uses, allowOfficialTags)) {
        findings.push({
          id: `workflow.action-unpinned.${file}.${jobName}.${index}`,
          ruleId: "workflow.action-unpinned",
          title: `Action is not pinned to a full commit SHA: ${uses}`,
          description:
            "Pin third-party actions to a full commit SHA to reduce supply-chain risk.",
          category: "workflow-risk",
          severity: "medium",
          scanner: "github-actions-hardening",
          status: "open",
          location: { file }
        });
      }

      const withInputs =
        step.with && typeof step.with === "object" ? (step.with as Record<string, unknown>) : {};
      const script =
        typeof step.run === "string"
          ? step.run
          : uses?.startsWith("actions/github-script@") && typeof withInputs.script === "string"
            ? withInputs.script
            : undefined;
      if (script && containsUntrustedGithubExpression(script)) {
        findings.push({
          id: `workflow.untrusted-expression.${file}.${jobName}.${index}`,
          ruleId: "workflow.untrusted-expression",
          title: "Step references untrusted event data in a script",
          description:
            "Avoid injecting untrusted GitHub context directly into shell commands.",
          category: "workflow-risk",
          severity: "high",
          scanner: "github-actions-hardening",
          status: "open",
          location: { file }
        });
      }
    }
  }

  return findings;
}

function normalizeEvents(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((event): event is string => typeof event === "string");
  }
  if (value && typeof value === "object") {
    return Object.keys(value);
  }
  return [];
}

function hasWriteAllPermissions(value: unknown): boolean {
  return value === "write-all";
}

function shouldFlagActionRef(uses: string, allowOfficialTags: boolean): boolean {
  if (uses.startsWith("./") || uses.startsWith("docker://")) {
    return false;
  }

  const [ownerRepo, ref] = uses.split("@");
  if (!ref) {
    return true;
  }

  if (fullShaPattern.test(ref)) {
    return false;
  }

  if (allowOfficialTags && ownerRepo.startsWith("actions/")) {
    return false;
  }

  return true;
}

function containsUntrustedGithubExpression(value: string): boolean {
  return untrustedExpressionPattern.test(value);
}
