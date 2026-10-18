import { hasFile } from "../../core/filesystem.js";
import { severityRank, type Finding } from "../../core/finding.js";
import { parseJson } from "../../core/json.js";
import type { Scanner, ScannerContext } from "../../core/scanner.js";
import {
  skippedToolFinding,
  toolUnavailableFinding,
  unparsableOutputFinding
} from "../../core/tooling.js";

interface NpmAuditVulnerability {
  name?: string;
  severity?: string;
  title?: string;
  url?: string;
  range?: string;
  via?: Array<string | { title?: string; url?: string; severity?: string; range?: string }>;
  fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
}

interface NpmAuditJson {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  error?: { code?: string; summary?: string; detail?: string };
}

interface NpmAdvisory {
  title?: string;
  url?: string;
  severity?: string;
  range?: string;
}

export class NpmAuditScanner implements Scanner {
  readonly name = "npm-audit";

  async scan(context: ScannerContext): Promise<Finding[]> {
    if (!context.config.scanners.node || !context.config.node.npmAudit) {
      return [];
    }

    if (!hasFile(context.cwd, "package.json")) {
      return [];
    }

    // In diff mode, skip if no Node manifest was changed
    if (context.changedFiles !== undefined) {
      const manifests = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"];
      if (!manifests.some((m) => context.changedFiles!.has(m))) {
        return [];
      }
    }

    const result = await context.toolRunner.run(
      context.config.tools.npm,
      ["audit", "--json"],
      { cwd: context.cwd }
    );

    const unavailable = toolUnavailableFinding(this.name, "tooling.npm.audit", "npm audit", result);
    if (unavailable) {
      return [unavailable];
    }

    const parsed = parseJson<NpmAuditJson>(result.stdout);
    if (!parsed) {
      return [unparsableOutputFinding(this.name, "tooling.npm.audit", "npm audit", result)];
    }

    if (parsed.error) {
      return [
        skippedToolFinding(
          this.name,
          "tooling.npm.audit.error",
          "npm audit could not run",
          parsed.error.summary ?? parsed.error.detail ?? parsed.error.code ?? "npm audit reported an error."
        )
      ];
    }

    return Object.entries(parsed.vulnerabilities ?? {}).map(([packageName, vulnerability]) => {
      const advisories = advisoriesOf(vulnerability);
      const advisory = advisories[0];
      const fixedVersion = fixedVersionFrom(vulnerability.fixAvailable);

      const references = [
        ...new Set(
          [...advisories.map((entry) => entry.url), vulnerability.url].filter(
            (url): url is string => typeof url === "string"
          )
        )
      ];

      return {
        id: `npm.audit.${packageName}`,
        ruleId: "npm.audit",
        title: advisory?.title ?? vulnerability.title ?? `Vulnerability in ${packageName}`,
        description: buildDescription(packageName, vulnerability, advisories),
        category: "vulnerability" as const,
        severity: highestSeverity([vulnerability.severity, ...advisories.map((a) => a.severity)]),
        scanner: this.name,
        status: "open" as const,
        packageName: vulnerability.name ?? packageName,
        fixedVersion,
        references: references.length > 0 ? references : undefined,
        metadata: {
          range: advisory?.range ?? vulnerability.range,
          fixAvailable: vulnerability.fixAvailable,
          advisories: advisories.map((entry) => entry.title).filter(Boolean)
        }
      };
    });
  }
}

function advisoriesOf(vulnerability: NpmAuditVulnerability): NpmAdvisory[] {
  return (vulnerability.via ?? []).filter(
    (entry): entry is NpmAdvisory => typeof entry === "object" && entry !== null
  );
}

function buildDescription(
  packageName: string,
  vulnerability: NpmAuditVulnerability,
  advisories: NpmAdvisory[]
): string {
  const range = advisories[0]?.range ?? vulnerability.range;
  const parts = [`npm reported a vulnerability for ${packageName}.`];
  if (range) {
    parts.push(`Affected versions: ${range}.`);
  }
  const titles = [...new Set(advisories.map((entry) => entry.title).filter(Boolean))];
  if (titles.length > 1) {
    parts.push(`Advisories: ${titles.join("; ")}.`);
  }
  return parts.join(" ");
}

function highestSeverity(values: Array<string | undefined>): Finding["severity"] {
  const known = values
    .filter((value): value is string => typeof value === "string")
    .map((value) => normalizeSeverity(value));
  if (known.length === 0) {
    return "medium";
  }
  return known.reduce((best, current) =>
    severityRank[current] > severityRank[best] ? current : best
  );
}

function fixedVersionFrom(value: NpmAuditVulnerability["fixAvailable"]): string | undefined {
  if (value && typeof value === "object") {
    return value.version;
  }
  return undefined;
}

function normalizeSeverity(value?: string): Finding["severity"] {
  const normalized = value?.toLowerCase();
  if (
    normalized === "critical" ||
    normalized === "high" ||
    normalized === "medium" ||
    normalized === "low"
  ) {
    return normalized;
  }
  return "medium";
}
