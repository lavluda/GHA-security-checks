import { writeFileSync } from "node:fs";
import type { Finding, ScanResult } from "../core/finding.js";

interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          defaultConfiguration: { level: string };
          properties: { tags: string[]; "security-severity"?: string };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: string;
      message: { text: string };
      locations?: Array<{
        physicalLocation: {
          artifactLocation: { uri: string; uriBaseId: string };
          region?: { startLine: number };
        };
      }>;
      partialFingerprints: Record<string, string>;
      suppressions?: Array<{ kind: "external"; justification?: string }>;
      properties?: Record<string, unknown>;
    }>;
  }>;
}

export function writeSarifReport(result: ScanResult, path: string): void {
  writeFileSync(path, `${JSON.stringify(toSarif(result), null, 2)}\n`, "utf8");
}

export function toSarif(result: ScanResult): SarifLog {
  // One rule per kind of check, not per finding instance, so GitHub groups alerts sensibly.
  const rulesById = new Map<string, Finding>();

  for (const finding of result.findings) {
    const key = ruleKey(finding);
    if (!rulesById.has(key)) {
      rulesById.set(key, finding);
    }
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "gha-security-checks",
            informationUri: "https://github.com/lavluda/GHA-security-checks",
            rules: [...rulesById.entries()].map(([id, finding]) => ({
              id,
              name: finding.title,
              shortDescription: { text: finding.title },
              fullDescription: { text: finding.description },
              defaultConfiguration: { level: sarifLevel(finding.severity) },
              properties: {
                tags: ["security", finding.category],
                ...securitySeverity(finding.severity)
              }
            }))
          }
        },
        results: result.findings.map((finding) => ({
          ruleId: ruleKey(finding),
          level: sarifLevel(finding.severity),
          message: { text: `${finding.title}. ${finding.description}` },
          locations: finding.location
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: finding.location.file, uriBaseId: "%SRCROOT%" },
                    region: finding.location.startLine
                      ? { startLine: finding.location.startLine }
                      : undefined
                  }
                }
              ]
            : undefined,
          partialFingerprints: { "ghaSecurityChecks/findingId": finding.id },
          suppressions:
            finding.status === "suppressed"
              ? [{ kind: "external" as const, justification: suppressionJustification(finding) }]
              : undefined,
          properties: {
            category: finding.category,
            scanner: finding.scanner,
            status: finding.status,
            packageName: finding.packageName,
            installedVersion: finding.installedVersion,
            fixedVersion: finding.fixedVersion
          }
        }))
      }
    ]
  };
}

function ruleKey(finding: Finding): string {
  return finding.ruleId ?? finding.id;
}

function suppressionJustification(finding: Finding): string {
  const reason = finding.metadata?.suppressionReason;
  if (typeof reason === "string" && reason.length > 0) {
    return reason;
  }
  return finding.metadata?.baselined ? "Present in the baseline." : "Suppressed by configuration.";
}

/** GitHub Code Scanning derives the displayed severity of security alerts from this CVSS-like value. */
function securitySeverity(severity: Finding["severity"]): { "security-severity"?: string } {
  const scores: Partial<Record<Finding["severity"], string>> = {
    critical: "9.5",
    high: "8.0",
    medium: "5.5",
    low: "3.0"
  };
  const score = scores[severity];
  return score ? { "security-severity": score } : {};
}

function sarifLevel(severity: Finding["severity"]): string {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium" || severity === "low") {
    return "warning";
  }
  return "note";
}
