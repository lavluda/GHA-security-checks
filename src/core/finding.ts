export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type FindingCategory =
  | "vulnerability"
  | "outdated-dependency"
  | "secret"
  | "workflow-risk"
  | "configuration"
  | "tooling";

export type FindingStatus = "open" | "suppressed" | "fixed" | "skipped";

export interface FindingLocation {
  file: string;
  startLine?: number;
  endLine?: number;
}

export interface Finding {
  id: string;
  /** Stable identifier of the check that produced this finding (shared by all instances). Used as the SARIF rule id. */
  ruleId?: string;
  title: string;
  description: string;
  category: FindingCategory;
  severity: FindingSeverity;
  scanner: string;
  status: FindingStatus;
  location?: FindingLocation;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  references?: string[];
  metadata?: Record<string, unknown>;
}

export interface ScanSummary {
  total: number;
  bySeverity: Record<FindingSeverity, number>;
  byCategory: Record<FindingCategory, number>;
}

export interface ScanResult {
  findings: Finding[];
  summary: ScanSummary;
  failed: boolean;
  mode: string;
  generatedAt: string;
}

export const severityRank: Record<FindingSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function createSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<FindingSeverity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0
  };
  const byCategory: Record<FindingCategory, number> = {
    vulnerability: 0,
    "outdated-dependency": 0,
    secret: 0,
    "workflow-risk": 0,
    configuration: 0,
    tooling: 0
  };

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] += 1;
  }

  return {
    total: findings.length,
    bySeverity,
    byCategory
  };
}
