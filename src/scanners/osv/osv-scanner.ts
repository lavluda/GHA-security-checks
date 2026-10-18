import { basename, isAbsolute, relative } from "node:path";
import type { Finding } from "../../core/finding.js";
import { parseJson } from "../../core/json.js";
import type { Scanner, ScannerContext } from "../../core/scanner.js";
import { toolUnavailableFinding, unparsableOutputFinding } from "../../core/tooling.js";

interface OsvPackage {
  name?: string;
  version?: string;
  ecosystem?: string;
}

interface OsvVulnerability {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  severity?: Array<{ type?: string; score?: string }>;
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
  database_specific?: Record<string, unknown>;
}

interface OsvGroup {
  ids?: string[];
  aliases?: string[];
  max_severity?: string;
}

interface OsvPackageResult {
  package?: OsvPackage;
  vulnerabilities?: OsvVulnerability[];
  groups?: OsvGroup[];
}

interface OsvSource {
  path?: string;
  type?: string;
}

interface OsvResult {
  source?: OsvSource;
  packages?: OsvPackageResult[];
}

interface OsvJson {
  results?: OsvResult[];
}

const lockfileNames = new Set([
  "composer.lock",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Pipfile.lock",
  "Gemfile.lock",
  "go.sum",
  "Cargo.lock"
]);

export class OsvScanner implements Scanner {
  readonly name = "osv-scanner";

  async scan(context: ScannerContext): Promise<Finding[]> {
    if (!context.config.scanners.osv) {
      return [];
    }

    // In diff mode, skip if no lockfile was changed
    if (context.changedFiles !== undefined) {
      if (![...context.changedFiles].some((file) => lockfileNames.has(basename(file)))) {
        return [];
      }
    }

    const result = await context.toolRunner.run(
      context.config.tools.osvScanner,
      ["scan", "source", "--format=json", "--recursive", context.cwd],
      { cwd: context.cwd }
    );

    const unavailable = toolUnavailableFinding(this.name, "tooling.osv-scanner", "OSV-Scanner", result);
    if (unavailable) {
      return [unavailable];
    }

    // osv-scanner exits with 128 when it finds no scannable sources.
    if (result.exitCode === 128) {
      return [];
    }

    const parsed = parseJson<OsvJson>(result.stdout);
    if (!parsed) {
      return [unparsableOutputFinding(this.name, "tooling.osv-scanner", "OSV-Scanner", result)];
    }

    const findings = new Map<string, Finding>();
    for (const resultEntry of parsed.results ?? []) {
      const sourcePath = relativeSourcePath(context.cwd, resultEntry.source?.path);
      for (const pkgResult of resultEntry.packages ?? []) {
        const packageName = pkgResult.package?.name ?? "unknown-package";
        for (const vulnerability of pkgResult.vulnerabilities ?? []) {
          const vulnId = vulnerability.id ?? vulnerability.aliases?.[0] ?? "unknown";
          const id = `osv.${packageName}.${vulnId}`;
          if (findings.has(id)) {
            continue;
          }
          findings.set(id, {
            id,
            ruleId: `osv.${vulnId}`,
            title: vulnerability.summary ?? `Vulnerability in ${packageName}`,
            description:
              vulnerability.details ?? `OSV reported a vulnerability for ${packageName}.`,
            category: "vulnerability",
            severity: normalizeOsvSeverity(vulnerability, pkgResult.groups),
            scanner: this.name,
            status: "open",
            packageName,
            installedVersion: pkgResult.package?.version,
            fixedVersion: findFixedVersion(vulnerability),
            location: sourcePath ? { file: sourcePath } : undefined,
            references: vulnerability.id
              ? [`https://osv.dev/vulnerability/${vulnerability.id}`]
              : undefined,
            metadata: {
              aliases: vulnerability.aliases,
              ecosystem: pkgResult.package?.ecosystem,
              modified: vulnerability.modified,
              severity: vulnerability.severity,
              databaseSpecific: vulnerability.database_specific
            }
          });
        }
      }
    }

    return [...findings.values()];
  }
}

function relativeSourcePath(cwd: string, path: string | undefined): string | undefined {
  if (!path) {
    return undefined;
  }
  const value = isAbsolute(path) ? relative(cwd, path) : path;
  return value.replace(/\\/g, "/");
}

function severityFromScore(score: number): Finding["severity"] {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function normalizeOsvSeverity(
  vulnerability: OsvVulnerability,
  groups: OsvGroup[] = []
): Finding["severity"] {
  // osv-scanner reports a numeric CVSS base score per vulnerability group.
  const knownIds = new Set([vulnerability.id, ...(vulnerability.aliases ?? [])].filter(Boolean));
  const group = groups.find((candidate) =>
    [...(candidate.ids ?? []), ...(candidate.aliases ?? [])].some((id) => knownIds.has(id))
  );
  const score = Number(group?.max_severity);
  if (group?.max_severity !== undefined && group.max_severity !== "" && !Number.isNaN(score)) {
    return severityFromScore(score);
  }

  // Many OSV databases (GHSA, ...) carry a plain-text rating instead.
  const label = vulnerability.database_specific?.severity;
  if (typeof label === "string") {
    switch (label.toUpperCase()) {
      case "CRITICAL":
        return "critical";
      case "HIGH":
        return "high";
      case "MODERATE":
      case "MEDIUM":
        return "medium";
      case "LOW":
        return "low";
    }
  }

  return "medium";
}

function findFixedVersion(vulnerability: OsvVulnerability): string | undefined {
  for (const affected of vulnerability.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) {
          return event.fixed;
        }
      }
    }
  }
  return undefined;
}
