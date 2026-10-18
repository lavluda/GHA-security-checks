import { matchesAnyGlob } from "./filesystem.js";
import type { Finding } from "./finding.js";
import type { SecurityCheckConfig } from "./config.js";

type Suppression = SecurityCheckConfig["suppressions"][number];

function matches(entry: Suppression, finding: Finding): boolean {
  if (!entry.id && !entry.category && !entry.path) {
    return false;
  }
  if (entry.id && entry.id !== finding.id) {
    return false;
  }
  if (entry.category && entry.category !== finding.category) {
    return false;
  }
  if (entry.path) {
    const file = finding.location?.file;
    if (!file || !matchesAnyGlob(file, [entry.path])) {
      return false;
    }
  }
  return true;
}

/** Marks open findings that match a configured suppression entry as suppressed. */
export function applySuppressions(
  findings: Finding[],
  suppressions: SecurityCheckConfig["suppressions"]
): Finding[] {
  if (suppressions.length === 0) {
    return findings;
  }

  return findings.map((finding) => {
    if (finding.status !== "open") {
      return finding;
    }
    const entry = suppressions.find((candidate) => matches(candidate, finding));
    return entry
      ? {
          ...finding,
          status: "suppressed" as const,
          metadata: { ...finding.metadata, suppressed: true, suppressionReason: entry.reason }
        }
      : finding;
  });
}
