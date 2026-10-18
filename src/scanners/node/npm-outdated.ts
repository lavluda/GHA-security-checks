import { hasFile } from "../../core/filesystem.js";
import type { Finding } from "../../core/finding.js";
import { parseJson } from "../../core/json.js";
import type { Scanner, ScannerContext } from "../../core/scanner.js";
import {
  skippedToolFinding,
  toolUnavailableFinding,
  unparsableOutputFinding
} from "../../core/tooling.js";

interface NpmOutdatedPackage {
  current?: string;
  wanted?: string;
  latest?: string;
  dependent?: string;
  type?: string;
}

export class NpmOutdatedScanner implements Scanner {
  readonly name = "npm-outdated";

  async scan(context: ScannerContext): Promise<Finding[]> {
    if (!context.config.scanners.node || !context.config.node.npmOutdated) {
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

    // npm outdated compares against installed packages; without node_modules every entry is empty.
    if (!hasFile(context.cwd, "node_modules")) {
      return [
        skippedToolFinding(
          this.name,
          "tooling.npm.outdated.not-installed",
          "npm outdated skipped: dependencies are not installed",
          "node_modules was not found. Run `npm ci` before the security checks to enable outdated-package detection."
        )
      ];
    }

    const result = await context.toolRunner.run(
      context.config.tools.npm,
      ["outdated", "--json"],
      { cwd: context.cwd }
    );

    const unavailable = toolUnavailableFinding(
      this.name,
      "tooling.npm.outdated",
      "npm outdated",
      result
    );
    if (unavailable) {
      return [unavailable];
    }

    // Depending on the npm version, an up-to-date project prints nothing instead of "{}".
    if (result.stdout.trim() === "") {
      return [];
    }

    const parsed = parseJson<Record<string, NpmOutdatedPackage>>(result.stdout);
    if (!parsed) {
      return [unparsableOutputFinding(this.name, "tooling.npm.outdated", "npm outdated", result)];
    }

    return Object.entries(parsed)
      .filter(([, pkg]) => pkg.current && pkg.latest && pkg.current !== pkg.latest)
      .map(([packageName, pkg]) => ({
        id: `npm.outdated.${packageName}`,
        ruleId: "npm.outdated",
        title: `Outdated npm package: ${packageName}`,
        description: `${packageName} is installed at ${pkg.current} and latest is ${pkg.latest}.`,
        category: "outdated-dependency" as const,
        severity: normalizeOutdatedSeverity(pkg),
        scanner: this.name,
        status: "open" as const,
        packageName,
        installedVersion: pkg.current,
        fixedVersion: pkg.latest,
        metadata: {
          wanted: pkg.wanted,
          dependent: pkg.dependent,
          type: pkg.type
        }
      }));
  }
}

function normalizeOutdatedSeverity(pkg: NpmOutdatedPackage): Finding["severity"] {
  if (pkg.current && pkg.wanted && pkg.current !== pkg.wanted) {
    return "medium";
  }
  return "low";
}
