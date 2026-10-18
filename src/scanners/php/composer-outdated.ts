import { hasFile } from "../../core/filesystem.js";
import type { Finding } from "../../core/finding.js";
import { parseJson } from "../../core/json.js";
import type { Scanner, ScannerContext } from "../../core/scanner.js";
import { toolUnavailableFinding, unparsableOutputFinding } from "../../core/tooling.js";

interface ComposerOutdatedPackage {
  name?: string;
  version?: string;
  latest?: string;
  "latest-status"?: string;
  description?: string;
}

interface ComposerOutdatedJson {
  installed?: ComposerOutdatedPackage[];
}

export class ComposerOutdatedScanner implements Scanner {
  readonly name = "composer-outdated";

  async scan(context: ScannerContext): Promise<Finding[]> {
    if (!context.config.scanners.php || !context.config.php.composerOutdated) {
      return [];
    }

    if (!hasFile(context.cwd, "composer.json")) {
      return [];
    }

    // In diff mode, skip if no PHP manifest was changed
    if (context.changedFiles !== undefined) {
      const manifests = ["composer.json", "composer.lock"];
      if (!manifests.some((m) => context.changedFiles!.has(m))) {
        return [];
      }
    }

    // Without --locked Composer inspects the installed vendor/ directory, which is empty on a fresh checkout.
    const args = ["outdated", "--format=json", "--no-interaction"];
    if (hasFile(context.cwd, "composer.lock")) {
      args.push("--locked");
    }

    const result = await context.toolRunner.run(context.config.tools.composer, args, {
      cwd: context.cwd
    });

    const unavailable = toolUnavailableFinding(
      this.name,
      "tooling.composer.outdated",
      "Composer outdated",
      result
    );
    if (unavailable) {
      return [unavailable];
    }

    const parsed = parseJson<ComposerOutdatedJson>(result.stdout);
    if (!parsed) {
      return [
        unparsableOutputFinding(this.name, "tooling.composer.outdated", "Composer outdated", result)
      ];
    }

    return (parsed.installed ?? [])
      .filter((pkg) => pkg.name && pkg.version && pkg.latest && pkg.version !== pkg.latest)
      .map((pkg) => ({
        id: `composer.outdated.${pkg.name}`,
        ruleId: "composer.outdated",
        title: `Outdated Composer package: ${pkg.name}`,
        description: `${pkg.name} is installed at ${pkg.version} and latest is ${pkg.latest}.`,
        category: "outdated-dependency" as const,
        severity: normalizeLatestStatus(pkg["latest-status"]),
        scanner: this.name,
        status: "open" as const,
        packageName: pkg.name,
        installedVersion: pkg.version,
        fixedVersion: pkg.latest,
        metadata: {
          latestStatus: pkg["latest-status"],
          description: pkg.description
        }
      }));
  }
}

function normalizeLatestStatus(status?: string): Finding["severity"] {
  if (status === "semver-safe-update") {
    return "low";
  }
  if (status === "update-possible") {
    return "medium";
  }
  return "info";
}
