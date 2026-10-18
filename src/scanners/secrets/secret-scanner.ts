import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { listFiles, matchesAnyGlob } from "../../core/filesystem.js";
import type { Finding } from "../../core/finding.js";
import type { Scanner, ScannerContext } from "../../core/scanner.js";

export class SecretScanner implements Scanner {
  readonly name = "secret-scanner";

  async scan(context: ScannerContext): Promise<Finding[]> {
    if (!context.config.scanners.secrets) {
      return [];
    }

    const patterns = context.config.secrets.patterns.map((pattern) => ({
      ...pattern,
      expression: new RegExp(pattern.regex, "gi")
    }));

    let files = listFiles({
      root: context.cwd,
      exclude: context.config.secrets.exclude,
      maxFileBytes: context.config.secrets.maxFileBytes
    });

    const include = context.config.secrets.include;
    if (include.length > 0) {
      files = files.filter((file) => matchesAnyGlob(file, include));
    }

    // In diff mode, only scan files that were changed
    if (context.changedFiles !== undefined) {
      files = files.filter((f) => context.changedFiles!.has(f));
    }

    const findings: Finding[] = [];
    const seenIds = new Set<string>();
    const push = (finding: Finding): void => {
      let id = finding.id;
      for (let n = 2; seenIds.has(id); n += 1) {
        id = `${finding.id}.${n}`;
      }
      seenIds.add(id);
      findings.push({ ...finding, id });
    };

    for (const file of files) {
      const content = safeRead(join(context.cwd, file));
      const text = content !== undefined && !isProbablyBinary(content) ? content : undefined;

      if (isExplicitSecretFile(file, text)) {
        push({
          id: `secret.file.${file}`,
          ruleId: "secret.file",
          title: `Sensitive file committed: ${file}`,
          description: "A file commonly used for local secrets is present in the repository.",
          category: "secret",
          severity: "high",
          scanner: this.name,
          status: "open",
          location: { file }
        });
      }

      if (text === undefined) {
        continue;
      }

      const lineStarts = computeLineStarts(text);

      for (const pattern of patterns) {
        pattern.expression.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.expression.exec(text)) !== null) {
          if (match[0].length === 0) {
            // A zero-length match would never advance lastIndex and loop forever.
            pattern.expression.lastIndex += 1;
            continue;
          }

          push({
            id: `secret.pattern.${pattern.id}.${file}.${fingerprint(match[0])}`,
            ruleId: `secret.pattern.${pattern.id}`,
            title: pattern.label,
            description:
              "Potential secret material was found. Rotate the value if it has ever been committed.",
            category: "secret",
            severity: pattern.severity,
            scanner: this.name,
            status: "open",
            location: {
              file,
              startLine: lineForIndex(lineStarts, match.index)
            },
            metadata: {
              pattern: pattern.id,
              matchPreview: redact(match[0])
            }
          });
        }
      }
    }

    return findings;
  }
}

const envTemplateSuffixes = [".example", ".sample", ".dist", ".template", ".tpl"];

function isExplicitSecretFile(file: string, content: string | undefined): boolean {
  const normalized = file.replace(/\\/g, "/").toLowerCase();
  const name = normalized.split("/").at(-1) ?? "";

  if (name === ".env" || (name.startsWith(".env.") && !envTemplateSuffixes.some((s) => name.endsWith(s)))) {
    return true;
  }

  if (name === ".npmrc") {
    // Only an .npmrc that carries a literal credential is sensitive; ${ENV_VAR} references are fine.
    return content !== undefined && /^\s*(?:\/\/\S+:)?_(?:auth|authToken|password)\s*=\s*(?!\$\{)\S+/im.test(content);
  }

  return (
    name === ".htpasswd" ||
    name === "id_rsa" ||
    name === "id_dsa" ||
    name === "id_ecdsa" ||
    name === "id_ed25519" ||
    name.endsWith(".p12") ||
    name.endsWith(".pfx")
  );
}

function safeRead(file: string): string | undefined {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
}

function isProbablyBinary(value: string): boolean {
  return value.includes("\u0000");
}

function computeLineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content.charCodeAt(i) === 10) {
      starts.push(i + 1);
    }
  }
  return starts;
}

function lineForIndex(lineStarts: number[], index: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if ((lineStarts[mid] as number) <= index) {
      low = mid;
    } else {
      high = mid - 1;
    }
  }
  return low + 1;
}

/** Stable across line moves so baselines and suppressions survive unrelated edits. */
function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 10);
}

function redact(value: string): string {
  if (value.length <= 8) {
    return "[redacted]";
  }
  return `${value.slice(0, 4)}...[redacted]`;
}
