import { execFileSync } from "node:child_process";
import { env } from "node:process";

function git(cwd: string, args: string[]): string {
  // safe.directory: inside the Docker action the workspace is owned by a different user than root.
  return execFileSync("git", ["-c", `safe.directory=${cwd}`, ...args], {
    cwd,
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 60_000
  })
    .toString()
    .trim();
}

function refExists(cwd: string, ref: string): boolean {
  try {
    git(cwd, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
    return true;
  } catch {
    return false;
  }
}

/** Branch names starting with "-" would be parsed as git options. */
function isSafeRefName(name: string): boolean {
  return name.length > 0 && !name.startsWith("-") && !/[\s\0]/.test(name);
}

function resolveBase(cwd: string): string {
  const baseRef = env.GITHUB_BASE_REF;
  if (baseRef) {
    if (!isSafeRefName(baseRef)) {
      throw new Error(`Unsafe base ref: ${baseRef}`);
    }
    const remoteRef = `origin/${baseRef}`;
    if (!refExists(cwd, remoteRef)) {
      // actions/checkout fetches a single commit by default, so the base branch may be missing.
      git(cwd, [
        "fetch",
        "--no-tags",
        "--depth=100",
        "origin",
        `+refs/heads/${baseRef}:refs/remotes/origin/${baseRef}`
      ]);
    }
    return remoteRef;
  }

  // Local dev — find the common ancestor with origin/main
  return git(cwd, ["merge-base", "HEAD", "origin/main"]);
}

/**
 * Resolves the set of files changed vs the PR base (or origin/main).
 * Returns undefined if git is unavailable — callers should fall back to a full scan.
 */
export function getChangedFiles(cwd: string): Set<string> | undefined {
  try {
    const base = resolveBase(cwd);

    let output: string;
    try {
      output = git(cwd, ["diff", "--name-only", `${base}...HEAD`]);
    } catch {
      // Shallow history may have no merge base; compare the trees directly instead.
      output = git(cwd, ["diff", "--name-only", base, "HEAD"]);
    }

    if (!output) return new Set();

    return new Set(
      output
        .split("\n")
        .map((f) => f.trim())
        .filter(Boolean)
    );
  } catch (error) {
    console.warn(
      `gha-security-checks: could not determine changed files (${
        error instanceof Error ? error.message.split("\n")[0] : String(error)
      }); falling back to a full scan.`
    );
    return undefined;
  }
}
