import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getChangedFiles } from "../src/core/diff.js";

function git(cwd: string, ...args: string[]): string {
  return execFileSync(
    "git",
    ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args],
    { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
}

async function setupRepos() {
  const root = await mkdtemp(join(tmpdir(), "gha-diff-"));
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  mkdirSync(origin);
  git(origin, "init", "--bare", "--initial-branch=main");
  git(root, "clone", origin, work);
  git(work, "checkout", "-b", "main");
  writeFileSync(join(work, "a.txt"), "a");
  git(work, "add", ".");
  git(work, "commit", "-m", "base");
  git(work, "push", "origin", "main");
  git(work, "checkout", "-b", "feature");
  writeFileSync(join(work, "b.txt"), "b");
  writeFileSync(join(work, "a.txt"), "changed");
  git(work, "add", ".");
  git(work, "commit", "-m", "feature");
  return { root, work };
}

describe("getChangedFiles", () => {
  const originalBaseRef = process.env.GITHUB_BASE_REF;

  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalBaseRef === undefined) {
      delete process.env.GITHUB_BASE_REF;
    } else {
      process.env.GITHUB_BASE_REF = originalBaseRef;
    }
  });

  it("returns files changed against the PR base branch", async () => {
    const { work } = await setupRepos();
    process.env.GITHUB_BASE_REF = "main";
    expect(getChangedFiles(work)).toEqual(new Set(["a.txt", "b.txt"]));
  });

  it("fetches the base branch when the checkout does not have it (shallow actions/checkout)", async () => {
    const { work } = await setupRepos();
    git(work, "update-ref", "-d", "refs/remotes/origin/main");
    process.env.GITHUB_BASE_REF = "main";
    expect(getChangedFiles(work)).toEqual(new Set(["a.txt", "b.txt"]));
  });

  it("uses the merge base with origin/main when not in a pull_request event", async () => {
    const { work } = await setupRepos();
    delete process.env.GITHUB_BASE_REF;
    expect(getChangedFiles(work)).toEqual(new Set(["a.txt", "b.txt"]));
  });

  it("never passes a malicious base ref to git as an option or shell command", async () => {
    const { root, work } = await setupRepos();
    const marker = join(root, "pwned");
    process.env.GITHUB_BASE_REF = `--upload-pack=touch ${marker}`;
    expect(getChangedFiles(work)).toBeUndefined();

    process.env.GITHUB_BASE_REF = `main"; touch ${marker}; echo "`;
    expect(getChangedFiles(work)).toBeUndefined();
    expect(existsSync(marker)).toBe(false);
  });

  it("warns and returns undefined outside a git repository", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gha-nogit-"));
    process.env.GITHUB_BASE_REF = "main";
    expect(getChangedFiles(dir)).toBeUndefined();
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("falling back to a full scan"));
  });
});
