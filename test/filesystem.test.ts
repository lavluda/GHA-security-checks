import { describe, expect, it } from "vitest";
import { globToRegExp, listWorkflowFiles, matchesAnyGlob } from "../src/core/filesystem.js";
import { tempProject } from "./helpers.js";

describe("globToRegExp", () => {
  it("handles *, ** and ?", () => {
    expect(globToRegExp("src/*.ts").test("src/a.ts")).toBe(true);
    expect(globToRegExp("src/*.ts").test("src/deep/a.ts")).toBe(false);
    expect(globToRegExp("src/**").test("src/deep/a.ts")).toBe(true);
    expect(globToRegExp("**/*.yml").test("a.yml")).toBe(true);
    expect(globToRegExp("**/*.yml").test(".github/workflows/a.yml")).toBe(true);
    expect(globToRegExp("a?.txt").test("ab.txt")).toBe(true);
    expect(globToRegExp("a?.txt").test("a/.txt")).toBe(false);
  });

  it("escapes regex metacharacters", () => {
    expect(globToRegExp("a.b").test("axb")).toBe(false);
    expect(globToRegExp("a+(b)").test("a+(b)")).toBe(true);
  });

  it("matchesAnyGlob normalises Windows separators", () => {
    expect(matchesAnyGlob("src\\a.ts", ["src/*.ts"])).toBe(true);
  });
});

describe("listWorkflowFiles", () => {
  it("returns only yaml files under the workflow dir, as repo-relative paths", async () => {
    const cwd = await tempProject({
      ".github/workflows/a.yml": "on: push",
      ".github/workflows/b.yaml": "on: push",
      ".github/workflows/readme.md": "x",
      ".github/other/c.yml": "on: push",
      "node_modules/pkg/.github/workflows/d.yml": "on: push"
    });
    expect(listWorkflowFiles(cwd, ".github/workflows").sort()).toEqual([
      ".github/workflows/a.yml",
      ".github/workflows/b.yaml"
    ]);
  });

  it("tolerates a trailing slash and a missing directory", async () => {
    const cwd = await tempProject({ ".github/workflows/a.yml": "on: push" });
    expect(listWorkflowFiles(cwd, ".github/workflows/")).toEqual([".github/workflows/a.yml"]);
    expect(listWorkflowFiles(cwd, "nope")).toEqual([]);
  });
});
