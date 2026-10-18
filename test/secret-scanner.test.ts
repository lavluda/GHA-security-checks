import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/core/config.js";
import { SecretScanner } from "../src/scanners/secrets/secret-scanner.js";
import type { ToolRunner } from "../src/integrations/tool-runner.js";
import { runnerReturning, tempProject } from "./helpers.js";

const toolRunner: ToolRunner = {
  async run(command, args) {
    return { command, args, exitCode: 0, stdout: "", stderr: "" };
  }
};

describe("SecretScanner", () => {
  it("reports explicit secret files and configured patterns", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "gha-security-checks-"));
    mkdirSync(join(cwd, "src"));
    writeFileSync(join(cwd, ".env"), "TOKEN=abc\n", "utf8");
    writeFileSync(
      join(cwd, "src", "config.php"),
      "api_key = \"12345678901234567890\";\n",
      "utf8"
    );

    const config = loadConfig({ cwd });
    const scanner = new SecretScanner();
    const findings = await scanner.scan({ cwd, config, toolRunner });

    expect(findings.some((finding) => finding.id.startsWith("secret.file."))).toBe(true);
    expect(findings.some((finding) => finding.id.startsWith("secret.pattern."))).toBe(true);
  });
});


async function scanProject(
  files: Record<string, string>,
  overrides: Parameters<typeof loadConfig>[0]["overrides"] = {}
) {
  const cwd = await tempProject(files);
  const config = loadConfig({ cwd, overrides });
  return new SecretScanner().scan({ cwd, config, toolRunner: runnerReturning(0) });
}

const awsKey = "AKIAIOSFODNN7EXAMPLE";

describe("SecretScanner — details", () => {
  it("reports the correct line number and redacts the match", async () => {
    const findings = await scanProject({ "a.txt": `one\ntwo\nkey=${awsKey}\n` });
    const finding = findings.find((f) => f.metadata?.pattern === "aws-access-key");
    expect(finding?.location).toEqual({ file: "a.txt", startLine: 3 });
    expect(finding?.metadata?.matchPreview).toBe("AKIA...[redacted]");
  });

  it("keeps finding ids stable when the secret moves to another line", async () => {
    const before = await scanProject({ "a.txt": `key=${awsKey}\n` });
    const after = await scanProject({ "a.txt": `# comment\n\n\nkey=${awsKey}\n` });
    expect(before[0]?.id).toBe(after[0]?.id);
    expect(before[0]?.location?.startLine).not.toBe(after[0]?.location?.startLine);
  });

  it("gives repeated identical secrets in one file distinct ids", async () => {
    const findings = await scanProject({ "a.txt": `${awsKey}\n${awsKey}\n` });
    const ids = findings.map((f) => f.id);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
  });

  it("does not hang on a custom pattern that can match the empty string", async () => {
    const findings = await scanProject(
      { "a.txt": "aaa bbb\n" },
      { secrets: { patterns: [{ id: "empty", label: "Empty", regex: "x*", severity: "low" }] } }
    );
    expect(findings).toEqual([]);
  });

  it("only scans files matching secrets.include when it is set", async () => {
    const files = { "src/a.txt": awsKey, "docs/b.txt": awsKey };
    const all = await scanProject(files);
    const limited = await scanProject(files, { secrets: { include: ["src/**"] } });
    expect(all).toHaveLength(2);
    expect(limited.map((f) => f.location?.file)).toEqual(["src/a.txt"]);
  });

  it("skips binary files", async () => {
    const findings = await scanProject({ "blob.bin": `\u0000${awsKey}` });
    expect(findings).toEqual([]);
  });

  it("does not flag .env template files", async () => {
    const findings = await scanProject({ ".env.example": "X=1", ".env.sample": "X=1", ".env.production": "X=1" });
    expect(findings.filter((f) => f.id.startsWith("secret.file.")).map((f) => f.location?.file)).toEqual([
      ".env.production"
    ]);
  });

  it("flags .npmrc only when it contains a literal credential", async () => {
    const literal = await scanProject({ ".npmrc": "//registry.npmjs.org/:_authToken=abc123def456\n" });
    const envRef = await scanProject({ ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n" });
    const plain = await scanProject({ ".npmrc": "save-exact=true\n" });
    expect(literal.some((f) => f.id === "secret.file..npmrc")).toBe(true);
    expect(envRef.some((f) => f.id.startsWith("secret.file."))).toBe(false);
    expect(plain.some((f) => f.id.startsWith("secret.file."))).toBe(false);
  });

  it("rejects an invalid custom regex at config load time", () => {
    expect(() =>
      loadConfig({
        cwd: process.cwd(),
        overrides: { secrets: { patterns: [{ id: "bad", label: "Bad", regex: "(", severity: "low" }] } }
      })
    ).toThrow();
  });
});
