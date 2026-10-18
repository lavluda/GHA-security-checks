import { describe, expect, it } from "vitest";
import { ChildProcessToolRunner } from "../src/integrations/tool-runner.js";

describe("ChildProcessToolRunner", () => {
  const runner = new ChildProcessToolRunner();

  it("captures output and exit code", async () => {
    const result = await runner.run(process.execPath, ["-e", "console.log('hi'); process.exit(3)"]);
    expect(result.exitCode).toBe(3);
    expect(result.stdout.trim()).toBe("hi");
  });

  it("returns 127 when the command does not exist", async () => {
    const result = await runner.run("definitely-not-a-real-command-xyz", []);
    expect(result.exitCode).toBe(127);
  });

  it("kills the process and returns 124 when it exceeds the timeout", async () => {
    const started = Date.now();
    const result = await runner.run(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], {
      timeoutMs: 300
    });
    expect(result.exitCode).toBe(124);
    expect(result.stderr).toContain("Timed out");
    expect(Date.now() - started).toBeLessThan(10_000);
  });
});
