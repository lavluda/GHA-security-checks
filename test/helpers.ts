import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { ToolResult, ToolRunner } from "../src/integrations/tool-runner.js";

export interface RecordingRunner extends ToolRunner {
  calls: Array<{ command: string; args: string[] }>;
}

export function runnerReturning(exitCode: number, stdout: unknown = "", stderr = ""): RecordingRunner {
  const calls: RecordingRunner["calls"] = [];
  return {
    calls,
    async run(command, args): Promise<ToolResult> {
      calls.push({ command, args });
      return {
        command,
        args,
        exitCode,
        stdout: typeof stdout === "string" ? stdout : JSON.stringify(stdout),
        stderr
      };
    }
  };
}

export async function tempProject(files: Record<string, string> = {}): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "gha-test-"));
  for (const [name, content] of Object.entries(files)) {
    const full = join(cwd, name);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content, "utf8");
  }
  return cwd;
}
