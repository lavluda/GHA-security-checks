import { spawn } from "node:child_process";

export const TOOL_MISSING_EXIT_CODE = 127;
export const TOOL_TIMEOUT_EXIT_CODE = 124;
export const DEFAULT_TOOL_TIMEOUT_MS = 5 * 60 * 1000;

export interface ToolResult {
  command: string;
  args: string[];
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface ToolRunOptions {
  cwd?: string;
  timeoutMs?: number;
}

export interface ToolRunner {
  run(command: string, args: string[], options?: ToolRunOptions): Promise<ToolResult>;
}

export class ChildProcessToolRunner implements ToolRunner {
  run(command: string, args: string[], options: ToolRunOptions = {}): Promise<ToolResult> {
    return new Promise((resolve) => {
      const child = spawn(command, args, {
        cwd: options.cwd,
        shell: false,
        windowsHide: true
      });

      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, options.timeoutMs ?? DEFAULT_TOOL_TIMEOUT_MS);

      child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

      child.on("error", (error) => {
        clearTimeout(timer);
        resolve({
          command,
          args,
          exitCode: TOOL_MISSING_EXIT_CODE,
          stdout: "",
          stderr: error.message
        });
      });

      child.on("close", (exitCode) => {
        clearTimeout(timer);
        resolve({
          command,
          args,
          exitCode: timedOut ? TOOL_TIMEOUT_EXIT_CODE : (exitCode ?? 1),
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: timedOut
            ? `Timed out after ${options.timeoutMs ?? DEFAULT_TOOL_TIMEOUT_MS}ms`
            : Buffer.concat(stderr).toString("utf8")
        });
      });
    });
  }
}
