import type { Finding } from "./finding.js";
import type { ToolResult } from "../integrations/tool-runner.js";
import { TOOL_MISSING_EXIT_CODE, TOOL_TIMEOUT_EXIT_CODE } from "../integrations/tool-runner.js";

export function skippedToolFinding(
  scanner: string,
  id: string,
  title: string,
  description: string
): Finding {
  return {
    id,
    title,
    description,
    category: "tooling",
    severity: "info",
    scanner,
    status: "skipped"
  };
}

/** Returns a skipped finding when the tool could not run at all (missing or timed out). */
export function toolUnavailableFinding(
  scanner: string,
  idPrefix: string,
  label: string,
  result: ToolResult
): Finding | undefined {
  if (result.exitCode === TOOL_MISSING_EXIT_CODE) {
    return skippedToolFinding(
      scanner,
      `${idPrefix}.missing`,
      `${label} is not available`,
      `${label} was skipped because the configured command was not found.`
    );
  }
  if (result.exitCode === TOOL_TIMEOUT_EXIT_CODE) {
    return skippedToolFinding(
      scanner,
      `${idPrefix}.timeout`,
      `${label} timed out`,
      `${label} was skipped because the command did not finish in time.`
    );
  }
  return undefined;
}

export function unparsableOutputFinding(
  scanner: string,
  idPrefix: string,
  label: string,
  result: ToolResult
): Finding {
  return skippedToolFinding(
    scanner,
    `${idPrefix}.parse-failed`,
    `${label} output could not be parsed`,
    result.stderr.trim() || `${label} did not return valid JSON output.`
  );
}
