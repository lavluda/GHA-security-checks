/**
 * In-place YAML config editor for suppressions management.
 * Uses the yaml package's Document API to preserve comments and formatting.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import YAML from "yaml";
import { configFileCandidates } from "./config.js";

export interface SuppressionEntry {
  id?: string;
  category?: string;
  path?: string;
  reason?: string;
}

/**
 * Finds the active config file path, creating the default one if none exists.
 */
export function resolveConfigPath(cwd: string, configPath?: string): string {
  if (configPath) return resolve(cwd, configPath);

  for (const candidate of configFileCandidates) {
    const full = resolve(cwd, candidate);
    if (existsSync(full)) return full;
  }

  // Default: create gha-security-checks.yml
  return resolve(cwd, "gha-security-checks.yml");
}

/**
 * Reads the config file as a YAML Document (preserving comments).
 */
function readDocument(filePath: string): YAML.Document {
  if (!existsSync(filePath)) {
    return YAML.parseDocument("# gha-security-checks configuration\n");
  }
  return YAML.parseDocument(readFileSync(filePath, "utf8"));
}

/**
 * Appends a suppression entry to the config file.
 */
export function addSuppression(
  cwd: string,
  entry: SuppressionEntry,
  configPath?: string
): string {
  const filePath = resolveConfigPath(cwd, configPath);
  const doc = readDocument(filePath);

  // Ensure suppressions key exists as a YAML sequence node (a plain array is not editable in place)
  if (!YAML.isSeq(doc.get("suppressions"))) {
    doc.set("suppressions", doc.createNode([]));
  }

  doc.addIn(["suppressions"], doc.createNode(entry));

  writeFileSync(filePath, doc.toString(), "utf8");
  return filePath;
}

/**
 * Lists all suppressions from the config file.
 */
export function listSuppressions(cwd: string, configPath?: string): SuppressionEntry[] {
  const filePath = resolveConfigPath(cwd, configPath);
  if (!existsSync(filePath)) return [];

  try {
    const parsed = YAML.parse(readFileSync(filePath, "utf8")) as {
      suppressions?: SuppressionEntry[];
    };
    return Array.isArray(parsed?.suppressions) ? parsed.suppressions : [];
  } catch {
    return [];
  }
}

/**
 * Removes suppressions matching the given ID from the config file.
 * Returns the number of entries removed.
 */
export function removeSuppression(
  cwd: string,
  id: string,
  configPath?: string
): { filePath: string; removed: number } {
  const filePath = resolveConfigPath(cwd, configPath);
  if (!existsSync(filePath)) return { filePath, removed: 0 };

  const doc = readDocument(filePath);
  const suppressions = doc.get("suppressions");
  if (!YAML.isSeq(suppressions)) return { filePath, removed: 0 };

  const before = suppressions.items.length;
  suppressions.items = suppressions.items.filter((item) => {
    const entry = YAML.isMap(item) ? item.toJSON() as SuppressionEntry : null;
    return entry?.id !== id;
  });
  const removed = before - suppressions.items.length;

  writeFileSync(filePath, doc.toString(), "utf8");
  return { filePath, removed };
}
