import { existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface WalkOptions {
  root: string;
  exclude: string[];
  maxFileBytes?: number;
}

export function hasFile(root: string, file: string): boolean {
  return existsSync(join(root, file));
}

export function listFiles(options: WalkOptions): string[] {
  const files: string[] = [];
  const excluded = new Set(options.exclude);

  function walk(directory: string): void {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (excluded.has(entry.name)) {
        continue;
      }

      const absolute = join(directory, entry.name);
      const repoRelative = relative(options.root, absolute);

      if (entry.isDirectory()) {
        walk(absolute);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      if (options.maxFileBytes !== undefined && statSync(absolute).size > options.maxFileBytes) {
        continue;
      }

      files.push(repoRelative);
    }
  }

  if (existsSync(options.root)) {
    walk(options.root);
  }

  return files;
}

export function listWorkflowFiles(root: string, workflowDir: string): string[] {
  const dir = workflowDir.replace(/\\/g, "/").replace(/\/+$/, "");
  const absolute = join(root, dir);
  if (!existsSync(absolute)) {
    return [];
  }

  return listFiles({
    root: absolute,
    exclude: [],
    maxFileBytes: 512 * 1024
  })
    .map((file) => `${dir}/${file.replace(/\\/g, "/")}`)
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"));
}

/** Converts a glob (`**`, `*`, `?`) to a RegExp that matches repo-relative, forward-slash paths. */
export function globToRegExp(glob: string): RegExp {
  let source = "";
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i] as string;
    if (char === "*") {
      if (glob[i + 1] === "*") {
        i += 1;
        if (glob[i + 1] === "/") {
          i += 1;
          source += "(?:.*/)?";
        } else {
          source += ".*";
        }
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${source}$`);
}

export function matchesAnyGlob(file: string, globs: string[]): boolean {
  const normalized = file.replace(/\\/g, "/");
  return globs.some((glob) => globToRegExp(glob).test(normalized));
}
