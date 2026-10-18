# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- The `tools` section of a repository config file is now ignored. A pull request could otherwise point `tools.composer` / `tools.npm` / `tools.osvScanner` at an executable inside the checked-out code and have the action run it.
- PR comment lookup only trusts comments authored by a bot account; the HTML marker alone could be forged by any commenter.
- Diff mode runs git with an argument list instead of a shell string and rejects base refs that look like options.
- Docker image: OSV-Scanner binary is verified against the release checksum file (and bumped to v2.7.0); `npm ci` is used for reproducible builds.
- Release workflow pins the published action image by digest (`image:tag@sha256:...`).

### Fixed
- OSV scanner read the wrong JSON shape (`results[].packages[]`) and mapped CVSS vector strings to `low`; it now uses the numeric group severity, then the database severity label.
- Composer audit/outdated use `--locked` when `composer.lock` exists, so they work on a fresh checkout without `vendor/`.
- `npm outdated` reports a skipped finding when `node_modules` is missing instead of silently returning nothing; `npm audit` errors are surfaced; all advisories of a package are kept and the highest severity is used.
- `suppressions` in the config file are now applied during scans (previously only added/listed by the CLI). `secrets.include` is now honoured.
- `baseline update` no longer drops previously baselined findings when run again, and defaults to the config's `baseline` path.
- `suppressions add` no longer crashes when the config file already contains other settings.
- Diff mode works inside the Docker action (safe.directory, base branch fetch, shallow-history fallback) and warns when it falls back to a full scan.
- A failed PR comment / job summary (read-only fork token) is now a warning instead of failing the job; action outputs are set first.
- Scanner commands time out after 5 minutes instead of hanging the job; every scanner reports unavailable / timed-out / unparsable tools with a distinct skipped finding id.
- Secret scanner: custom patterns that match the empty string no longer loop forever; line lookup is no longer quadratic; `.env.example`-style templates and `.npmrc` without a literal credential are no longer flagged; finding ids no longer contain line numbers so baselines survive unrelated edits.
- Workflow scanner: no more false "missing permissions" when every job sets its own; an unparsable workflow no longer discards other findings; added `workflow_run`, reusable-workflow pinning, `github-script` and a much wider list of untrusted expressions.
- `listWorkflowFiles` no longer walks the whole repository.
- PR comment: truncated comments link to the workflow run (was a literal `$SUMMARY_URL`), all pages of comments are searched, config-suppressed findings are counted.
- SARIF: one rule per check (not per finding), `security-severity`, `%SRCROOT%` base id, stable fingerprints, suppressed results marked as suppressed, correct `informationUri`.
- Action failure message reports blocking findings rather than the total.
- `suppress` alias now supports `--category` and `--path`.

### Changed
- `npm run prepare:action` bundles the compiled `dist/` output instead of `src/`: `@vercel/ncc`'s TypeScript loader cannot run on TypeScript 7.
- `js/action.yml` runs on `node24`; `docker/action.yml` now uses the same `__VERSION__` placeholder as the root action.
- Dependencies updated to latest majors (zod 4, commander 15, TypeScript 7, vitest 5, eslint 10, @types/node 26).
- CI runs tests with coverage (`npm run test:coverage`); pinned GitHub Actions updated to their latest releases.
- `tsc` now also fails on unused locals/parameters and implicit returns.
- Invalid regular expressions in `secrets.patterns` are rejected when the config is loaded.

## [0.4.0] - 2026-05-27

### Added
- `diff` mode: scanners limit scope to changed files only (secret scanner, workflow hardening, dependency scanners all filter by `changedFiles`)
- `changedFiles` context field on `ScannerContext` — populated from `GITHUB_BASE_REF` or `git merge-base HEAD origin/main` in diff mode
- `baseline` config option: suppress pre-existing findings; `baseline update` CLI command writes the current findings to a baseline file
- `gha-security-checks baseline update` — runs a full scan and writes all open findings to baseline
- `gha-security-checks suppress <id> --reason` and `suppressions add/list/remove` CLI subcommands
- JS action variant at `js/action.yml` (node20, no Docker pull) for repos with toolchains pre-installed
- PR comment delta view: **New** / **Fixed since last run** / **Still open** sections; finding IDs persisted in HTML comment for cross-run diffing; 60KB truncation guard
- `src/core/diff.ts`, `src/core/baseline.ts`, `src/core/config-editor.ts` — new core modules
- Release workflow now builds and commits `dist-action/` bundle so JS action always matches the tag
- 14 new tests (baseline round-trips, diff-mode scanner filtering, scanner context propagation) — 68 total

## [0.3.0] - 2026-05-27

### Added
- CI workflow: lint, typecheck, vitest, and Docker smoke test on every PR and push to main
- Release workflow: tag-driven, atomic — builds multi-arch GHCR image, publishes to npm, creates GitHub release
- Self-audit workflow: dogfoods the action against this repo on PRs, pushes, and weekly schedule; uploads SARIF to GitHub Security
- `action.yml` now uses `__VERSION__` placeholder substituted at release time (prevents version drift between package.json and the image tag)
- `action-yml-guard` CI job rejects any push to main where `action.yml` has a pinned tag instead of the placeholder
- Dockerfile base images pinned by digest for reproducible builds
- `.nvmrc` pinning Node 24
- `CHANGELOG.md`, `RELEASING.md`, `CONTRIBUTING.md`
- `--version` CLI flag with embedded build SHA
- Version log line at the start of every action run
- `scripts/generate-version.mjs` prebuild script generating `src/core/version.ts`
- Test coverage: config schema, reporter round-trips (JSON / Markdown / SARIF), CLI e2e
- Vitest coverage reporting with threshold gates

## [0.2.0] - 2026-05-25

### Added
- Node.js npm vulnerability scanner (`npm audit`)
- Node.js outdated package scanner (`npm outdated`)
- Multi-architecture Docker image (`linux/amd64`, `linux/arm64`)

### Fixed
- Scoped workflow permission handling (e.g. `pull-requests: write` no longer triggers write-all warning)
- Action metadata parsing for CLI arguments

## [0.1.0] - 2026-05-24

### Added
- PHP Composer vulnerability scanner (`composer audit`)
- PHP outdated and abandoned package detection (`composer outdated`)
- OSV-Scanner integration (when binary is present)
- Secret and sensitive-file scanner with configurable regex patterns
- GitHub Actions workflow hardening scanner
- JSON, Markdown, and SARIF reporters
- Pull request comment, job summary, and annotation outputs
- Policy modes: `audit`, `warn`, `fail-on-high`, `fail-on-critical`, `strict`, `custom`
- YAML config file with Zod schema validation
- CLI (`npx gha-security-checks`)
- Docker-backed GitHub Action published to GitHub Marketplace

[Unreleased]: https://github.com/lavluda/GHA-security-checks/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/lavluda/GHA-security-checks/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lavluda/GHA-security-checks/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lavluda/GHA-security-checks/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lavluda/GHA-security-checks/releases/tag/v0.1.0
