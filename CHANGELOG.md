# Changelog

All notable changes to this Action are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this is a security tool, note the difference between a breaking change
and a stricter scan: a new scanner, a new rule pack or an updated vulnerability
database can surface findings in a repository that passed yesterday. That
arrives in a minor or patch release, and the
[ignore file](README.md#ignore-file) is how you manage the transition. Only
changes to the inputs, outputs, ignore-file schema or defaults that cannot be
resolved that way are treated as breaking.

## [Unreleased]

## [1.0.0] - 2026-09-14

First release.

### Added

- Composite Action running four complementary scanners in one pass:
  - **Semgrep Community Edition 1.177.0** for JavaScript/TypeScript SAST, with
    the `p/javascript`, `p/nodejsscan` and `p/github-actions` packs. No Semgrep
    Cloud account, and telemetry disabled.
  - **Trivy 0.74.0** for dependency vulnerabilities across ecosystems and for
    Dockerfile, Docker Compose, Kubernetes, Helm, Terraform, CloudFormation and
    Ansible misconfiguration.
  - **npm, Yarn Classic, Yarn Berry and pnpm audits**, selected per project
    from its lockfile, run without installing dependencies and without
    executing lifecycle scripts.
  - **Gitleaks 8.30.1** for committed credentials, with secrets redacted before
    they reach the log or the report.
- Package-manager autodetection from `package-lock.json`,
  `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`, including Yarn major
  version detection from `packageManager`, `.yarnrc.yml` and the lockfile's
  `__metadata` block, with Corepack used when a project pins its package
  manager.
- Recursive monorepo detection that audits each package tree exactly once and
  skips generated directories.
- Justified suppressions through `.github/web-security-ignore.yml` (or
  `.web-security-ignore.yml`): every entry requires `id`, `scanner` and a real
  `reason`, supports an optional `expires` date, and may be scoped by `package`
  or `paths`. Entries that are unjustified, malformed, duplicated, or expired
  fail the run before any scanner is downloaded.
- Scanner-native suppression mechanisms deliberately disabled — `.trivyignore`,
  `trivy.yaml`, `.gitleaksignore`, `gitleaks:allow`, `// nosemgrep` and a
  committed `.gitleaks.toml` — so suppression cannot happen without a
  justification.
- One severity scale across all scanners, with `severity` deriving
  `trivy-severity` and `audit-level` so thresholds cannot disagree.
- Cross-scanner deduplication: the same advisory reported by Trivy and by a
  package-manager audit becomes one finding that records both sources, and one
  ignore entry covers it.
- Distinct `PASS` / `FAIL` / `ERROR` / `SKIPPED` states per scanner. A scanner
  that crashes, times out, produces unparsable output, or never records an
  outcome is an error, not a pass.
- Job summary, inline annotations and `.web-security/report.json`, plus
  `.web-security/raw/` with unmodified scanner output. Every actionable finding
  is printed with the exact ignore entry that would accept it.
- Outputs `result`, `status`, `findings`, `ignored-findings` and `report`,
  populated even when the run fails.
- Scanner versions pinned in `tools.json` and verified by SHA-256 before
  execution; Semgrep installed from PyPI at an exact version, wheels only.
- Works with `permissions: contents: read`, on pull requests from forks, with
  no secrets and no third-party Actions.

[Unreleased]: https://github.com/keldynai/web-security/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/keldynai/web-security/releases/tag/v1.0.0
