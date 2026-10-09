# Web Security

[![Test](https://github.com/keldynai/web-security/actions/workflows/test.yml/badge.svg)](https://github.com/keldynai/web-security/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SAST, dependency, vulnerability, secret and configuration scanning for web
projects, as one GitHub Action.

```yaml
- uses: keldynai/web-security@v1
```

> This Action provides a baseline set of automated security checks. It is not a
> replacement for threat modelling, code review, penetration testing, runtime
> protections or a mature application-security programme. Use it together with
> the [Keldyn Review Bot](https://docs.keldyn.ai/integrations/review-bot).

---

## Minimal usage

```yaml
name: Web Security

on:
  pull_request:
  schedule:
    - cron: "0 7 * * *"

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: keldynai/web-security@v1
        with:
          keldyn-api-key: ${{ secrets.KELDYN_API_KEY }} # This is optional to submit scans to your keldyn workspace
```

That is the whole setup. Everything is autodetected. The daily schedule runs
only from the default branch, and GitHub may start it later than 07:00 UTC.

`keldyn-api-key` is optional. Without it, the scan stays in GitHub. To submit
scans to a Keldyn workspace, create a team API key under **User settings →
Team → API Keys** and turn on **Submit automated evidence** (`evidence.submit`).
A key that already has **Edit GRC records** (`grc.write`) can submit scans too.
Save the key as the repository secret `KELDYN_API_KEY`.

## Every commit

Scan each push, not only pull requests:

```yaml
name: Web Security

on:
  push:

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: keldynai/web-security@v1
```

See [`examples/every-commit.yml`](examples/every-commit.yml). Add `pull_request`
and `schedule` to the same workflow when you also want those runs.

## Full configuration

```yaml
name: Web Security

on:
  pull_request:
  push:
    branches: [master]
  schedule:
    - cron: "0 7 * * *"

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - id: scan
        uses: keldynai/web-security@v1
        with:
          path: "."
          severity: high
          trivy-severity: HIGH,CRITICAL
          ignore-file: .github/web-security-ignore.yml
          monorepo: true
          require-ignore-expiry: true
          keldyn-api-key: ${{ secrets.KELDYN_API_KEY }}

      # Optional: keep the normalised report for triage. Needs no extra
      # permissions. `always()` so the report survives a failing scan.
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: web-security-report
          path: .web-security/
          retention-days: 14

      - if: always()
        run: |
          echo "result=${{ steps.scan.outputs.result }}"
          echo "actionable=${{ steps.scan.outputs.findings }}"
          echo "ignored=${{ steps.scan.outputs.ignored-findings }}"
```

## Contents

- [Minimal usage](#minimal-usage)
- [Every commit](#every-commit)
- [Full configuration](#full-configuration)
- [What it does](#what-it-does)
- [Use it with the Keldyn Review Bot](#use-it-with-the-keldyn-review-bot)
- [What it checks for](#what-it-checks-for)
- [Scanners, and why these ones](#scanners-and-why-these-ones)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Package-manager autodetection](#package-manager-autodetection)
- [Monorepos](#monorepos)
- [Trivy behaviour](#trivy-behaviour)
- [SAST behaviour](#sast-behaviour)
- [npm / Yarn / pnpm audit behaviour](#npm--yarn--pnpm-audit-behaviour)
- [Secret scanning behaviour](#secret-scanning-behaviour)
- [Ignore file](#ignore-file)
- [Mandatory justification policy](#mandatory-justification-policy)
- [Severity behaviour](#severity-behaviour)
- [Failure semantics](#failure-semantics)
- [Reports and artifacts](#reports-and-artifacts)
- [GitHub permissions](#github-permissions)
- [Pull requests from forks](#pull-requests-from-forks)
- [Scanner versions](#scanner-versions)
- [Security and supply-chain considerations](#security-and-supply-chain-considerations)
- [What this Action does not detect](#what-this-action-does-not-detect)
- [Troubleshooting](#troubleshooting)
- [Versioning](#versioning)
- [Contributing](#contributing)

---

## What it does

On every pull request, the Action walks the repository, runs a small set of
complementary open-source scanners, merges their results into one normalised
report, applies any *justified* suppressions, and fails the check only when
something actionable is left.

```text
Web Security
│
├─ Discover repository
│  ├─ npm / Yarn / pnpm projects (from lockfiles)
│  └─ Dockerfiles, Compose, Terraform, Kubernetes, Helm, workflows
│
├─ SAST                 Semgrep CE
│
├─ Trivy                vulnerabilities + IaC misconfiguration
│
├─ Package audit        npm audit / yarn audit / pnpm audit
│
├─ Secret scanning      Gitleaks
│
├─ Apply justified suppressions
│
└─ Security summary
   ├─ actionable findings (with the exact ignore entry that would accept them)
   ├─ ignored findings + reasons + expiry dates
   └─ final PASS / FAIL / ERROR
```

It requires no SaaS account, no API key and no GitHub Advanced Security. It
needs `permissions: contents: read` and nothing else.

## Use it with the Keldyn Review Bot

Run this Action on the same pull requests as the
[Keldyn Review Bot](https://docs.keldyn.ai/integrations/review-bot). The Action
is the scanner baseline. The Review Bot reviews that pull request against the
code-level controls in your Keldyn organization and posts a **Keldyn Controls
Review** check you can require before merge.

| | This Action | Keldyn Review Bot |
| --- | --- | --- |
| Question | Are there known vulnerabilities, committed secrets, insecure code patterns, or infrastructure misconfiguration? | Would merging this pull request cause a code-level control to fail? |
| Needs | A workflow file. No GitHub Advanced Security. An API key is optional and only used to create Keldyn findings. Create it under **User settings → Team → API Keys** and turn on **Submit automated evidence** (`evidence.submit`). | A Keldyn organization. Connect it under **Integrations → Keldyn Review Bot**. |
| Runs on | GitHub Actions | GitHub, GitLab, and Bitbucket |
| Check | This job | **Keldyn Controls Review** |

On GitHub, comment `@keldyn` (the App slug is `@keldyn-reviewbot`) for an
on-demand review. Setup, repository binding, and merge gating are in the
[Review Bot documentation](https://docs.keldyn.ai/integrations/review-bot).

Keep both checks on the pull request. This Action scans with Semgrep, Trivy,
the package-manager audit, and Gitleaks. The Review Bot judges the diff against
your controls.

## What it checks for

| Area | Covered by |
| --- | --- |
| Injection (SQL, NoSQL, command, template, code) | Semgrep |
| Unsafe shell execution, `child_process` misuse | Semgrep |
| `eval`, `vm`, `vm2`, sandbox and `require` injection | Semgrep |
| Insecure deserialisation (`node-serialize`, YAML, XML/XXE) | Semgrep |
| Cross-site scripting, `dangerouslySetInnerHTML`, raw HTML sinks | Semgrep |
| Server-side request forgery, open redirects | Semgrep |
| Path traversal (`path.join`/`resolve`, `res.sendFile`) | Semgrep |
| Dangerous cryptography (MD5/SHA-1, ECB, missing IV, weak Argon2) | Semgrep |
| Insecure randomness | Semgrep |
| Disabled TLS verification, insecure transport | Semgrep, Trivy |
| Hardcoded credentials and JWT/session secrets | Semgrep, Gitleaks |
| Committed secrets and API keys (≈170 providers) | Gitleaks |
| Known vulnerable dependencies | Trivy, npm/Yarn/pnpm audit |
| Dependency vulnerabilities beyond npm (Go, Python, Ruby, Java, OS packages) | Trivy |
| Dockerfile misconfiguration (root user, `ADD` from URL, missing `USER`) | Trivy |
| Kubernetes misconfiguration (privileged, hostNetwork, capabilities) | Trivy |
| Terraform / CloudFormation / Helm / Ansible misconfiguration | Trivy |
| Insecure GitHub Actions workflow patterns, `${{ }}` script injection | Semgrep |
| ReDoS and request-parsing denial of service patterns | Semgrep |

## Scanners, and why these ones

Every scanner adds runtime, a dependency, supply-chain exposure and
maintenance. These four were chosen because their coverage is complementary
rather than overlapping, and each is open source, actively maintained,
runnable offline-ish in CI and free of any commercial account requirement.

### Semgrep Community Edition: SAST

Chosen over alternatives (CodeQL, njsscan alone, ESLint security plugins)
because:

- it is genuinely open source (LGPL-2.1 engine) and needs **no Semgrep Cloud
  account, login or token**;
- it has the strongest maintained JavaScript/TypeScript security rule coverage
  of the OSS scanners, including framework-aware rules for Express, React and
  Angular;
- CodeQL's default Action is tied to GitHub code scanning (and its licence
  restricts use outside GitHub CI), whereas this Action must work anywhere with
  only `contents: read`;
- ESLint security plugins need the project's own toolchain, dependencies and
  config to run, which means installing untrusted dependencies.

Telemetry is disabled (`--metrics=off`). Rule packs are fetched from the public
Semgrep registry; no code leaves the runner.

### Trivy: dependency vulnerabilities and infrastructure misconfiguration

Trivy is a **primary** scanner here, not an afterthought. It is the only tool
in the set that covers, in one pass:

- lockfile vulnerabilities across ecosystems, not only npm, which is useful
  for the Go/Python/Java sidecars that real web repositories accumulate;
- Dockerfiles, Docker Compose, Kubernetes manifests, Terraform, CloudFormation,
  Helm charts and Ansible playbooks;
- a vulnerability database that is updated continuously and does not need an
  account.

Its overlap with `npm audit` is real, so identical dependency findings from the
two are **merged into one finding** that remembers both sources (see
[Failure semantics](#failure-semantics)).

### The project's own package manager: dependency audit

Trivy reads lockfiles; `npm audit` queries the registry's advisory database.
They disagree often enough that running both is worth it: Trivy tends to have
better CVE metadata and fix versions, while the package manager knows about
advisories that have not reached the Trivy DB yet, and understands workspaces,
overrides and `resolutions` the way the project actually installs them.

The audit always uses the package manager the lockfile belongs to, so a Yarn
repository is never audited with npm.

### Gitleaks: secret scanning

Trivy can also scan for secrets, so this is the one place where two tools could
overlap, and the overlap is deliberately avoided: Trivy's `secret` scanner is
**off by default** (`trivy-scanners: vuln,misconfig`) and Gitleaks does the job.

Gitleaks is worth the extra binary because:

- it ships roughly 170 provider-specific rules with entropy checks, against
  Trivy's smaller built-in set, so it detects materially more real credential
  formats;
- its suppression mechanisms can be switched off completely, which lets this
  Action enforce its justification policy on secrets too (see
  [Security and supply-chain considerations](#security-and-supply-chain-considerations)).

If you would rather run one tool, set `secret-scan: false` and
`trivy-scanners: vuln,misconfig,secret`.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Directory to scan, relative to the repository root. Must stay inside the checkout. |
| `severity` | `high` | Minimum severity that fails the run: `critical`, `high`, `medium` or `low`. Also derives `trivy-severity` and `audit-level`. |
| `sast` | `true` | Run Semgrep. |
| `trivy` | `true` | Run Trivy. |
| `dependency-audit` | `true` | Run the package manager's audit for every detected lockfile. |
| `secret-scan` | `true` | Run Gitleaks. |
| `ignore-file` | *(auto)* | Path to the justified-suppression file. Unset: `.github/web-security-ignore.yml` then `.web-security-ignore.yml`. |
| `monorepo` | `true` | Detect lockfiles recursively. `false` audits only the project at `path`. |
| `trivy-severity` | *(derived)* | Explicit Trivy severity list, e.g. `HIGH,CRITICAL`. |
| `trivy-scanners` | `vuln,misconfig` | Trivy scanners: `vuln`, `misconfig`, `secret`, `license`. |
| `audit-level` | *(derived)* | npm/Yarn audit level: `info`, `low`, `moderate`, `high`, `critical`. |
| `sast-config` | *(none)* | Extra Semgrep configs, comma separated. E.g. `p/owasp-top-ten`. |
| `report-dir` | `.web-security` | Where `report.json`, `summary.md` and raw scanner output are written. |
| `require-ignore-expiry` | `false` | Reject ignore entries that have no expiry date. |
| `fail-on-error` | `true` | Fail when a scanner cannot run. Turning this off means a broken scanner is reported but does not fail the build. An upload failure follows the same switch. |
| `keldyn-api-key` | *(empty)* | Team API key. When set, the full report is posted to Keldyn. Create it under User settings → Team → API Keys and turn on Submit automated evidence (`evidence.submit`). A key with Edit GRC records (`grc.write`) can submit scans too. Pass `${{ secrets.KELDYN_API_KEY }}`. |
| `keldyn-api-url` | `https://api.keldyn.ai` | API origin used when `keldyn-api-key` is set. |

Booleans accept `true`/`false` (also `yes`/`no`, `1`/`0`). Every input is
validated before any scanner runs, and an invalid value fails the job in
seconds with a message naming the input, the value and the allowed values.

## Outputs

| Output | Example | Description |
| --- | --- | --- |
| `result` | `fail` | `pass` or `fail`. A scanner error counts as `fail`. |
| `status` | `error` | `pass`, `fail` or `error`, which distinguishes findings from a broken scanner. |
| `findings` | `3` | Number of actionable findings at or above the threshold. |
| `ignored-findings` | `2` | Number of findings suppressed by a justified entry. |
| `report` | `.web-security/report.json` | Repository-relative path to the normalised JSON report. |

Outputs are populated even when the Action fails, so later steps can read them
(use `if: always()`).

## Package-manager autodetection

Detection is based entirely on **lockfiles that exist on disk**. No project code
is executed and no dependencies are installed.

Each directory is examined for these files, in this order of precedence:

| Lockfile | Package manager | Audit command |
| --- | --- | --- |
| `pnpm-lock.yaml` | pnpm | `pnpm audit --json` |
| `yarn.lock` | Yarn | see below |
| `package-lock.json` | npm | `npm audit --json --package-lock-only` |
| `npm-shrinkwrap.json` | npm | `npm audit --json --package-lock-only` |

A directory with no lockfile is not a project. A directory with a
`package.json` but no lockfile is reported in the log as *not audited* (unless
it sits inside a project, in which case it is a workspace member and is covered
by the parent's lockfile).

When several lockfiles share one directory, which is common mid-migration, the
highest precedence wins and the ambiguity is printed as a warning rather than
silently resolved.

### Yarn Classic vs Yarn Berry

A `yarn.lock` is not enough to know which Yarn to use, so the major version is
determined from, in order:

1. `"packageManager": "yarn@4.1.0"` in `package.json`;
2. the presence of `.yarnrc.yml` (Berry only, since Classic uses `.yarnrc`);
3. the `__metadata:` block that Berry writes into `yarn.lock`.

Nothing found means Yarn Classic.

| Detected | Command |
| --- | --- |
| Yarn Classic (1.x) | `yarn audit --json --no-progress` |
| Yarn Berry (2, 3, 4, …) | `yarn npm audit --all --recursive --json` |

When a project pins `packageManager`, the audit runs through
[Corepack](https://nodejs.org/api/corepack.html) so the project's own Yarn or
pnpm version is used. Corepack downloads that version from the npm registry;
see [Security and supply-chain considerations](#security-and-supply-chain-considerations)
if that matters to you.

Output formats differ wildly between these tools (npm 7+, npm 6, pnpm, Yarn
Classic NDJSON, Yarn Berry `value`/`children`). All five are normalised into
one finding shape, so the ignore file, severity threshold and summary work the
same way for all of them.

## Monorepos

With `monorepo: true` (the default) the repository is walked recursively and
every directory containing a lockfile becomes its own audited project:

```text
Detected projects:
  backend    npm  [package-lock.json]
  docs       yarn (classic)  [yarn.lock]
  frontend   npm  [package-lock.json]
```

Rules and limits:

- These directories are never descended into:
  `node_modules`, `bower_components`, `vendor`, `dist`, `build`, `out`,
  `coverage`, `.git`, `.next`, `.nuxt`, `.svelte-kit`, `.astro`, `.angular`,
  `.output`, `.vercel`, `.netlify`, `.turbo`, `.nx`, `.cache`,
  `.parcel-cache`, `.yarn`, `.pnpm-store`, `.terraform`, `.venv`, `venv`,
  `__pycache__`, `target`, `tmp`, `.idea`, `.vscode`.
- A package tree is audited **once**: projects are keyed by directory, so two
  lockfiles in the same directory do not cause two audits.
- Symlinked directories are not followed.
- The walk stops at depth 8 and prints a warning if it had to.
- More than 50 detected package trees is treated as a configuration mistake and
  fails with advice to set `monorepo: false` or narrow `path`.

Known limitation: a nested lockfile inside another project's directory is
treated as an independent project. That is correct for a polyrepo-style
monorepo and slightly wasteful for an unusual layout that commits a stray
lockfile inside a workspace. Use `monorepo: false` plus one job per package if
you need exact control.

SAST, Trivy and secret scanning always run across the whole `path`, regardless
of `monorepo`.

## Trivy behaviour

```bash
trivy fs . \
  --scanners vuln,misconfig \
  --severity HIGH,CRITICAL \
  --format json --output <state>/raw/trivy.json \
  --exit-code 0 \
  --config <empty file> \
  --ignorefile <empty file> \
  --cache-dir <state>/trivy-cache \
  --list-all-pkgs=false \
  --include-dev-deps \
  --no-progress --disable-telemetry \
  --timeout 14m \
  --skip-dirs '**/node_modules' --skip-dirs '**/dist' … 
```

Why each of the less obvious flags:

- **`--exit-code 0`**: Trivy never decides the build result. Findings are
  normalised and suppressed first; the aggregation step decides. A non-zero
  exit from Trivy therefore means *Trivy itself failed*, which is reported as
  `ERROR`.
- **`--config <empty file>`**: Trivy loads `trivy.yaml` from the working
  directory by default. On a pull request that file is attacker-controlled and
  could silently weaken the scan, so an empty config is supplied instead.
- **`--ignorefile <empty file>`**: likewise for `.trivyignore`, which accepts
  bare identifiers with no reason and no expiry. Suppression must go through
  the [justified ignore file](#ignore-file).
- **`--include-dev-deps`**: matches `npm audit`, which reports
  devDependencies by default, so the two scanners agree on scope and their
  findings can be merged rather than double-counted.
- **`--list-all-pkgs=false`**: keeps `report.json` about findings instead of a
  full package inventory.
- **`--skip-dirs`**: generated and vendored directories only add noise and
  runtime.
- **`--timeout 14m`**: inside a 15-minute wall-clock limit, so Trivy exits
  with a useful message rather than being killed.

Trivy downloads its vulnerability database (and, for misconfiguration
scanning, its checks bundle) on each run, roughly 50 MB from
`mirror.gcr.io`/`ghcr.io`, taking a few seconds. There is no caching by
default, to keep results deterministic and avoid depending on
`actions/cache`.

Trivy's misconfiguration scanners cover Dockerfiles, Docker Compose,
Kubernetes, Helm, Terraform (including plan JSON), CloudFormation, Azure ARM
and Ansible. Only `FAIL` results become findings.

## SAST behaviour

Semgrep runs with these rule packs by default:

| Pack | Rules | Why |
| --- | --- | --- |
| [`p/javascript`](https://semgrep.dev/p/javascript) | ~74 | Core JS/TS application security: XSS, SQLi, SSRF, path traversal, JWT and session secrets, crypto misuse, React/Angular/Express sinks. Identical to `p/typescript`, so both are not needed. |
| [`p/nodejsscan`](https://semgrep.dev/p/nodejsscan) | ~114 | Node-specific and entirely additive: `eval`/`vm`/`vm2` injection, OS command execution, weak hashes and ciphers, insecure randomness, deserialisation, NoSQL injection, ReDoS, hardcoded secrets. |
| [`p/github-actions`](https://semgrep.dev/p/github-actions) | ~12 | Insecure workflow patterns, including `${{ }}` script injection and `pull_request_target` misuse. |

Add more with `sast-config`, for example
`sast-config: "p/owasp-top-ten, rules/custom-rules.yml"`. Values are validated
against a strict character allowlist so they cannot inject another CLI flag.

Hardening:

- `--metrics=off` and `SEMGREP_SEND_METRICS=off`: no telemetry.
- `--disable-nosem`: `// nosemgrep` comments in repository code do **not**
  suppress findings. The flag is probed from `--help` first, and if a future
  Semgrep release removes it the Action prints a warning instead of failing.
- `--no-git-ignore`: scan coverage is not controlled by `.gitignore`.
- Settings and caches are written inside the Action's own temporary directory.
- If Semgrep's engine dies, which is almost always memory on a large
  repository, the scan is retried once with a single worker (`--jobs 1`), which
  is slower but needs much less memory. Semgrep can exit successfully while
  reporting an internal failure and no findings, so that case is detected and
  reported as `ERROR` rather than as a clean scan.

Semgrep severities map to the shared scale as `ERROR` → `HIGH`,
`WARNING` → `MEDIUM`, `INFO` → `LOW`. With the default `severity: high`, only
`ERROR`-level rules can fail the build; everything else is reported as
informational.

## npm / Yarn / pnpm audit behaviour

- **Nothing is installed.** `npm audit --package-lock-only` resolves from the
  lockfile; Yarn Classic builds its tree from `yarn.lock`; `yarn npm audit` and
  `pnpm audit` work from the lockfile too.
- **No lifecycle scripts run.** `npm_config_ignore_scripts=true`,
  `--ignore-scripts` and `YARN_ENABLE_SCRIPTS=false` are set. A pull request's
  `postinstall` never executes on the runner.
- Each project audit has a 5-minute timeout.
- Console output shows each project, its package manager and version:

  ```text
  Dependency audit
    frontend: npm 10.9.2 (frontend/package-lock.json)
    docs: yarn-classic 1.22.22 (docs/yarn.lock)
  ```

- Exit codes are used only to tell "ran" from "failed". Yarn Classic's severity
  bitmask (1-31), npm's `0`/`1`, and a `{"error": …}` JSON body are all handled;
  a genuine tool failure becomes `ERROR`, never a silent pass.
- Advisory identifiers are normalised towards GHSA/CVE. Yarn Berry sometimes
  reports only a numeric npm advisory id, which becomes `NPM-1673`; the exact
  string to use in the ignore file is always printed with the finding.

Audits query the registry's advisory API, so they need outbound network access.
If a project's `.npmrc` configures a different registry, the Action warns, since
advisory data then comes from that registry.

## Secret scanning behaviour

Gitleaks scans the working tree (`gitleaks dir .`) with the full upstream
ruleset and these hardening flags:

- `--redact`: candidate secrets never reach the job log, and the normalised
  report never stores the secret or the matched line, only rule, file and line.
- `--ignore-gitleaks-allow`: `gitleaks:allow` comments in repository code do
  not suppress findings.
- `--gitleaks-ignore-path <empty dir>`: a committed `.gitleaksignore` does not
  suppress findings.
- `--config <generated>`: a generated config that does
  `[extend] useDefault = true` and adds path allowlists for generated
  directories, so a committed `.gitleaks.toml` cannot replace the ruleset or add
  a blanket allowlist.

Every secret is treated as `HIGH`: a committed credential needs a decision, not
a triage queue. Suppress by rule id (optionally with `paths:`) or by the
`<path>:<rule>:<line>` fingerprint.

Only the working tree is scanned, not git history, so runtime does not depend
on the consumer's `fetch-depth`. For history scanning, run the official
[gitleaks-action](https://github.com/gitleaks/gitleaks-action) separately with
`fetch-depth: 0`.

## Ignore file

Place a file at `.github/web-security-ignore.yml` (or
`.web-security-ignore.yml`), or point `ignore-file` anywhere inside the
repository. A `.json` file with the same structure also works. A JSON Schema
for editor autocompletion is in
[`schemas/web-security-ignore.schema.json`](schemas/web-security-ignore.schema.json).

```yaml
version: 1

ignores:
  - id: "CVE-2026-1234"
    scanner: trivy
    package: "libexample"
    reason: "No fixed version published upstream. The affected parser is not exposed to untrusted input; reviewed with the platform team on 2026-05-02."
    expires: "2027-01-31"

  - id: "GHSA-abcd-1234-5678"
    scanner: dependency
    reason: "Only reachable through the package's optional CLI, which this service never invokes. Upgrade blocked on the 4.x migration in PLAT-812."
    expires: "2027-03-31"

  - id: "javascript.lang.security.detect-eval-with-expression.detect-eval-with-expression"
    scanner: sast
    paths:
      - "tools/codegen/**/*.mjs"
    reason: "Build-time code generator evaluating templates from this repository; input never comes from a request or a user."
    expires: "2027-06-30"
```

A fuller, commented example is in
[`examples/web-security-ignore.yml`](examples/web-security-ignore.yml).

### Fields

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | CVE, GHSA, `NPM-1234`, Trivy check id (`AVD-DS-0002`), Semgrep rule id, or Gitleaks rule id / fingerprint. Quote numeric ids. |
| `scanner` | yes | `sast`, `trivy`, `npm`, `yarn`, `pnpm`, `secrets`, or the groups `dependency` (npm + yarn + pnpm) and `any`. |
| `reason` | yes | Why this is acceptable **in this application**. At least 15 characters, and placeholder text is rejected. |
| `expires` | no (recommended) | `YYYY-MM-DD`, inclusive. After this date the entry stops suppressing and the run fails until it is re-reviewed. |
| `package` | no | Restrict to one package name. |
| `paths` | no | Restrict to repository-relative paths. Supports `*` (one segment) and `**` (any depth). Trailing `/` matches a directory prefix. |

### Matching

- `id` is matched case-insensitively against the finding's id **and its
  aliases**, so one GHSA entry can cover the CVE that Trivy reports for the same
  advisory.
- A finding reported by several scanners is suppressed when an entry covers
  **any** of its sources. Without that, a justified `scanner: trivy` entry would
  leave npm's identical finding actionable and the summary would contradict
  itself.
- Entries that matched nothing are reported as warnings, so stale suppressions
  get cleaned up.

### Ignore reporting

Every run prints suppressed findings, with justification and expiry:

```text
Ignored security findings
-------------------------
GHSA-abcd-1234-5678 (lodash)
Scanner: trivy, npm
Reason: Only reachable through the package's optional CLI, which this service never invokes.
Expires: 2027-03-31
```

They also appear in the job summary and in `report.json` with
`"ignored": true` and the reason attached. Nothing is suppressed silently.

## Mandatory justification policy

There is no way to ignore a finding by listing its identifier. The validator
**fails the run** before any scanner downloads, so feedback takes seconds, when
an entry:

- has no `reason`, or an empty or whitespace-only one;
- has a `reason` shorter than 15 characters;
- uses placeholder text (`n/a`, `none`, `tbd`, `todo`, `false positive`,
  `known issue`, `wontfix`, `temporary`, …);
- has no `scanner`, or names an unsupported one;
- has an invalid or unparsable `expires` date;
- **has expired**;
- duplicates another entry (same id, scanner, package and paths);
- has an unknown key, a numeric unquoted id, a `paths` entry containing `..`,
  or malformed YAML.

Every message says which entry (`ignores[2]`) and what to do about it. All
problems are reported in one pass.

Expiry is enforced twice: once in validation, and again at match time, so an
expired entry cannot suppress a finding even if validation is ever bypassed.
Set `require-ignore-expiry: true` to make expiry dates mandatory; without it,
a missing expiry is a warning on every run.

For each actionable finding, the log prints the exact entry that would accept
it, with the reason left as a placeholder that the validator rejects:

```text
[HIGH] CVE-2026-1234 (lodash)
  Location: frontend/package-lock.json
  installed 4.17.20, vulnerable <4.17.21, fixed in 4.17.21
  To accept this risk, add a justified entry to the ignore file:
    - id: "CVE-2026-1234"
      scanner: dependency
      package: "lodash"
      reason: "<why this is acceptable in this application>"
      expires: "2026-12-13"
```

## Severity behaviour

One severity scale is used for every scanner, because each speaks its own
dialect:

| Shared | Semgrep | npm / Yarn / pnpm | Trivy | Gitleaks |
| --- | --- | --- | --- | --- |
| `CRITICAL` | n/a | `critical` | `CRITICAL` | n/a |
| `HIGH` | `ERROR` | `high` | `HIGH` | every leak |
| `MEDIUM` | `WARNING` | `moderate` | `MEDIUM` | n/a |
| `LOW` | `INFO` | `low` | `LOW` | n/a |
| `UNKNOWN` | n/a | n/a | `UNKNOWN` | n/a |

`severity` sets the threshold at or above which a finding is **actionable**.
`UNKNOWN` is ranked with `LOW`: it is always reported, but it does not fail a
run configured for `high`.

`severity` also derives the other two knobs, so they cannot disagree:

| `severity` | `trivy-severity` | `audit-level` |
| --- | --- | --- |
| `critical` | `CRITICAL` | `critical` |
| `high` (default) | `HIGH,CRITICAL` | `high` |
| `medium` | `MEDIUM,HIGH,CRITICAL` | `moderate` |
| `low` | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL` | `low` |

Set either explicitly to override. Findings below the threshold are still
collected and written to `report.json` (with `"belowThreshold": true`) and
counted in the summary, so lowering the threshold never reveals a surprise.

## Failure semantics

Each scanner reports one of four outcomes, and the Action's exit status is the
combination:

| State | Meaning | Effect |
| --- | --- | --- |
| `PASS` | Ran, nothing actionable | none |
| `FAIL: security findings` | Ran, actionable findings remain after suppressions | exit 1 |
| `ERROR: scanner failed` | Could not run, crashed, timed out, or produced unparsable output | exit 1 (unless `fail-on-error: false`) |
| `SKIPPED: not applicable` | Nothing to scan (e.g. no lockfile), or disabled | none |

Design details that make this trustworthy:

- Scanner steps never decide the result. They record an outcome and their raw
  output; a single later step normalises everything and writes the verdict.
  `continue-on-error` is not used anywhere.
- A scanner that exits successfully but writes no parsable output is an
  `ERROR`, not a pass.
- An enabled scanner with **no recorded outcome at all** (its step never
  completed) is an `ERROR`. The Action cannot report success because its own
  bookkeeping went missing.
- A missing verdict file makes the final step fail rather than pass.
- Trivy and `npm audit` findings for the same advisory, package and project are
  merged into one finding, so the count is not inflated and one ignore entry
  covers both.

```text
Web Security Summary
====================

SAST
  PASS

Trivy
  FAIL: security findings
  1 CRITICAL, 8 HIGH
  9 actionable

Dependency Audit
  PASS
  4 below the "high" threshold (not actionable)
  - frontend: npm 10.9.2 ok

Secrets
  FAIL: security findings
  1 HIGH
  1 actionable

Result: FAILED
11 actionable findings at or above the configured severity
```

## Reports and artifacts

| File | Contents |
| --- | --- |
| `.web-security/report.json` | Normalised findings, per-scanner status, discovery results, tool versions, warnings |
| `.web-security/summary.md` | The same content as the job summary |
| `.web-security/raw/` | Unmodified scanner output (Trivy, Semgrep, Gitleaks, each audit) |

A normalised finding:

```json
{
  "scanner": "trivy",
  "sources": ["trivy", "npm"],
  "category": "dependency",
  "id": "CVE-2021-44906",
  "aliases": ["GHSA-xvch-5gv4-984h", "NPM-1179"],
  "severity": "CRITICAL",
  "title": "minimist: prototype pollution",
  "package": "minimist",
  "installedVersion": "1.2.0",
  "fixedVersion": "1.2.6",
  "vulnerableRange": "<1.2.6",
  "project": "frontend",
  "path": "frontend/package-lock.json",
  "line": null,
  "url": "https://avd.aquasec.com/nvd/cve-2021-44906",
  "ignored": false,
  "reason": null,
  "expires": null,
  "belowThreshold": false
}
```

Nothing is uploaded automatically, since that would need extra complexity and is
better left to the consumer:

```yaml
- if: always()
  uses: actions/upload-artifact@v4
  with:
    name: web-security-report
    path: .web-security/
```

Findings with a file path also become **inline pull-request annotations**, using
only log output, so no extra permissions are needed. Repository-controlled
strings are escaped before they reach a workflow command.

The report is deliberately designed so SARIF can be added later (findings
already carry rule id, severity, path and line). SARIF upload is **not**
included, because `github/codeql-action/upload-sarif` needs
`security-events: write`, which not every consumer can grant, and it does not
work for pull requests from forks.

## GitHub permissions

```yaml
permissions:
  contents: read
```

That is all the default configuration needs. No write permissions, no
`security-events`, no `pull-requests: write`, no secrets, and no GitHub
Advanced Security.

If you add artifact upload, `actions/upload-artifact@v4` works with
`contents: read`.

## Pull requests from forks

The Action works normally on `pull_request` events from forks:

- it needs no secrets, so it does not matter that fork PRs get none;
- it needs no write permissions, so a read-only `GITHUB_TOKEN` is fine;
- annotations are log-based, so they still appear.

Use `pull_request`, not `pull_request_target`. `pull_request_target` runs with
the base repository's secrets and a writable token against the *fork's* code,
which is exactly the escalation this Action is designed not to need.

## Scanner versions

Versions live in one file, [`tools.json`](tools.json), together with the
SHA-256 checksum of every release archive:

| Tool | Version | Installed from |
| --- | --- | --- |
| Trivy | `0.74.0` | GitHub release tarball, SHA-256 verified |
| Gitleaks | `8.30.1` | GitHub release tarball, SHA-256 verified |
| Semgrep | `1.177.0` | PyPI, exact version, wheels only |

They are printed at the start of every run:

```text
Web Security (keldynai/web-security)
  Semgrep:  1.177.0
  Trivy:    0.74.0
  Gitleaks: 8.30.1
```

and recorded in `report.json` under `tools`. Updating a scanner means editing
`tools.json` only: change the version and paste the new checksums from the
upstream `*_checksums.txt` release asset.

## Security and supply-chain considerations

This Action is itself part of your supply chain, so:

**Scanner installation**

- No `curl … | sh`. Archives are downloaded to a private `mktemp` directory and
  their SHA-256 is checked against `tools.json` before anything is extracted or
  executed. A mismatch aborts the run.
- No floating `latest`. Every version is pinned.
- Downloads are forced to HTTPS (`--proto '=https' --tlsv1.2`), so a redirect
  cannot downgrade the transport.
- Semgrep is installed into a private virtualenv with `--only-binary=:all:`, so
  pip does not execute a source distribution's `setup.py`. If no wheel is
  available the Action warns loudly before retrying.
- Binaries go into the Action's own temporary directory. `PATH` is not modified
  and nothing is installed into your project.

**No third-party Actions**

`action.yml` uses no third-party Actions at all, so there is nothing to pin to
a commit SHA, and no transitive Action supply chain. Everything is
`shell: bash` plus the repository's own scripts.

**Treating repository content as untrusted**

- Inputs are passed to scripts as environment variables and never interpolated
  into a shell command. There is no `eval` anywhere, every expansion is quoted,
  and arguments are built in Bash arrays so paths with spaces stay one
  argument.
- Enumerated inputs are validated against allowlists; paths must resolve inside
  the checkout; values that could be mistaken for a CLI flag are rejected.
- Scanner-native suppression mechanisms are disabled where the tool allows it
  (`.trivyignore`, `trivy.yaml`, `.gitleaksignore`, `gitleaks:allow`,
  `// nosemgrep`, `.gitleaks.toml`), because they accept an identifier with no
  reason and no expiry. Where a mechanism cannot be disabled, its presence is
  reported in the summary.
- Project lifecycle scripts are never executed, and dependencies are never
  installed.
- Strings that reach workflow commands are percent-escaped, so a crafted file
  path cannot emit its own `::set-output`/`::error`.
- Candidate secrets are redacted at the source and never written to
  `report.json`.

**Zero runtime dependencies**

`src/` uses only the Node standard library, and there is no `node_modules`, no
committed bundle and no `npm install` on the runner. That includes the
[ignore-file parser](src/yaml.mjs): a small strict YAML subset parser is
maintained here rather than vendoring a YAML library into a security tool.

**Network access required**

| Host | Why |
| --- | --- |
| `github.com`, `objects.githubusercontent.com` | Trivy and Gitleaks release archives |
| `mirror.gcr.io`, `ghcr.io` | Trivy vulnerability DB and checks bundle |
| `pypi.org`, `files.pythonhosted.org` | Semgrep |
| `semgrep.dev` | Semgrep rule packs |
| `registry.npmjs.org` (or your registry) | `npm`/`yarn`/`pnpm audit` advisories |

**Honest limitation: a pull request can influence its own scan.** A PR author
can edit the ignore file, `.npmrc`, or the workflow in their branch. The
justification policy makes such a change *visible and reviewable in the diff*,
but it is not a technical barrier. Protect the branch, require review of
`.github/` and the ignore file (a `CODEOWNERS` entry works well), and do not
rely on CI alone as an authorisation boundary.

## What this Action does not detect

Being explicit is more useful than a long feature list:

- **Prototype pollution in your own code.** The default Semgrep packs have no
  prototype-pollution rules. Dependency advisories for it are caught.
- **Anything requiring a running application**: authentication and
  authorisation flaws, IDOR, business-logic bugs, session handling, CSRF in
  practice, race conditions. This is static analysis only, with no DAST.
- **Reachability.** A reported dependency vulnerability may not be exploitable
  in your application; the Action cannot tell. That is what the ignore file's
  `reason` is for.
- **Secrets in git history** (working tree only) and **revoked or already
  rotated secrets** (no credential verification is attempted).
- **Malicious dependency behaviour**: typosquatting, dependency confusion,
  install-script backdoors, compromised maintainers. Detection is
  advisory-database-driven, not behavioural.
- **Lockfile integrity.** Tampered integrity hashes or a lockfile that does not
  match `package.json` are not checked. Use `npm ci` in your build job, which
  fails on a mismatch.
- **Client-side runtime concerns**: CSP, CORS behaviour of a deployed service,
  security headers, subresource integrity of third-party scripts.
- **Infrastructure that only exists at deploy time**: cloud configuration not
  represented in committed IaC.
- **Languages beyond JS/TS for SAST.** Semgrep's packs here are
  JavaScript/TypeScript focused; Trivy still finds dependency vulnerabilities in
  other ecosystems' lockfiles.
- **Custom business rules.** Add them via `sast-config`.
- **Whether merging the change would fail one of your controls.** That is the
  [Keldyn Review Bot](https://docs.keldyn.ai/integrations/review-bot). Run both.
- Findings below the configured severity, by design: they are reported but do
  not fail the build.

## Troubleshooting

**"Input `path` points at …, which is not a directory. Did the workflow run
actions/checkout first?"**
Add `- uses: actions/checkout@v4` before this Action.

**"Ignore file … is invalid"**
The message lists each problem with its entry index. Common causes: an expired
`expires`, a reason under 15 characters, a placeholder reason, or an unquoted
numeric id. Validation happens before scanning, so this fails in seconds.

**"No Node lockfile detected, so the npm/Yarn audit is skipped."**
Expected for repositories with no lockfile, or one that is git-ignored. Commit
the lockfile, or set `dependency-audit: false`. Trivy and SAST still run.

**Semgrep reports `ERROR` and no JSON report**
Either the runner cannot reach `semgrep.dev` to download rule packs (check
egress rules), or its engine ran out of memory. The Action already retries once
with a single worker; if that still fails, narrow the scan with `path`, use a
larger runner, or set `sast: false` and run Semgrep in its own job.

**Trivy reports `ERROR` about the database**
`mirror.gcr.io` or `ghcr.io` is unreachable, or the runner is out of disk. The
DB needs roughly 1 GB free.

**Yarn Berry audit fails**
`yarn npm audit` needs to resolve the project. Make sure `yarn.lock` is
committed and, if the project pins `packageManager`, that Corepack can reach the
npm registry.

**Too many findings on first adoption**
Raise the bar and lower it over time: start with `severity: critical`, or
disable a scanner while you clean up, rather than filling the ignore file with
entries you cannot justify. `fail-on-error: false` is for rollout only, because
it hides broken scanners.

**Secret scanning is slow**
Run this Action before `npm ci` in the job, or in its own job. Dependencies are
excluded from the scan, but a huge working tree still costs time.

**The scan takes too long**
Typical run on `ubuntu-latest` is 2-4 minutes, most of it the Trivy DB download
and Semgrep. Narrow with `path`, or disable a scanner you cover elsewhere.

**I need the report when the check fails**
Outputs and `.web-security/` are written before the failure is raised. Use
`if: always()` on the steps that read them.

## Versioning

Semantic versioning. Releases are tagged `v1.0.0`, and the `v1` tag is moved to
each new `v1.x.y` release.

```yaml
# Recommended: patch and minor updates, including scanner updates
- uses: keldynai/web-security@v1

# Exact release
- uses: keldynai/web-security@v1.0.0

# Immutable: pin to a commit SHA (recommended for security-conscious consumers)
- uses: keldynai/web-security@<full-40-character-commit-sha> # v1.0.0
```

Pinning to a SHA means scanner version bumps arrive only when you update the
pin; [Dependabot](https://docs.github.com/en/code-security/dependabot) can do
that for you and keeps the annotated version comment in sync.

What counts as a breaking change (major version): removing or renaming an
input or output, changing a default in a way that makes a previously passing
repository fail, or changing the ignore-file schema incompatibly. Adding a
scanner, updating a pinned scanner version, or adding rules can surface new
findings within a minor release. That is the point of a security baseline, and
the [ignore file](#ignore-file) is how you manage the transition.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run the tests with:

```bash
node --test
```

Report vulnerabilities in the Action itself privately; see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
