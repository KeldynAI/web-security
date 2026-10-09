# Contributing

Thanks for helping improve this Action. Please report vulnerabilities in the
Action itself privately instead of opening an issue; see
[SECURITY.md](SECURITY.md).

## Local setup

There is nothing to install:

```bash
git clone https://github.com/keldynai/web-security.git
cd web-security
node --test
```

You need Node 20 or newer. Leave the paths off `node --test`: Node 20 does not
expand a glob such as `tests/**/*.test.mjs`, and the runner discovers
`*.test.mjs` files on its own. Bash, `shellcheck` and `python3` with PyYAML are
useful for the other checks:

```bash
node --test    # unit tests
python3 tests/check-metadata.py     # action.yml, tools.json, docs agree
shellcheck --severity=style --external-sources \
  scripts/*.sh scripts/lib/*.sh tests/e2e/*.sh
```

To run the whole Action against a local directory without GitHub Actions:

```bash
export GITHUB_WORKSPACE="$PWD"
export WEB_SECURITY_INPUT_PATH="."
scripts/preflight.sh          # writes a state directory and prints its path
export WEB_SECURITY_STATE=... # the state-dir it printed
scripts/install-tools.sh
scripts/run-trivy.sh          # or run-sast.sh / run-secrets.sh / run-dependency-audit.sh
scripts/aggregate.sh
scripts/enforce.sh
```

## Project shape

```text
action.yml          composite Action: input mapping and step order only
scripts/            one script per pipeline stage, plus scripts/lib/common.sh
src/                Node logic: config, detection, ignores, normalisation, reporting
src/normalize/      one module per scanner output format
tools.json          pinned scanner versions and SHA-256 checksums
tests/              node:test unit tests; tests/e2e/ is driven by the workflow
```

Two rules matter more than style:

**No runtime dependencies.** Everything under `src/` uses only the Node
standard library, there is no lockfile and nothing is installed on a runner.
A security tool that runs `npm install` before scanning adds the very
supply-chain risk it is meant to find. If you need a library, either write the
small piece you need (as with [`src/yaml.mjs`](src/yaml.mjs)) or open an issue
to discuss it first.

**Repository content is attacker-controlled.** On a pull request, every file
being scanned comes from someone who may be hostile. So: inputs reach scripts
through environment variables and are never interpolated into a command; no
`eval`; arguments are built in Bash arrays; every expansion is quoted; strings
that reach a workflow command are escaped; and project lifecycle scripts are
never executed.

## Adding or changing a scanner

Adding a scanner is a bigger change than it looks. It costs runtime,
maintenance and supply-chain surface for every consumer, and often duplicates
findings. Please open an issue first, describing what it detects that the
existing four do not.

If it is agreed, the work is:

1. Add the pinned version, download URL template and SHA-256 checksums for each
   platform to `tools.json`, and install it in `scripts/install-tools.sh`.
2. Add `scripts/run-<scanner>.sh`, which must record its outcome with
   `ws::record_status` and **never** fail the step for findings.
3. Add `src/normalize/<scanner>.mjs`, mapping its output onto the shared
   finding model in [`src/findings.mjs`](src/findings.mjs) with a severity from
   [`src/severity.mjs`](src/severity.mjs).
4. Disable the scanner's own suppression mechanisms, so suppression only
   happens through the justified ignore file.
5. Wire it into `src/report.mjs`, `src/cli.mjs` and `action.yml`.
6. Add unit tests for the normaliser, including a real sample of the tool's
   output and at least one malformed input.
7. Document it in the README, including *why* it is worth the extra scanner.

## Updating a pinned scanner version

Only `tools.json` changes:

1. Find the upstream release and its `*_checksums.txt` asset.
2. Update `version`, the asset file names and each `sha256`.
3. Update the version table in the README (CI checks the two agree).
4. Run the tests, then run the Action against a repository you know has
   findings to confirm the output format has not changed.

Never replace a checksum with one you computed from a download you did not
verify, and never point an installer at `latest`.

## Tests

Every behavioural change needs a test. The unit tests use `node:test` with no
test framework, and fixtures are built on disk by
[`tests/helpers/fixtures.mjs`](tests/helpers/fixtures.mjs) so detection is
tested against real files rather than mocks.

The end-to-end job in `.github/workflows/test.yml` builds a deliberately
insecure repository, asserts that every scanner finds its planted problem, then
derives an ignore file from the report and asserts that the same repository
passes. Suppressions there are derived rather than hard-coded, so a newly
published advisory does not break CI.

Be careful with fixture data: this repository scans itself, so a
credential-shaped literal in a committed file becomes a real finding. Build
such values from parts at runtime, as `tests/e2e/build-fixture.sh` does.

## Style

- Bash with `set -Eeuo pipefail`, sourced through `scripts/lib/common.sh`.
- `shellcheck --severity=style` clean.
- Node: two-space indent, single quotes, semicolons, ES modules, no `any`-ish
  defensive catch-alls that hide errors.
- Comment the security decision, not the mechanics. A comment explaining why
  `--ignorefile` points at an empty file is worth it; one explaining what a
  `for` loop does is not.
- Error messages name the input or ignore entry at fault and say what to do
  about it. They are read by people debugging a red check.

## Pull requests

Keep them focused, explain the security reasoning, and note any change to
consumer-visible behaviour. Anything that can make a previously passing
repository fail (a new scanner, a stricter default, a new rule pack) needs to
be called out for the changelog.

By contributing you agree that your work is licensed under the
[MIT License](LICENSE).
