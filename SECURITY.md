# Security Policy

This policy covers vulnerabilities **in this Action itself**: the scripts in
`scripts/`, the code in `src/`, `action.yml`, and the way scanners are
installed and invoked.

It does not cover vulnerabilities that the Action reports in *your*
repository; those are yours to triage, and vulnerabilities in the scanners
themselves should go to their own maintainers ([Trivy][trivy],
[Semgrep][semgrep], [Gitleaks][gitleaks]).

## Reporting a vulnerability

Please report privately, and **do not open a public GitHub issue, pull
request or discussion** for an exploitable vulnerability.

Use one of:

1. **GitHub private vulnerability reporting**, which is preferred.
   Go to the repository's **Security** tab and choose
   **Report a vulnerability**. This creates a private advisory visible only to
   the maintainers.
2. **Email** to `security@keldyn.ai`, with `web-security` in the subject.

Please include, as far as you can:

- a description of the issue and why it is a security problem;
- the affected version, tag or commit SHA;
- a minimal reproduction (a workflow file and a repository layout is ideal);
- the impact you believe it has (for example: a pull request can suppress
  findings without justification, secrets can be exfiltrated to the job log,
  arbitrary code from a pull request executes on the runner);
- any suggested fix.

You do not need a proof-of-concept exploit. Do not include real credentials in
a report; redact them.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 3 working days |
| Initial assessment and severity | within 7 working days |
| Fix or documented mitigation for high/critical issues | within 30 days |

We will keep you updated while we work, credit you in the advisory and the
release notes unless you prefer otherwise, and publish a GitHub Security
Advisory with a patched release when the issue is fixed. Please give us a
reasonable chance to release a fix before disclosing publicly; we will agree a
date with you rather than asking for open-ended silence.

## Issues that are in scope

- Anything that lets repository content (which is attacker-controlled on a pull
  request) execute code, inject workflow commands, or escape the scan path.
- Anything that lets a finding be suppressed without a valid, unexpired,
  justified ignore entry.
- Anything that makes the Action report `PASS` when a scanner failed or was
  not actually run.
- Secrets, tokens or candidate credentials leaking into the job log,
  `report.json`, the step summary or annotations.
- A weakness in how scanner binaries are downloaded, pinned or verified.
- Privilege or permission requirements beyond `contents: read` in the default
  configuration.

## Issues that are not in scope

- False positives or false negatives in a scanner's own rules or
  vulnerability database. Report these upstream.
- A pull request author editing the ignore file, `.npmrc`, or the workflow in
  their own branch. This is expected: those changes are visible in the diff and
  the control is branch protection plus code review. See
  "[Security and supply-chain considerations][readme-security]" in the README.
- Missing coverage for a language, ecosystem or vulnerability class that this
  Action does not claim to scan. Please open a normal feature request.

## Supported versions

Security fixes are released for the latest `v1` release. The `v1` tag is moved
to each new `v1.x.y` release, so consumers tracking `@v1` receive fixes
automatically. Consumers pinned to a commit SHA need to update the SHA.

[trivy]: https://github.com/aquasecurity/trivy/security/policy
[semgrep]: https://github.com/semgrep/semgrep/security/policy
[gitleaks]: https://github.com/gitleaks/gitleaks/security/policy
[readme-security]: README.md#security-and-supply-chain-considerations
