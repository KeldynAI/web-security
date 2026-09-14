#!/usr/bin/env node
/**
 * Asserts that the same insecure fixture passes once every finding carries a
 * justified suppression, and that the suppressions are reported rather than
 * silently applied.
 *
 * Reads STATUS, FINDINGS, IGNORED and REPORT from the environment.
 */

import fs from 'node:fs';

const problems = [];
const env = process.env;

function expect(condition, message) {
  if (!condition) problems.push(message);
}

expect(env.STATUS === 'pass', `expected status "pass" after suppression, got "${env.STATUS}"`);
expect(Number(env.FINDINGS) === 0, `expected 0 actionable findings, got "${env.FINDINGS}"`);
expect(Number(env.IGNORED) > 0, `expected suppressed findings, got "${env.IGNORED}"`);

const report = JSON.parse(fs.readFileSync(env.REPORT, 'utf8'));
const actionable = report.findings.filter((f) => !f.ignored && !f.belowThreshold);
const ignored = report.findings.filter((f) => f.ignored);

expect(actionable.length === 0, `${actionable.length} findings are still actionable`);
expect(ignored.length === Number(env.IGNORED), 'the "ignored-findings" output disagrees with the report');

// A suppressed finding must keep its justification, or the audit trail is lost.
for (const finding of ignored) {
  expect(
    typeof finding.reason === 'string' && finding.reason.length > 0,
    `suppressed finding ${finding.id} has no recorded reason`,
  );
  expect(Boolean(finding.expires), `suppressed finding ${finding.id} has no recorded expiry`);
}

// Suppressing a finding must not make the scanner look like it found nothing.
const secrets = report.scanners.find((scanner) => scanner.name === 'secrets');
expect(secrets?.status === 'pass', `secrets scanner reported "${secrets?.status}"`);
expect(secrets?.ignored > 0, 'the planted secret should be counted as suppressed, not lost');

const summaryFile = env.REPORT.replace(/report\.json$/, 'summary.md');
if (fs.existsSync(summaryFile)) {
  const summary = fs.readFileSync(summaryFile, 'utf8');
  expect(/ignored/i.test(summary), 'the summary does not mention the ignored findings');
}

if (problems.length > 0) {
  for (const problem of problems) console.log(`::error::${problem}`);
  console.log(JSON.stringify(report.summary, null, 2));
  process.exit(1);
}

console.log(
  `suppression works: ${ignored.length} findings ignored with justification, 0 actionable, result ${report.result ?? 'pass'}`,
);
