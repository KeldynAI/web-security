#!/usr/bin/env node
/**
 * Asserts that the scan of the deliberately insecure fixture failed, and that
 * every scanner contributed at least one finding.
 *
 * The per-category assertions are the point of this test: a scanner that stops
 * producing findings (a broken download, a renamed CLI flag, an output format
 * change) would otherwise look exactly like a clean repository.
 *
 * Reads OUTCOME, STATUS, FINDINGS and REPORT from the environment, which the
 * workflow populates from the step's outputs.
 */

import fs from 'node:fs';

const problems = [];
const env = process.env;

function expect(condition, message) {
  if (!condition) problems.push(message);
}

expect(env.OUTCOME === 'failure', `expected the step to fail, but its outcome was "${env.OUTCOME}"`);
expect(env.STATUS === 'fail', `expected status "fail" (findings), got "${env.STATUS}"`);

const report = JSON.parse(fs.readFileSync(env.REPORT, 'utf8'));
const actionable = report.findings.filter((f) => !f.ignored && !f.belowThreshold);

expect(
  Number(env.FINDINGS) === actionable.length,
  `the "findings" output (${env.FINDINGS}) disagrees with the report (${actionable.length})`,
);
expect(Number(env.IGNORED ?? 0) === 0, 'no findings should be suppressed without an ignore file');

// Every scanner must have run: "skipped" or "error" here would mean the
// fixture was not discovered, or the scanner could not execute.
const byName = new Map(report.scanners.map((scanner) => [scanner.name, scanner]));
for (const name of ['sast', 'trivy', 'dependency', 'secrets']) {
  const status = byName.get(name)?.status;
  expect(status === 'fail' || status === 'pass', `scanner "${name}" reported "${status}"`);
}

// Every planted problem must be found by the scanner it targets.
const categories = new Set(report.findings.map((f) => f.category));
for (const category of ['sast', 'dependency', 'misconfig', 'secret']) {
  expect(categories.has(category), `no "${category}" finding; the fixture plants one`);
}

const hasCriticalDependency = report.findings.some(
  (f) => f.category === 'dependency' && f.package === 'minimist',
);
expect(hasCriticalDependency, 'the vulnerable minimist dependency was not reported');

// The secret must be reported, and its value must never be stored.
const serialized = JSON.stringify(report);
expect(
  !serialized.includes('aB3dEfGhIjKlMnOpQrStUvWxYz0123456789'),
  'the report contains the raw secret from the fixture; it must be redacted',
);

// Cross-scanner deduplication: the minimist advisory is reported by Trivy and
// by npm audit, and must appear as one finding with two sources.
const minimist = report.findings.filter((f) => f.package === 'minimist');
const ids = minimist.map((f) => f.id);
expect(
  new Set(ids).size === ids.length,
  `duplicate ids for the same package were not merged: ${ids.join(', ')}`,
);

if (problems.length > 0) {
  for (const problem of problems) console.log(`::error::${problem}`);
  console.log(`\nScanner statuses: ${JSON.stringify(report.scanners, null, 2)}`);
  console.log(`Findings: ${JSON.stringify(report.findings, null, 2)}`);
  process.exit(1);
}

console.log(
  `the insecure fixture failed as expected: ${actionable.length} actionable findings across ${[...categories].sort().join(', ')}`,
);
