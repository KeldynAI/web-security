/**
 * Aggregation and verdict logic.
 *
 * Each test builds a state directory that looks exactly like the one the
 * scanner steps produce, then checks the verdict, so the four outcomes
 * (PASS / FAIL / ERROR / SKIPPED) are covered end to end without running a
 * real scanner.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { buildReport } from '../src/report.mjs';
import { validateIgnoreDocument } from '../src/ignores.mjs';
import { renderConsole, renderMarkdown, renderAnnotations } from '../src/summary.mjs';
import { createTree } from './helpers/fixtures.mjs';

const TODAY = '2026-06-01';
const GOOD_REASON = 'The vulnerable code path is not reachable from this application.';

const BASE_CONFIG = {
  workspace: '/repo',
  scanPath: '/repo',
  scanPathRelative: '.',
  severity: 'high',
  scanners: { sast: true, trivy: true, dependencyAudit: true, secretScan: true },
  monorepo: true,
  requireIgnoreExpiry: false,
  failOnError: true,
  trivySeverities: ['HIGH', 'CRITICAL'],
  trivyScanners: ['vuln', 'misconfig'],
  auditLevel: 'high',
  sastConfigs: [],
  reportDir: '/repo/.web-security',
  reportDirRelative: '.web-security',
  ignoreFile: null,
  ignoreFileRelative: null,
  ignoreFileExplicit: false,
};

const EMPTY_DETECT = {
  root: '.',
  projects: [],
  packagesWithoutLockfile: [],
  infrastructure: {},
  nativeSuppressions: [],
  warnings: [],
};

const TRIVY_HIGH = {
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2026-1234',
          PkgName: 'lodash',
          InstalledVersion: '4.17.20',
          FixedVersion: '4.17.21',
          Severity: 'HIGH',
          Title: 'Prototype pollution',
          References: ['https://github.com/advisories/GHSA-abcd-1234-5678'],
        },
      ],
    },
  ],
};

/**
 * Creates a state directory.
 * @param {object} options
 * @param {object} options.statuses map of scanner -> status record
 * @param {object} options.raw map of raw filename -> JSON value
 */
function createState({ statuses = {}, raw = {} } = {}) {
  const tree = { status: {}, raw: {} };
  for (const [scanner, status] of Object.entries(statuses)) {
    tree.status[`${scanner}.json`] = JSON.stringify({ scanner, ...status });
  }
  for (const [name, value] of Object.entries(raw)) {
    tree.raw[name] = typeof value === 'string' ? value : JSON.stringify(value);
  }
  return createTree(tree);
}

const OK = { state: 'ok', exitCode: 0, message: null };

function report({ statuses, raw, config = {}, ignores = [], detect = {} } = {}) {
  const stateDir = createState({ statuses, raw });
  return buildReport({
    config: { ...BASE_CONFIG, ...config },
    detect: { ...EMPTY_DETECT, ...detect },
    ignores: { entries: ignores, warnings: [] },
    stateDir,
    today: TODAY,
    tools: { trivy: '0.74.0', semgrep: '1.177.0', gitleaks: '8.30.1' },
  });
}

function entries(...ignoreEntries) {
  return validateIgnoreDocument({ version: 1, ignores: ignoreEntries }, { today: TODAY }).entries;
}

// --------------------------------------------------------------------------

test('zero findings is a pass', () => {
  const result = report({
    statuses: { sast: OK, trivy: OK, dependency: OK, secrets: OK },
    raw: {
      'semgrep.json': { results: [], errors: [] },
      'trivy.json': { Results: [] },
      'gitleaks.json': [],
      'audit-000.meta.json': {
        index: 0,
        dir: '.',
        packageManager: 'npm',
        lockfile: 'package-lock.json',
        state: 'ok',
        output: 'audit-000.json',
      },
      'audit-000.json': { auditReportVersion: 2, vulnerabilities: {} },
    },
  });

  assert.equal(result.result, 'pass');
  assert.equal(result.summary.actionable, 0);
  assert.deepEqual(
    result.scanners.map((scanner) => [scanner.name, scanner.status]),
    [
      ['sast', 'pass'],
      ['trivy', 'pass'],
      ['dependency', 'pass'],
      ['secrets', 'pass'],
    ],
  );
});

test('an actionable HIGH finding is a failure', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'fail');
  assert.equal(result.summary.actionable, 1);
  assert.equal(result.summary.severities.HIGH, 1);
  assert.match(result.exitReason, /1 actionable finding/);
  assert.equal(result.scanners.find((scanner) => scanner.name === 'trivy').status, 'fail');
});

test('only justified, unexpired suppressions is a pass', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
    ignores: entries({
      id: 'CVE-2026-1234',
      scanner: 'trivy',
      reason: GOOD_REASON,
      expires: '2026-12-31',
    }),
  });

  assert.equal(result.result, 'pass');
  assert.equal(result.summary.actionable, 0);
  assert.equal(result.summary.ignored, 1);
  assert.equal(result.findings[0].ignored, true);
  assert.equal(result.findings[0].reason, GOOD_REASON);
});

test('an expired suppression leaves the finding actionable', () => {
  // Bypasses validation on purpose: expiry must be enforced at match time too.
  const expired = [
    {
      id: 'CVE-2026-1234',
      scanner: 'trivy',
      scanners: ['trivy'],
      reason: GOOD_REASON,
      expires: '2026-05-31',
      package: null,
      paths: [],
      index: 0,
    },
  ];

  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
    ignores: expired,
  });

  assert.equal(result.result, 'fail');
  assert.equal(result.summary.ignored, 0);
});

test('a suppression for a GHSA alias covers the Trivy CVE', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
    ignores: entries({
      id: 'GHSA-abcd-1234-5678',
      scanner: 'any',
      reason: GOOD_REASON,
      expires: '2026-12-31',
    }),
  });

  assert.equal(result.result, 'pass');
  assert.equal(result.summary.ignored, 1);
});

test('a crashed scanner is an ERROR, not a pass', () => {
  const result = report({
    statuses: {
      trivy: { state: 'error', exitCode: 2, message: 'Trivy exited with status 2.' },
    },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'error');
  assert.equal(result.scanners.find((scanner) => scanner.name === 'trivy').status, 'error');
  assert.match(result.exitReason, /Scanner failure: trivy/);
  assert.equal(result.summary.errors.length, 1);
});

test('a scanner that reports success but writes no output is an ERROR', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: {},
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'error');
  assert.match(result.scanners[1].message, /file is missing/);
});

test('unparsable scanner output is an ERROR', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': 'not json at all' },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'error');
  assert.match(result.scanners[1].message, /not valid JSON/);
});

test('an enabled scanner with no status file at all is an ERROR', () => {
  const result = report({
    statuses: {},
    config: { scanners: { sast: true, trivy: false, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'error');
  assert.match(result.scanners[0].message, /did not complete/);
});

test('fail-on-error: false downgrades a scanner failure', () => {
  const result = report({
    statuses: { trivy: { state: 'error', exitCode: 2, message: 'network unreachable' } },
    config: {
      failOnError: false,
      scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false },
    },
  });

  assert.equal(result.result, 'pass');
  // The scanner is still reported as ERROR, so the failure is visible.
  assert.equal(result.scanners.find((scanner) => scanner.name === 'trivy').status, 'error');
});

test('a scanner that is not applicable is SKIPPED and does not fail the run', () => {
  const result = report({
    statuses: {
      dependency: { state: 'skipped', exitCode: 0, message: 'No lockfile was found.', projects: [] },
    },
    config: { scanners: { sast: false, trivy: false, dependencyAudit: true, secretScan: false } },
  });

  assert.equal(result.result, 'pass');
  assert.equal(result.scanners.find((scanner) => scanner.name === 'dependency').status, 'skipped');
});

test('each scanner section reports the version of the tool that ran it', () => {
  const result = report({
    statuses: {
      sast: { ...OK, tool: 'semgrep' },
      trivy: { ...OK, tool: 'trivy' },
      secrets: { ...OK, tool: 'gitleaks' },
    },
    raw: { 'semgrep.json': { results: [] }, 'trivy.json': { Results: [] }, 'gitleaks.json': [] },
    config: { scanners: { sast: true, trivy: true, dependencyAudit: false, secretScan: true } },
  });

  const versions = Object.fromEntries(
    result.scanners.map((scanner) => [scanner.name, scanner.version]),
  );
  assert.equal(versions.sast, '1.177.0');
  assert.equal(versions.trivy, '0.74.0');
  assert.equal(versions.secrets, '8.30.1');
});

test('a disabled scanner is reported as disabled', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': { Results: [] } },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  const sast = result.scanners.find((scanner) => scanner.name === 'sast');
  assert.equal(sast.status, 'disabled');
});

test('findings below the threshold are reported but not actionable', () => {
  const result = report({
    statuses: { sast: OK },
    raw: {
      'semgrep.json': {
        results: [
          {
            check_id: 'javascript.express.security.audit.express-cookie-settings',
            path: 'src/app.js',
            start: { line: 4 },
            extra: { severity: 'WARNING', message: 'Cookie without httpOnly', metadata: {} },
          },
        ],
      },
    },
    config: { scanners: { sast: true, trivy: false, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'pass');
  assert.equal(result.summary.actionable, 0);
  assert.equal(result.summary.belowThreshold, 1);
  assert.equal(result.findings[0].belowThreshold, true);
});

test('lowering the threshold makes a MEDIUM finding actionable', () => {
  const result = report({
    statuses: { sast: OK },
    raw: {
      'semgrep.json': {
        results: [
          {
            check_id: 'rule',
            path: 'src/app.js',
            start: { line: 4 },
            extra: { severity: 'WARNING', message: 'Cookie without httpOnly', metadata: {} },
          },
        ],
      },
    },
    config: {
      severity: 'medium',
      scanners: { sast: true, trivy: false, dependencyAudit: false, secretScan: false },
    },
  });

  assert.equal(result.result, 'fail');
  assert.equal(result.summary.actionable, 1);
});

test('a failed project audit fails the dependency scanner', () => {
  const result = report({
    statuses: { dependency: { ...OK, projects: [] } },
    raw: {
      'audit-000.meta.json': {
        index: 0,
        dir: 'frontend',
        packageManager: 'yarn',
        lockfile: 'frontend/yarn.lock',
        state: 'error',
        message: 'yarn-berry exited with status 3.',
      },
    },
    config: { scanners: { sast: false, trivy: false, dependencyAudit: true, secretScan: false } },
  });

  assert.equal(result.result, 'error');
  assert.match(result.scanners.find((scanner) => scanner.name === 'dependency').message, /frontend/);
});

test('Trivy and npm audit findings are counted once', () => {
  const result = report({
    statuses: { trivy: OK, dependency: { ...OK, projects: [] } },
    raw: {
      'trivy.json': TRIVY_HIGH,
      'audit-000.meta.json': {
        index: 0,
        dir: '.',
        packageManager: 'npm',
        lockfile: 'package-lock.json',
        state: 'ok',
        output: 'audit-000.json',
      },
      'audit-000.json': {
        vulnerabilities: {
          lodash: {
            name: 'lodash',
            severity: 'high',
            via: [
              {
                source: 1673,
                name: 'lodash',
                dependency: 'lodash',
                title: 'Prototype Pollution',
                url: 'https://github.com/advisories/GHSA-abcd-1234-5678',
                severity: 'high',
                range: '<4.17.21',
              },
            ],
            fixAvailable: { name: 'lodash', version: '4.17.21' },
          },
        },
      },
    },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: true, secretScan: false } },
  });

  assert.equal(result.summary.actionable, 1);
  assert.deepEqual(result.findings[0].sources, ['trivy', 'npm']);

  // Counted once overall, but both sections have to own up to it: a
  // "Dependency Audit: PASS" next to a critical advisory the audit did report
  // would read as "your lockfile is fine".
  const section = (name) => result.scanners.find((scanner) => scanner.name === name);
  assert.equal(section('trivy').status, 'fail');
  assert.equal(section('trivy').actionable, 1);
  assert.equal(section('dependency').status, 'fail');
  assert.equal(section('dependency').actionable, 1);
});

test('a scanner that fails internally but exits 0 is an ERROR', () => {
  // Semgrep's failure mode: exit code 0, no results, an engine-level error in
  // the JSON. The status file says the process succeeded, so only the
  // normalised output can reveal that nothing was actually scanned.
  const result = report({
    statuses: { sast: OK },
    raw: {
      'semgrep.json': {
        results: [],
        errors: [{ code: 2, level: 'error', type: 'SemgrepError', message: 'semgrep-core died' }],
      },
    },
    config: { scanners: { sast: true, trivy: false, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.result, 'error');
  const sast = result.scanners.find((scanner) => scanner.name === 'sast');
  assert.equal(sast.status, 'error');
  assert.match(sast.message, /failed internally/);
});

test('stale ignore entries and native suppression files are warned about', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': { Results: [] } },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
    detect: { nativeSuppressions: ['.trivyignore'] },
    ignores: entries({
      id: 'CVE-1999-0001',
      scanner: 'trivy',
      reason: GOOD_REASON,
      expires: '2026-12-31',
    }),
  });

  const warnings = result.warnings.join('\n');
  assert.match(warnings, /did not match any finding/);
  assert.match(warnings, /\.trivyignore/);
});

// --------------------------------------------------------------------------
// Rendering
// --------------------------------------------------------------------------

test('the console summary shows ignored findings with their justification', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
    ignores: entries({
      id: 'CVE-2026-1234',
      scanner: 'trivy',
      reason: GOOD_REASON,
      expires: '2026-12-31',
    }),
  });

  const text = renderConsole(result);
  assert.match(text, /Ignored security findings/);
  assert.match(text, /CVE-2026-1234/);
  assert.match(text, new RegExp(`Reason: ${GOOD_REASON}`));
  assert.match(text, /Expires: 2026-12-31/);
  assert.match(text, /Result: PASSED/);
});

test('the console summary suggests a justified ignore entry for each finding', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  const text = renderConsole(result);
  assert.match(text, /Result: FAILED/);
  assert.match(text, /id: "CVE-2026-1234"/);
  assert.match(text, /reason: "<why this is acceptable in this application>"/);
  assert.match(text, /expires: "\d{4}-\d{2}-\d{2}"/);
});

test('annotations escape values that come from repository content', () => {
  const result = report({
    statuses: { secrets: OK },
    raw: {
      'gitleaks.json': [
        {
          RuleID: 'generic-api-key',
          Description: 'Detected a generic API key',
          File: 'src/we:ird,name\n::set-output name=x::y.js',
          StartLine: 3,
        },
      ],
    },
    config: { scanners: { sast: false, trivy: false, dependencyAudit: false, secretScan: true } },
  });

  const annotations = renderAnnotations(result);
  assert.match(annotations, /^::error file=/);
  // Newlines and separators from the path must be percent-encoded so the path
  // cannot emit its own workflow command.
  assert.ok(!annotations.slice(2).includes('\n::'), 'no injected workflow command');
  assert.match(annotations, /%0A/);
  assert.match(annotations, /%3A/);
});

test('the markdown summary renders a scanner table and a disclaimer', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
    detect: {
      projects: [{ dir: '.', packageManager: 'npm', lockfile: 'package-lock.json', yarnMajor: null }],
    },
  });

  const markdown = renderMarkdown(result);
  assert.match(markdown, /## Web Security/);
  assert.match(markdown, /\| Trivy \(0\.74\.0\) \|/);
  assert.match(markdown, /Actionable findings \(1\)/);
  assert.match(markdown, /not a replacement for threat modelling/);
});

test('report.json has a stable, documented shape', () => {
  const result = report({
    statuses: { trivy: OK },
    raw: { 'trivy.json': TRIVY_HIGH },
    config: { scanners: { sast: false, trivy: true, dependencyAudit: false, secretScan: false } },
  });

  assert.equal(result.schemaVersion, 1);
  assert.equal(result.action, 'keldynai/web-security');
  assert.ok(Date.parse(result.generatedAt) > 0);
  assert.deepEqual(Object.keys(result.summary).sort(), [
    'actionable',
    'belowThreshold',
    'errors',
    'ignored',
    'severities',
    'total',
  ]);

  const finding = result.findings[0];
  for (const field of [
    'scanner',
    'sources',
    'category',
    'id',
    'aliases',
    'severity',
    'package',
    'installedVersion',
    'fixedVersion',
    'path',
    'ignored',
    'reason',
  ]) {
    assert.ok(field in finding, `report findings should include "${field}"`);
  }
});

test('the JSON schema shipped for the ignore file is valid JSON', () => {
  const schemaPath = path.join(import.meta.dirname, '..', 'schemas', 'web-security-ignore.schema.json');
  const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  assert.equal(schema.type, 'object');
  assert.deepEqual(schema.required, ['version', 'ignores']);
});
