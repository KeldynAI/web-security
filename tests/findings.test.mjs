/** Cross-scanner merging and ordering. */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canonicalAdvisoryId,
  createFinding,
  extractAdvisoryIds,
  mergeFindings,
  sortFindings,
} from '../src/findings.mjs';

function trivyFinding(overrides = {}) {
  return createFinding({
    scanner: 'trivy',
    category: 'dependency',
    id: 'CVE-2026-1234',
    aliases: ['GHSA-abcd-1234-5678'],
    severity: 'HIGH',
    package: 'lodash',
    installedVersion: '4.17.20',
    fixedVersion: '4.17.21',
    project: 'frontend',
    path: 'frontend/package-lock.json',
    ...overrides,
  });
}

function npmFinding(overrides = {}) {
  return createFinding({
    scanner: 'npm',
    category: 'dependency',
    id: 'GHSA-abcd-1234-5678',
    aliases: ['NPM-1673'],
    severity: 'HIGH',
    package: 'lodash',
    vulnerableRange: '<4.17.21',
    project: 'frontend',
    path: 'frontend/package-lock.json',
    ...overrides,
  });
}

test('merges the same advisory reported by Trivy and npm audit', () => {
  const merged = mergeFindings([trivyFinding(), npmFinding()]);

  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].sources, ['trivy', 'npm']);
  assert.equal(merged[0].id, 'CVE-2026-1234');
  assert.ok(merged[0].aliases.includes('GHSA-abcd-1234-5678'));
  assert.ok(merged[0].aliases.includes('NPM-1673'));
  // Fields missing from one scanner are filled in from the other.
  assert.equal(merged[0].installedVersion, '4.17.20');
  assert.equal(merged[0].fixedVersion, '4.17.21');
  assert.equal(merged[0].vulnerableRange, '<4.17.21');
});

test('keeps the same advisory separate when it affects different projects', () => {
  const merged = mergeFindings([
    npmFinding({ project: 'frontend', path: 'frontend/package-lock.json' }),
    npmFinding({ project: 'backend', path: 'backend/package-lock.json' }),
  ]);

  assert.equal(merged.length, 2);
});

test('keeps different packages separate even with a shared advisory id', () => {
  const merged = mergeFindings([npmFinding({ package: 'lodash' }), npmFinding({ package: 'async' })]);
  assert.equal(merged.length, 2);
});

test('merging is transitive across identifier aliases', () => {
  const merged = mergeFindings([
    npmFinding({ id: 'NPM-1673', aliases: [] }),
    npmFinding({ id: 'GHSA-abcd-1234-5678', aliases: ['NPM-1673'] }),
    trivyFinding(),
  ]);

  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].sources, ['trivy', 'npm']);
});

test('the highest severity wins when scanners disagree', () => {
  const merged = mergeFindings([
    npmFinding({ severity: 'MEDIUM' }),
    trivyFinding({ severity: 'CRITICAL' }),
  ]);

  assert.equal(merged.length, 1);
  assert.equal(merged[0].severity, 'CRITICAL');
});

test('non-dependency findings are never merged', () => {
  const sast = createFinding({
    scanner: 'sast',
    category: 'sast',
    id: 'rule-1',
    severity: 'HIGH',
    path: 'src/a.js',
    line: 1,
  });
  const secret = createFinding({
    scanner: 'secrets',
    category: 'secret',
    id: 'rule-1',
    severity: 'HIGH',
    path: 'src/a.js',
    line: 1,
  });

  assert.equal(mergeFindings([sast, secret]).length, 2);
});

test('extracts GHSA and CVE identifiers from reference URLs', () => {
  assert.deepEqual(
    extractAdvisoryIds('https://github.com/advisories/GHSA-abcd-1234-5678', [
      'https://nvd.nist.gov/vuln/detail/CVE-2026-1234',
      'https://example.com/not-an-id',
    ]),
    ['GHSA-abcd-1234-5678', 'CVE-2026-1234'],
  );
});

test('advisory ids are written the way their issuer writes them', () => {
  // Scanners disagree about case: Trivy reports CVE ids upper case, npm audit
  // reports GHSA ids lower case, and Yarn Berry shouts both. They have to
  // agree here or the same advisory would not merge, and the ignore-file
  // snippet printed for a finding would not be copy-pasteable.
  assert.equal(canonicalAdvisoryId('ghsa-xvch-5gv4-984h'), 'GHSA-xvch-5gv4-984h');
  assert.equal(canonicalAdvisoryId('GHSA-XVCH-5GV4-984H'), 'GHSA-xvch-5gv4-984h');
  assert.equal(canonicalAdvisoryId('cve-2021-44906'), 'CVE-2021-44906');
  assert.equal(canonicalAdvisoryId('npm-1179'), 'NPM-1179');
  // Anything else is a scanner's own rule id, which is case-sensitive.
  assert.equal(canonicalAdvisoryId('AVD-DS-0002'), 'AVD-DS-0002');
  assert.equal(
    canonicalAdvisoryId('javascript.lang.security.detect-eval-with-expression'),
    'javascript.lang.security.detect-eval-with-expression',
  );
});

test('findings are ordered worst-first with ignored findings last', () => {
  const ordered = sortFindings([
    { ...npmFinding({ severity: 'LOW' }), ignored: false },
    { ...npmFinding({ severity: 'CRITICAL' }), ignored: true },
    { ...npmFinding({ severity: 'MEDIUM' }), ignored: false },
    { ...npmFinding({ severity: 'CRITICAL' }), ignored: false },
  ]);

  assert.deepEqual(
    ordered.map((finding) => [finding.severity, finding.ignored]),
    [
      ['CRITICAL', false],
      ['MEDIUM', false],
      ['LOW', false],
      ['CRITICAL', true],
    ],
  );
});
