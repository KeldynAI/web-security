/** Input validation. */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';

import { DEFAULT_IGNORE_FILES, envName, loadConfig } from '../src/config.mjs';
import { UserError } from '../src/util.mjs';
import { NPM_LOCK, createTree, packageJson } from './helpers/fixtures.mjs';

function env(workspace, inputs = {}) {
  const result = { GITHUB_WORKSPACE: workspace };
  for (const [key, value] of Object.entries(inputs)) {
    result[envName(key)] = value;
  }
  return result;
}

function workspace(extra = {}) {
  return createTree({ 'package.json': packageJson(), 'package-lock.json': NPM_LOCK, ...extra });
}

function expectInvalid(inputs, pattern, extraFiles = {}) {
  const root = workspace(extraFiles);
  try {
    loadConfig(env(root, inputs));
    assert.fail('expected the inputs to be rejected');
  } catch (error) {
    assert.ok(error instanceof UserError, `expected UserError, got ${error.name}`);
    assert.match([error.message, ...(error.details ?? [])].join('\n'), pattern);
  }
}

test('the defaults are a usable configuration', () => {
  const root = workspace();
  const config = loadConfig(env(root));

  assert.equal(config.scanPathRelative, '.');
  assert.equal(config.severity, 'high');
  assert.deepEqual(config.scanners, {
    sast: true,
    trivy: true,
    dependencyAudit: true,
    secretScan: true,
  });
  assert.deepEqual(config.trivySeverities, ['HIGH', 'CRITICAL']);
  assert.deepEqual(config.trivyScanners, ['vuln', 'misconfig']);
  assert.equal(config.auditLevel, 'high');
  assert.equal(config.monorepo, true);
  assert.equal(config.failOnError, true);
  assert.equal(config.ignoreFile, null);
  assert.equal(config.reportDirRelative, '.web-security');
});

test('the severity threshold derives the Trivy list and the audit level', () => {
  const root = workspace();

  const medium = loadConfig(env(root, { severity: 'medium' }));
  assert.deepEqual(medium.trivySeverities, ['MEDIUM', 'HIGH', 'CRITICAL']);
  assert.equal(medium.auditLevel, 'moderate');

  const low = loadConfig(env(root, { severity: 'low' }));
  assert.deepEqual(low.trivySeverities, ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
  assert.equal(low.auditLevel, 'low');

  const critical = loadConfig(env(root, { severity: 'critical' }));
  assert.deepEqual(critical.trivySeverities, ['CRITICAL']);
  assert.equal(critical.auditLevel, 'critical');
});

test('an explicit trivy-severity overrides the derived list', () => {
  const root = workspace();
  const config = loadConfig(env(root, { severity: 'low', 'trivy-severity': 'critical, HIGH' }));
  assert.deepEqual(config.trivySeverities, ['HIGH', 'CRITICAL']);
});

test('booleans accept the documented spellings', () => {
  const root = workspace();
  const config = loadConfig(env(root, { sast: 'FALSE', trivy: 'true', 'secret-scan': 'no' }));
  assert.equal(config.scanners.sast, false);
  assert.equal(config.scanners.trivy, true);
  assert.equal(config.scanners.secretScan, false);
});

test('rejects an invalid severity, boolean, scanner list and audit level', () => {
  expectInvalid({ severity: 'urgent' }, /Input "severity" must be one of/);
  expectInvalid({ sast: 'maybe' }, /Input "sast" must be "true" or "false"/);
  expectInvalid({ 'trivy-severity': 'SEVERE' }, /unsupported values: SEVERE/);
  expectInvalid({ 'trivy-scanners': 'vuln,sbom' }, /unsupported values: sbom/);
  expectInvalid({ 'audit-level': 'huge' }, /Input "audit-level" must be one of/);
});

test('rejects disabling every scanner', () => {
  expectInvalid(
    { sast: 'false', trivy: 'false', 'dependency-audit': 'false', 'secret-scan': 'false' },
    /All scanners are disabled/,
  );
});

test('refuses a path outside the checked-out repository', () => {
  expectInvalid({ path: '../..' }, /must point inside the checked-out repository/);
  expectInvalid({ 'report-dir': '/tmp/elsewhere' }, /must point inside the checked-out repository/);
});

test('refuses inputs that could be mistaken for a CLI flag', () => {
  expectInvalid({ path: '--exclude' }, /must not start with "-"/);
  expectInvalid({ 'sast-config': '--config=/etc/passwd' }, /not a valid Semgrep config reference/);
});

test('accepts registry packs and repository-relative rule files for sast-config', () => {
  const root = workspace();
  const config = loadConfig(
    env(root, { 'sast-config': 'p/owasp-top-ten, rules/custom.yml' }),
  );
  assert.deepEqual(config.sastConfigs, ['p/owasp-top-ten', 'rules/custom.yml']);
});

test('reports a missing path with a hint about actions/checkout', () => {
  expectInvalid({ path: 'does-not-exist' }, /Did the workflow run actions\/checkout first/);
});

test('an explicitly configured ignore file must exist', () => {
  expectInvalid({ 'ignore-file': 'nope.yml' }, /which does not exist/);
});

test('finds the default ignore file locations', () => {
  for (const candidate of DEFAULT_IGNORE_FILES) {
    const root = workspace();
    const tree = {};
    tree[candidate] = 'version: 1\nignores: []\n';
    const populated = createTree({
      'package.json': packageJson(),
      'package-lock.json': NPM_LOCK,
      ...expand(candidate),
    });

    const config = loadConfig(env(populated));
    assert.equal(config.ignoreFileRelative, candidate);
    assert.equal(config.ignoreFileExplicit, false);
    assert.ok(path.isAbsolute(config.ignoreFile));
    assert.ok(root);
  }
});

test('an explicit ignore file wins over the default locations', () => {
  const root = createTree({
    'package.json': packageJson(),
    'package-lock.json': NPM_LOCK,
    '.github': { 'web-security-ignore.yml': 'version: 1\nignores: []\n' },
    'custom.yml': 'version: 1\nignores: []\n',
  });

  const config = loadConfig(env(root, { 'ignore-file': 'custom.yml' }));
  assert.equal(config.ignoreFileRelative, 'custom.yml');
  assert.equal(config.ignoreFileExplicit, true);
});

test('reports several problems at once', () => {
  const root = workspace();
  try {
    loadConfig(env(root, { severity: 'nope', sast: 'perhaps', 'trivy-scanners': 'weird' }));
    assert.fail('expected the inputs to be rejected');
  } catch (error) {
    assert.equal(error.details.length, 3);
  }
});

/** Turns "a/b/c.yml" into the nested object the fixture helper expects. */
function expand(relativePath) {
  const parts = relativePath.split('/');
  const filename = parts.pop();
  let node = { [filename]: 'version: 1\nignores: []\n' };
  while (parts.length > 0) {
    node = { [parts.pop()]: node };
  }
  return node;
}
