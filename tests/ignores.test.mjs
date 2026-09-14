/**
 * Ignore-file validation and matching.
 *
 * These are the tests that enforce the product's central promise: nothing gets
 * suppressed without a reviewable, non-expired justification.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  MIN_REASON_LENGTH,
  applyIgnores,
  findMatchingIgnore,
  loadIgnores,
  pathMatches,
  validateIgnoreDocument,
} from '../src/ignores.mjs';
import { UserError } from '../src/util.mjs';
import { createFinding } from '../src/findings.mjs';
import { createTree } from './helpers/fixtures.mjs';

const TODAY = '2026-06-01';
const GOOD_REASON = 'The vulnerable code path is not reachable from this application.';

function validate(document, options = {}) {
  return validateIgnoreDocument(document, { today: TODAY, ...options });
}

function expectInvalid(document, pattern, options = {}) {
  try {
    validate(document, options);
    assert.fail('expected the ignore file to be rejected');
  } catch (error) {
    assert.ok(error instanceof UserError, `expected UserError, got ${error.name}`);
    const text = [error.message, ...(error.details ?? [])].join('\n');
    assert.match(text, pattern);
    return text;
  }
}

// --------------------------------------------------------------------------
// Validation
// --------------------------------------------------------------------------

test('accepts a valid, justified, unexpired entry', () => {
  const { entries } = validate({
    version: 1,
    ignores: [
      { id: 'CVE-2026-1234', scanner: 'trivy', reason: GOOD_REASON, expires: '2026-12-31' },
    ],
  });

  assert.equal(entries.length, 1);
  assert.equal(entries[0].id, 'CVE-2026-1234');
  assert.deepEqual(entries[0].scanners, ['trivy']);
  assert.equal(entries[0].expires, '2026-12-31');
});

test('accepts an entry with no expiry but warns about it', () => {
  const { entries, warnings } = validate({
    version: 1,
    ignores: [{ id: 'CVE-2026-1234', scanner: 'trivy', reason: GOOD_REASON }],
  });

  assert.equal(entries.length, 1);
  assert.match(warnings.join('\n'), /has no "expires" date/);
});

test('rejects a missing reason', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-2026-1234', scanner: 'trivy' }] },
    /is missing "reason"/,
  );
});

test('rejects an empty or whitespace-only reason', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: '' }] },
    /empty "reason"/,
  );
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: '    ' }] },
    /empty "reason"/,
  );
});

test('rejects a reason that is too short to review', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: 'not an issue' }] },
    new RegExp(`at least ${MIN_REASON_LENGTH} are required`),
  );
});

test('rejects placeholder reasons', () => {
  for (const reason of ['n/a', 'false positive', 'WONTFIX', 'known issue.', 'To Do']) {
    expectInvalid(
      { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: reason.padEnd(20, ' ') }] },
      /placeholder reason|at least/,
    );
  }
});

test('rejects an expired entry with an actionable message', () => {
  const text = expectInvalid(
    {
      version: 1,
      ignores: [
        { id: 'CVE-2026-1234', scanner: 'trivy', reason: GOOD_REASON, expires: '2026-05-31' },
      ],
    },
    /expired on 2026-05-31/,
  );
  assert.match(text, /Re-assess the finding/);
});

test('accepts an entry that expires today', () => {
  const { entries } = validate({
    version: 1,
    ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, expires: TODAY }],
  });
  assert.equal(entries.length, 1);
});

test('rejects an unsupported scanner', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'snyk', reason: GOOD_REASON }] },
    /unsupported scanner "snyk"/,
  );
});

test('rejects a missing scanner', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', reason: GOOD_REASON }] },
    /is missing "scanner"/,
  );
});

test('rejects a duplicate entry', () => {
  expectInvalid(
    {
      version: 1,
      ignores: [
        { id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON },
        { id: 'cve-1', scanner: 'trivy', reason: 'A different but equally valid explanation.' },
      ],
    },
    /duplicates ignores\[0\]/,
  );
});

test('allows the same id for two different scanners', () => {
  const { entries } = validate({
    version: 1,
    ignores: [
      { id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON },
      { id: 'CVE-1', scanner: 'npm', reason: GOOD_REASON },
    ],
  });
  assert.equal(entries.length, 2);
});

test('rejects unknown keys at both levels', () => {
  expectInvalid({ version: 1, ignore: [] }, /Unknown top-level key "ignore"/);
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, until: 'x' }] },
    /unknown key "until"/,
  );
});

test('rejects a missing or unsupported version', () => {
  expectInvalid({ ignores: [] }, /Missing "version: 1"/);
  expectInvalid({ version: 2, ignores: [] }, /Unsupported ignore-file version/);
});

test('rejects a malformed structure', () => {
  expectInvalid({ version: 1, ignores: 'CVE-1' }, /"ignores" must be a list/);
  expectInvalid({ version: 1, ignores: ['CVE-1'] }, /must be a mapping/);
  assert.throws(() => validate([1, 2, 3]), /must be a mapping/);
});

test('rejects an unquoted numeric id with advice', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 1234, scanner: 'npm', reason: GOOD_REASON }] },
    /quote it so it stays a string/,
  );
});

test('rejects an invalid expiry date', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, expires: '2026-02-30' }] },
    /invalid "expires" value/,
  );
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, expires: '31/12/2026' }] },
    /invalid "expires" value/,
  );
});

test('require-ignore-expiry turns a missing expiry into an error', () => {
  expectInvalid(
    { version: 1, ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON }] },
    /is missing "expires"/,
    { requireExpiry: true },
  );
});

test('warns about an expiry far in the future', () => {
  const { warnings } = validate({
    version: 1,
    ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, expires: '2030-01-01' }],
  });
  assert.match(warnings.join('\n'), /consider a shorter review cycle/);
});

test('rejects path traversal in a paths entry', () => {
  expectInvalid(
    {
      version: 1,
      ignores: [
        { id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, paths: ['../../etc/passwd'] },
      ],
    },
    /invalid path/,
  );
});

test('reports every problem in one pass', () => {
  const text = expectInvalid(
    {
      version: 1,
      ignores: [
        { id: 'CVE-1', scanner: 'nope', reason: 'x' },
        { scanner: 'trivy', reason: GOOD_REASON },
      ],
    },
    /unsupported scanner/,
  );
  assert.match(text, /is missing "id"/);
});

// --------------------------------------------------------------------------
// Loading from disk
// --------------------------------------------------------------------------

test('loads and validates a YAML file from disk', () => {
  const root = createTree({
    '.github': {
      'web-security-ignore.yml': `version: 1
ignores:
  - id: "GHSA-abcd-1234-5678"
    scanner: dependency
    reason: "${GOOD_REASON}"
    expires: "2026-12-31"
`,
    },
  });

  const { entries } = loadIgnores(path.join(root, '.github/web-security-ignore.yml'), {
    today: TODAY,
  });

  assert.equal(entries.length, 1);
  assert.deepEqual(entries[0].scanners, ['npm', 'yarn', 'pnpm']);
});

test('reports malformed YAML with the file name and a pointer to the schema', () => {
  const root = createTree({ 'bad.yml': 'version: 1\nignores:\n\t- id: CVE-1\n' });
  try {
    loadIgnores(path.join(root, 'bad.yml'), { today: TODAY, displayPath: 'bad.yml' });
    assert.fail('expected the file to be rejected');
  } catch (error) {
    assert.ok(error instanceof UserError);
    assert.match(error.message, /bad\.yml" could not be parsed/);
    assert.match(error.details.join('\n'), /#ignore-file/);
  }
});

test('accepts a JSON ignore file', () => {
  const root = createTree({
    'ignore.json': JSON.stringify({
      version: 1,
      ignores: [{ id: 'CVE-1', scanner: 'trivy', reason: GOOD_REASON, expires: '2026-12-31' }],
    }),
  });

  const { entries } = loadIgnores(path.join(root, 'ignore.json'), { today: TODAY });
  assert.equal(entries.length, 1);
});

test('no ignore file means no suppressions', () => {
  const { entries, warnings } = loadIgnores(null);
  assert.deepEqual(entries, []);
  assert.deepEqual(warnings, []);
});

test('an empty ignore file is accepted with a warning', () => {
  const root = createTree({ 'empty.yml': '# nothing yet\n' });
  const { entries, warnings } = loadIgnores(path.join(root, 'empty.yml'), { today: TODAY });
  assert.deepEqual(entries, []);
  assert.match(warnings.join('\n'), /is empty/);
});

test('the example ignore file shipped with the Action is valid', () => {
  const example = path.join(import.meta.dirname, '..', 'examples', 'web-security-ignore.yml');
  const text = fs.readFileSync(example, 'utf8');
  // The example intentionally uses dates that will eventually pass, so it is
  // validated against a date inside its own window.
  const { entries } = loadIgnores(example, { today: '2026-01-01' });
  assert.ok(entries.length >= 2, 'the example should demonstrate several entries');
  assert.ok(text.includes('reason:'), 'every documented entry carries a reason');
});

// --------------------------------------------------------------------------
// Matching and filtering
// --------------------------------------------------------------------------

function dependencyFinding(overrides = {}) {
  return createFinding({
    scanner: 'npm',
    category: 'dependency',
    id: 'GHSA-abcd-1234-5678',
    aliases: ['CVE-2026-1234'],
    severity: 'HIGH',
    package: 'lodash',
    project: 'frontend',
    path: 'frontend/package-lock.json',
    paths: ['frontend'],
    ...overrides,
  });
}

test('a justified entry suppresses the matching finding', () => {
  const { entries } = validate({
    version: 1,
    ignores: [
      { id: 'GHSA-abcd-1234-5678', scanner: 'npm', reason: GOOD_REASON, expires: '2026-12-31' },
    ],
  });

  const { findings } = applyIgnores([dependencyFinding()], entries, TODAY);
  assert.equal(findings[0].ignored, true);
  assert.equal(findings[0].reason, GOOD_REASON);
  assert.equal(findings[0].expires, '2026-12-31');
});

test('an alias identifier also matches', () => {
  const { entries } = validate({
    version: 1,
    ignores: [{ id: 'CVE-2026-1234', scanner: 'npm', reason: GOOD_REASON }],
  });

  assert.ok(findMatchingIgnore(dependencyFinding(), entries, TODAY));
});

test('an expired entry never suppresses, even if validation is bypassed', () => {
  // Constructed directly: validateIgnoreDocument would already reject this.
  const expired = [
    {
      id: 'GHSA-abcd-1234-5678',
      scanner: 'npm',
      scanners: ['npm'],
      reason: GOOD_REASON,
      expires: '2026-05-31',
      package: null,
      paths: [],
      index: 0,
    },
  ];

  const { findings } = applyIgnores([dependencyFinding()], expired, TODAY);
  assert.equal(findings[0].ignored, false);
});

test('a finding that is not in the ignore file stays actionable', () => {
  const { entries } = validate({
    version: 1,
    ignores: [{ id: 'CVE-2000-0001', scanner: 'npm', reason: GOOD_REASON }],
  });

  const { findings } = applyIgnores([dependencyFinding()], entries, TODAY);
  assert.equal(findings[0].ignored, false);
});

test('the scanner must match, unless a group is used', () => {
  const trivyOnly = validate({
    version: 1,
    ignores: [{ id: 'GHSA-abcd-1234-5678', scanner: 'trivy', reason: GOOD_REASON }],
  }).entries;
  assert.equal(findMatchingIgnore(dependencyFinding(), trivyOnly, TODAY), null);

  const group = validate({
    version: 1,
    ignores: [{ id: 'GHSA-abcd-1234-5678', scanner: 'dependency', reason: GOOD_REASON }],
  }).entries;
  assert.ok(findMatchingIgnore(dependencyFinding(), group, TODAY));

  const any = validate({
    version: 1,
    ignores: [{ id: 'GHSA-abcd-1234-5678', scanner: 'any', reason: GOOD_REASON }],
  }).entries;
  assert.ok(findMatchingIgnore(dependencyFinding(), any, TODAY));
});

test('a merged finding is suppressed by an entry naming any of its sources', () => {
  const finding = { ...dependencyFinding(), sources: ['trivy', 'npm'] };
  const { entries } = validate({
    version: 1,
    ignores: [{ id: 'CVE-2026-1234', scanner: 'trivy', reason: GOOD_REASON }],
  });

  assert.ok(findMatchingIgnore(finding, entries, TODAY));
});

test('package and path scoping narrow a suppression', () => {
  const byPackage = validate({
    version: 1,
    ignores: [
      { id: 'GHSA-abcd-1234-5678', scanner: 'npm', reason: GOOD_REASON, package: 'express' },
    ],
  }).entries;
  assert.equal(findMatchingIgnore(dependencyFinding(), byPackage, TODAY), null);

  const byPath = validate({
    version: 1,
    ignores: [
      { id: 'GHSA-abcd-1234-5678', scanner: 'npm', reason: GOOD_REASON, paths: ['backend/'] },
    ],
  }).entries;
  assert.equal(findMatchingIgnore(dependencyFinding(), byPath, TODAY), null);

  const matchingPath = validate({
    version: 1,
    ignores: [
      { id: 'GHSA-abcd-1234-5678', scanner: 'npm', reason: GOOD_REASON, paths: ['frontend/'] },
    ],
  }).entries;
  assert.ok(findMatchingIgnore(dependencyFinding(), matchingPath, TODAY));
});

test('unused entries are reported so they can be cleaned up', () => {
  const { entries } = validate({
    version: 1,
    ignores: [
      { id: 'GHSA-abcd-1234-5678', scanner: 'npm', reason: GOOD_REASON },
      { id: 'CVE-1999-0001', scanner: 'trivy', reason: GOOD_REASON },
    ],
  });

  const { unused } = applyIgnores([dependencyFinding()], entries, TODAY);
  assert.deepEqual(unused.map((entry) => entry.id), ['CVE-1999-0001']);
});

test('path globs behave as documented', () => {
  assert.ok(pathMatches('frontend/src/app.ts', 'frontend/'));
  assert.ok(pathMatches('frontend/src/app.ts', 'frontend'));
  assert.ok(pathMatches('frontend/src/app.ts', 'frontend/**/*.ts'));
  assert.ok(pathMatches('src/app.ts', 'src/*.ts'));
  assert.ok(!pathMatches('src/nested/app.ts', 'src/*.ts'));
  assert.ok(!pathMatches('frontend-old/src/app.ts', 'frontend/'));
  assert.ok(!pathMatches(null, 'frontend/'));
});
