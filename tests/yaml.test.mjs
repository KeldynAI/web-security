/** The restricted YAML subset parser. */

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseYaml, YamlError } from '../src/yaml.mjs';

test('parses the documented ignore-file shape', () => {
  const document = parseYaml(`version: 1

ignores:
  - id: CVE-2026-1234
    scanner: trivy
    reason: "Vulnerable code path is not reachable in this application."
    expires: "2026-12-31"

  - id: GHSA-abcd-1234-5678
    scanner: npm
    reason: Only affects the package's optional CLI, which is never shipped.
    expires: 2026-11-01
    paths: ["frontend/", "backend/"]
`);

  assert.equal(document.version, 1);
  assert.equal(document.ignores.length, 2);
  assert.deepEqual(document.ignores[0], {
    id: 'CVE-2026-1234',
    scanner: 'trivy',
    reason: 'Vulnerable code path is not reachable in this application.',
    expires: '2026-12-31',
  });
  assert.deepEqual(document.ignores[1].paths, ['frontend/', 'backend/']);
  // An unquoted ISO date stays a string, so comparisons are lexicographic.
  assert.equal(document.ignores[1].expires, '2026-11-01');
});

test('accepts a sequence at the same indentation as its key', () => {
  const document = parseYaml(`version: 1
ignores:
- id: CVE-1
  scanner: trivy
  reason: A perfectly reasonable explanation here.
`);
  assert.equal(document.ignores.length, 1);
  assert.equal(document.ignores[0].id, 'CVE-1');
});

test('handles comments, blank lines and a leading document marker', () => {
  const document = parseYaml(`---
# top level comment
version: 1  # trailing comment

ignores: []
`);
  assert.deepEqual(document, { version: 1, ignores: [] });
});

test('keeps "#" inside quoted strings', () => {
  const document = parseYaml('reason: "tracked in JIRA#4711 and accepted"\n');
  assert.equal(document.reason, 'tracked in JIRA#4711 and accepted');
});

test('keeps colons inside plain scalars such as URLs', () => {
  const document = parseYaml('url: https://example.com/advisories/1\n');
  assert.equal(document.url, 'https://example.com/advisories/1');
});

test('interprets booleans, nulls and numbers', () => {
  const document = parseYaml('a: true\nb: false\nc: null\nd: ~\ne: 42\nf: 1.5\ng: "true"\n');
  assert.deepEqual(document, {
    a: true,
    b: false,
    c: null,
    d: null,
    e: 42,
    f: 1.5,
    g: 'true',
  });
});

test('parses nested mappings and flow collections', () => {
  const document = parseYaml(`outer:
  inner:
    list: [a, "b, c", 'd']
    map: {x: 1, y: two}
`);
  assert.deepEqual(document.outer.inner.list, ['a', 'b, c', 'd']);
  assert.deepEqual(document.outer.inner.map, { x: 1, y: 'two' });
});

test('decodes escapes in double-quoted strings', () => {
  const document = parseYaml('reason: "line one\\nline \\"two\\""\n');
  assert.equal(document.reason, 'line one\nline "two"');
});

test('treats doubled single quotes as an escaped quote', () => {
  const document = parseYaml("reason: 'it''s fine'\n");
  assert.equal(document.reason, "it's fine");
});

test('returns null for an empty document', () => {
  assert.equal(parseYaml(''), null);
  assert.equal(parseYaml('# only a comment\n'), null);
});

const rejected = [
  ['tabs used for indentation', 'ignores:\n\t- id: CVE-1\n', /Tabs cannot be used/],
  ['duplicate keys', 'version: 1\nversion: 2\n', /Duplicate key "version"/],
  ['unterminated double quote', 'reason: "unbalanced\n', /Unterminated double-quoted/],
  ['unterminated single quote', "reason: 'unbalanced\n", /Unterminated single-quoted/],
  ['anchors', 'a: &anchor value\nb: *anchor\n', /anchors and aliases are not supported/],
  ['block scalars', 'reason: |\n  multi line\n', /Block scalars/],
  ['explicit tags', 'reason: !!str value\n', /tags are not supported/],
  ['merge keys', 'base: {a: 1}\nchild:\n  <<: base\n', /merge keys/],
  ['multiple documents', 'a: 1\n---\nb: 2\n', /Multiple YAML documents/],
  ['complex keys', '? [a, b]\n: value\n', /Complex mapping keys/],
  ['missing colon', 'just a string\n', /Expected "key: value"/],
  ['unterminated flow sequence', 'list: [a, b\n', /Unterminated flow collection/],
  ['nested flow collections', 'list: [[a], b]\n', /Nested flow collections/],
  ['content after a quoted value', 'reason: "a" trailing\n', /Unexpected content after a quoted value/],
  ['bad indentation', 'a: 1\n  b: 2\n', /Unexpected content|Unexpected indentation/],
];

for (const [name, input, pattern] of rejected) {
  test(`rejects ${name}`, () => {
    assert.throws(
      () => parseYaml(input),
      (error) => {
        assert.ok(error instanceof YamlError, `expected YamlError, got ${error.name}`);
        assert.match(error.message, pattern);
        return true;
      },
    );
  });
}

test('reports the line number of a problem', () => {
  try {
    parseYaml('version: 1\nignores:\n  - id: CVE-1\n    reason: "unterminated\n');
    assert.fail('expected a YamlError');
  } catch (error) {
    assert.equal(error.line, 4);
    assert.match(error.message, /line 4/);
  }
});
