/**
 * Exit-code semantics of the shell layer.
 *
 * These spawn the real scripts, because the contract that matters to a
 * consumer is the process exit status, not an internal return value.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { createTree, scriptEnv } from './helpers/fixtures.mjs';

const ROOT = path.join(import.meta.dirname, '..');
const ENFORCE = path.join(ROOT, 'scripts', 'enforce.sh');
const CLI = path.join(ROOT, 'src', 'cli.mjs');

function runEnforce(resultJson) {
  const stateDir = createTree(
    resultJson === null ? {} : { 'result.json': JSON.stringify(resultJson) },
  );
  return spawnSync('bash', [ENFORCE], {
    encoding: 'utf8',
    env: scriptEnv({ WEB_SECURITY_STATE: stateDir }),
  });
}

test('a pass verdict exits 0', () => {
  const result = runEnforce({ result: 'pass', reason: 'No actionable findings' });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /PASS — No actionable findings/);
});

test('a fail verdict exits 1 and points at the ignore file', () => {
  const result = runEnforce({ result: 'fail', reason: '2 actionable findings' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /FAIL — 2 actionable findings/);
  assert.match(result.stderr, /justified entry to the ignore file/);
});

test('a scanner error exits 1 and says the repository was not fully scanned', () => {
  const result = runEnforce({ result: 'error', reason: 'Scanner failure: trivy' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /ERROR — Scanner failure: trivy/);
  assert.match(result.stderr, /not fully scanned/);
});

test('a missing verdict file fails rather than passing silently', () => {
  const result = runEnforce(null);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /did not record a result/);
});

test('an unrecognised verdict fails', () => {
  const result = runEnforce({ result: 'probably-fine' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unrecognised result/);
});

test('the CLI reports an unknown subcommand with usage and exit 2', () => {
  const result = spawnSync(process.execPath, [CLI, 'nonsense'], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Usage: cli\.mjs </);
});

test('invalid inputs fail preflight with an actionable message and no stack trace', () => {
  const workspace = createTree({ 'package.json': '{}' });
  const stateDir = createTree({});

  const result = spawnSync(process.execPath, [CLI, 'preflight'], {
    encoding: 'utf8',
    env: scriptEnv({
      GITHUB_WORKSPACE: workspace,
      WEB_SECURITY_STATE: stateDir,
      GITHUB_OUTPUT: path.join(stateDir, 'outputs.txt'),
      WEB_SECURITY_INPUT_SEVERITY: 'extremely-high',
    }),
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Invalid inputs for keldynai\/web-security/);
  assert.match(result.stderr, /Input "severity" must be one of/);
  assert.ok(!result.stderr.includes('at Object.'), 'user errors should not print a stack trace');
});

test('preflight publishes the plan and skips the audit when no lockfile exists', () => {
  const workspace = createTree({ 'index.js': 'console.log(1);\n' });
  const stateDir = createTree({ status: {}, raw: {} });
  const outputFile = path.join(stateDir, 'outputs.txt');

  const result = spawnSync(process.execPath, [CLI, 'preflight'], {
    encoding: 'utf8',
    env: scriptEnv({
      GITHUB_WORKSPACE: workspace,
      WEB_SECURITY_STATE: stateDir,
      GITHUB_OUTPUT: outputFile,
    }),
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /No Node lockfile detected/);

  const outputs = readOutputs(outputFile);
  assert.equal(outputs['run-dependency'], 'false');
  assert.equal(outputs['run-trivy'], 'true');
  assert.equal(outputs['trivy-severity'], 'HIGH,CRITICAL');
  assert.equal(outputs['audit-level'], 'high');
});

test('the audit plan survives empty fields when read back by bash', () => {
  // Regression test: with tab-separated fields, bash collapses the empty
  // `yarnMajor` column for npm projects and every later field shifts, so the
  // audit runs against the wrong lockfile path.
  const stateDir = createTree({
    'detect.json': JSON.stringify({
      projects: [
        {
          dir: 'frontend app',
          packageManager: 'npm',
          lockfile: 'package-lock.json',
          yarnMajor: null,
          packageManagerField: null,
        },
        {
          dir: 'docs',
          packageManager: 'yarn',
          lockfile: 'yarn.lock',
          yarnMajor: 4,
          packageManagerField: 'yarn@4.1.0',
        },
      ],
    }),
  });

  const plan = spawnSync(process.execPath, [CLI, 'audit-plan'], {
    encoding: 'utf8',
    env: scriptEnv({ WEB_SECURITY_STATE: stateDir }),
  });
  assert.equal(plan.status, 0, plan.stderr);

  const script = `
    set -euo pipefail
    while IFS=$'\\x1f' read -r index dir pm yarn_major lockfile pm_field; do
      printf '%s|%s|%s|%s|%s|%s\\n' "$index" "$dir" "$pm" "$yarn_major" "$lockfile" "$pm_field"
    done
  `;
  const parsed = spawnSync('bash', ['-c', script], { encoding: 'utf8', input: plan.stdout });

  assert.equal(parsed.status, 0, parsed.stderr);
  assert.deepEqual(parsed.stdout.trim().split('\n'), [
    '0|frontend app|npm||frontend app/package-lock.json|',
    '1|docs|yarn|4|docs/yarn.lock|yarn@4.1.0',
  ]);
});

/** Parses the heredoc form that GitHub Actions uses for step outputs. */
function readOutputs(file) {
  const text = fs.readFileSync(file, 'utf8');
  const outputs = {};
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const match = /^([A-Za-z0-9_-]+)<<(\S+)$/.exec(lines[index]);
    if (!match) continue;
    const [, key, delimiter] = match;
    const value = [];
    index += 1;
    while (index < lines.length && lines[index] !== delimiter) {
      value.push(lines[index]);
      index += 1;
    }
    outputs[key] = value.join('\n');
  }
  return outputs;
}
