import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildUploadBody,
  githubRunUrl,
  normalizeTrigger,
  postScan,
  readCommitMessage,
  runUpload,
} from '../src/keldyn-upload.mjs';

const report = {
  result: 'fail',
  findings: [
    { id: 'CVE-2024-1', ignored: false, belowThreshold: false, path: 'a.js' },
    { id: 'RULE', ignored: true, belowThreshold: false, path: 'b.js' },
    { id: 'LOW', ignored: false, belowThreshold: true, path: 'c.js' },
  ],
};

test('the commit message is the scanned revision, and a flag-like value is ignored', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'web-security-'));
  try {
    execFileSync('git', ['init'], { cwd: dir });
    execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir });
    execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
    execFileSync('git', ['commit', '--allow-empty', '-m', 'Subject line'], { cwd: dir });
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
    execFileSync('git', ['commit', '--allow-empty', '-m', 'Later commit'], { cwd: dir });

    assert.match(readCommitMessage(dir, sha), /^Subject line/);
    assert.doesNotMatch(readCommitMessage(dir, sha), /Later commit/);
    assert.match(readCommitMessage(dir, '--format=%H'), /^Later commit/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an empty key does not open a request', async () => {
  let called = false;
  const result = await runUpload(
    { WEB_SECURITY_KELDYN_API_KEY: '  ' },
    { fetchImpl: async () => { called = true; } },
  );
  assert.equal(result.posted, false);
  assert.equal(called, false);
});

test('a set key posts the full report and run metadata', async () => {
  const seen = [];
  const body = buildUploadBody({
    report,
    repository: 'acme/api',
    commitSha: 'abc',
    commitMessage: 'Subject\n\nBody line',
    ref: 'main',
    trigger: normalizeTrigger('schedule'),
    githubRunId: '99',
    githubRunUrl: githubRunUrl({
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'acme/api',
      GITHUB_RUN_ID: '99',
    }),
    durationMs: 1200,
  });
  assert.equal(body.trigger, 'schedule');
  assert.equal(body.commitMessage, 'Subject\n\nBody line');
  assert.equal(body.report.findings.length, 3);
  assert.equal(body.githubRunUrl, 'https://github.com/acme/api/actions/runs/99');

  await postScan({
    url: 'https://api.keldyn.ai/',
    apiKey: 'kld_secret',
    body,
    fetchImpl: async (url, init) => {
      seen.push({ url, init });
      return { ok: true, json: async () => ({ id: 'scan' }) };
    },
  });
  assert.equal(seen[0].url, 'https://api.keldyn.ai/web-security/scans');
  assert.equal(seen[0].init.headers.authorization, 'Bearer kld_secret');
  const posted = JSON.parse(seen[0].init.body);
  assert.deepEqual(posted.report.findings.map((row) => row.id), ['CVE-2024-1', 'RULE', 'LOW']);
  assert.equal(JSON.stringify(seen[0].init).includes('kld_secret') ? 'header-only' : 'missing', 'header-only');
});

test('upload failure is reported without printing the key', async () => {
  const logs = [];
  const original = console.error;
  console.error = (line) => logs.push(String(line));
  try {
    await assert.rejects(
      () => runUpload(
        {
          WEB_SECURITY_KELDYN_API_KEY: 'kld_secret',
          WEB_SECURITY_KELDYN_API_URL: 'https://api.keldyn.ai',
          WEB_SECURITY_REPORT: '/no/such/report.json',
          WEB_SECURITY_FAIL_ON_ERROR: 'true',
          GITHUB_EVENT_NAME: 'push',
        },
        { fetchImpl: async () => { throw new Error('should not be called'); } },
      ),
    );
  } finally {
    console.error = original;
  }
  assert.equal(logs.some((line) => line.includes('kld_secret')), false);
});
