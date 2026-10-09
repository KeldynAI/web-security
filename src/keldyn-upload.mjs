/**
 * Post the finished report to Keldyn when a team API key is configured.
 *
 * The key is read from the environment and is never printed. An empty key
 * leaves the scan in GitHub and does not open a request.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const KELDYN_TRIGGERS = ['schedule', 'push', 'pull_request'];

export function normalizeTrigger(eventName) {
  const name = String(eventName || '').trim();
  return KELDYN_TRIGGERS.includes(name) ? name : null;
}

export function readCommitMessage(cwd = process.cwd(), sha) {
  const args = ['log', '-1', '--format=%B'];
  // Only a hex revision is passed, so a value starting with "-" cannot be a git flag.
  if (/^[0-9a-f]{7,64}$/i.test(String(sha || ''))) args.push(String(sha));
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
  });
}

export function durationMs(startedAt, now = Date.now()) {
  const started = Number(startedAt);
  if (!Number.isFinite(started) || started <= 0) return null;
  return Math.max(0, now - started);
}

/**
 * Body posted to POST /web-security/scans. `report` is the document on disk,
 * including ignored and below-threshold findings.
 */
export function buildUploadBody({
  report,
  repository,
  commitSha,
  commitMessage,
  ref,
  trigger,
  githubRunId,
  githubRunUrl,
  durationMs: elapsed,
}) {
  return {
    report,
    repository,
    commitSha,
    commitMessage: commitMessage ?? '',
    ref,
    trigger,
    githubRunId: githubRunId || null,
    githubRunUrl: githubRunUrl || null,
    durationMs: elapsed,
  };
}

export function githubRunUrl(env) {
  const server = String(env.GITHUB_SERVER_URL || '').replace(/\/$/, '');
  const repository = env.GITHUB_REPOSITORY;
  const runId = env.GITHUB_RUN_ID;
  if (!server || !repository || !runId) return null;
  return `${server}/${repository}/actions/runs/${runId}`;
}

export async function postScan({ url, apiKey, body, fetchImpl = fetch }) {
  const endpoint = `${String(url).replace(/\/$/, '')}/web-security/scans`;
  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': 'keldyn-web-security',
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    const detail = (await response.text()).replaceAll(String(apiKey), '[redacted]').slice(0, 300);
    const error = new Error(`Keldyn rejected the scan (${response.status}). ${detail}`.trim());
    error.status = response.status;
    throw error;
  }
  return response.json().catch(() => ({}));
}

function failOnErrorEnabled(value) {
  const text = String(value ?? 'true').trim().toLowerCase();
  return !['false', '0', 'no'].includes(text);
}

export async function runUpload(env = process.env, options = {}) {
  const apiKey = String(env.WEB_SECURITY_INPUT_KELDYN_API_KEY || '').trim();
  if (!apiKey) {
    return { posted: false };
  }

  const failOnError = failOnErrorEnabled(env.WEB_SECURITY_FAIL_ON_ERROR);
  try {
    const reportPath = env.WEB_SECURITY_REPORT;
    if (!reportPath) {
      throw new Error('WEB_SECURITY_REPORT is not set.');
    }
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    const trigger = normalizeTrigger(env.GITHUB_EVENT_NAME);
    if (!trigger) {
      throw new Error(
        `Keldyn upload supports schedule, push, and pull_request (this run is ${env.GITHUB_EVENT_NAME || 'unknown'}).`,
      );
    }
    let started = null;
    if (env.WEB_SECURITY_STATE) {
      try {
        started = fs.readFileSync(path.join(env.WEB_SECURITY_STATE, 'started-at'), 'utf8').trim();
      } catch {
        started = null;
      }
    }
    const body = buildUploadBody({
      report,
      repository: env.GITHUB_REPOSITORY,
      commitSha: env.GITHUB_SHA,
      commitMessage: options.readCommitMessage
        ? options.readCommitMessage()
        : readCommitMessage(env.GITHUB_WORKSPACE || process.cwd(), env.GITHUB_SHA),
      ref: env.GITHUB_REF_NAME,
      trigger,
      githubRunId: env.GITHUB_RUN_ID || null,
      githubRunUrl: githubRunUrl(env),
      durationMs: durationMs(started, options.now),
    });
    await postScan({
      url: env.WEB_SECURITY_INPUT_KELDYN_API_URL || 'https://api.keldyn.ai',
      apiKey,
      body,
      fetchImpl: options.fetchImpl,
    });
    console.log('Posted the Web Security report to Keldyn.');
    return { posted: true, body };
  } catch (error) {
    const message = error?.message || String(error);
    console.error(message);
    if (failOnError) {
      const wrapped = new Error(message);
      wrapped.exitCode = 1;
      throw wrapped;
    }
    return { posted: false, error: message };
  }
}

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  return import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  runUpload().then(
    () => {},
    (error) => {
      process.exitCode = error.exitCode || 1;
    },
  );
}
