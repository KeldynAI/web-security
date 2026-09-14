/**
 * Small shared helpers. Deliberately dependency-free: the Action must run on a
 * bare GitHub-hosted runner without `npm install`, because installing packages
 * at scan time would add supply-chain risk to a security tool.
 */

import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

/**
 * Error type for problems that are the consumer's to fix (bad input, malformed
 * ignore file, ...). The CLI prints these without a stack trace.
 */
export class UserError extends Error {
  constructor(message, { details = [] } = {}) {
    super(message);
    this.name = 'UserError';
    this.details = details;
  }
}

export function readTextFile(file) {
  return fs.readFileSync(file, 'utf8');
}

export function readJsonFile(file) {
  const text = readTextFile(file);
  try {
    return JSON.parse(stripBom(text));
  } catch (error) {
    throw new UserError(`${file} is not valid JSON: ${error.message}`);
  }
}

/** Reads JSON, returning `fallback` when the file is missing or unreadable. */
export function tryReadJsonFile(file, fallback = null) {
  try {
    return readJsonFile(file);
  } catch {
    return fallback;
  }
}

export function stripBom(text) {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function writeJsonFile(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function fileExists(file) {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

export function dirExists(dir) {
  try {
    return fs.statSync(dir).isDirectory();
  } catch {
    return false;
  }
}

/** Splits a comma/whitespace separated input into trimmed, non-empty values. */
export function splitList(value) {
  if (value === undefined || value === null) return [];
  return String(value)
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/** Normalises a repo-relative path for stable, deterministic output. */
export function toPosix(relativePath) {
  return relativePath.split(path.sep).join('/');
}

/**
 * Appends `key=value` to a GitHub Actions file (`$GITHUB_OUTPUT`,
 * `$GITHUB_STEP_SUMMARY`, ...) using the heredoc form so that multi-line and
 * attacker-influenced values can never be interpreted as extra commands.
 */
export function appendGithubKeyValue(file, key, value) {
  if (!file) return;
  // The delimiter must be unguessable from repository content: a value that
  // contained a predictable delimiter could close the heredoc early and write
  // arbitrary outputs or summary markup.
  const delimiter = `ghadelim_${randomUUID().replace(/-/g, '')}`;
  const text = String(value ?? '');
  if (text.includes(delimiter)) {
    throw new Error('Generated output delimiter collided with value; retry.');
  }
  fs.appendFileSync(file, `${key}<<${delimiter}\n${text}\n${delimiter}\n`, 'utf8');
}

export function appendGithubText(file, text) {
  if (!file) return;
  fs.appendFileSync(file, text.endsWith('\n') ? text : `${text}\n`, 'utf8');
}

/** Truncates for log output while keeping the result single-line and readable. */
export function oneLine(value, max = 160) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === 'string' && value.length > 0))];
}

/** Parses simple `--flag value` / `--flag=value` CLI arguments. */
export function parseArgs(argv) {
  const args = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      args._.push(token);
      continue;
    }
    const body = token.slice(2);
    const equals = body.indexOf('=');
    if (equals !== -1) {
      args[body.slice(0, equals)] = body.slice(equals + 1);
      continue;
    }
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) {
      args[body] = 'true';
    } else {
      args[body] = next;
      index += 1;
    }
  }
  return args;
}
