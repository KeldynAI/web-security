/**
 * Input validation and normalisation.
 *
 * Inputs reach this module through environment variables that the composite
 * Action sets explicitly; they are never interpolated into a shell command.
 * Everything is validated here, once, before any scanner runs, so that a typo
 * fails in seconds instead of after a five-minute Trivy download.
 *
 * Values that end up on a scanner command line (paths, Semgrep configs,
 * severity lists) are additionally checked against a conservative character
 * allowlist and rejected if they could be mistaken for a CLI flag.
 */

import path from 'node:path';
import fs from 'node:fs';

import { UserError, dirExists, fileExists, splitList, toPosix } from './util.mjs';
import { THRESHOLDS, npmAuditLevel, trivySeverityList } from './severity.mjs';

export const TRIVY_SCANNERS = ['vuln', 'misconfig', 'secret', 'license'];
export const TRIVY_SEVERITIES = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/** Ignore-file locations searched when `ignore-file` is not set. */
export const DEFAULT_IGNORE_FILES = [
  '.github/web-security-ignore.yml',
  '.github/web-security-ignore.yaml',
  '.web-security-ignore.yml',
  '.web-security-ignore.yaml',
];

const ENV_PREFIX = 'WEB_SECURITY_INPUT_';

/** Rejects shell/CLI metacharacters and anything that looks like a flag. */
const SAFE_TOKEN = /^[A-Za-z0-9._][A-Za-z0-9._/@:+-]*$/;

export function envName(input) {
  return `${ENV_PREFIX}${input.replace(/-/g, '_').toUpperCase()}`;
}

function readInput(env, name, fallback = '') {
  const raw = env[envName(name)];
  if (raw === undefined || raw === null) return fallback;
  const value = String(raw).trim();
  return value.length === 0 ? fallback : value;
}

function parseBoolean(value, name, errors) {
  const normalized = String(value).trim().toLowerCase();
  if (['true', 'yes', '1'].includes(normalized)) return true;
  if (['false', 'no', '0'].includes(normalized)) return false;
  errors.push(`Input "${name}" must be "true" or "false" (received "${value}").`);
  return false;
}

function parseEnum(value, name, allowed, errors, { lowercase = true } = {}) {
  const normalized = lowercase ? String(value).trim().toLowerCase() : String(value).trim();
  if (allowed.includes(normalized)) return normalized;
  errors.push(`Input "${name}" must be one of: ${allowed.join(', ')} (received "${value}").`);
  return allowed[0];
}

/**
 * Resolves a consumer-supplied relative path and refuses to leave the
 * workspace. Repository content and inputs are treated as untrusted, so
 * "path: ../../etc" must not turn into a scan of the runner's filesystem.
 */
function resolveInsideWorkspace(workspace, candidate, name, errors) {
  if (candidate.includes('\0')) {
    errors.push(`Input "${name}" contains a null byte.`);
    return null;
  }
  if (candidate.startsWith('-')) {
    errors.push(`Input "${name}" must not start with "-" (received "${candidate}").`);
    return null;
  }

  const workspaceReal = realpathOrSelf(workspace);
  const resolved = path.resolve(workspaceReal, candidate);
  const resolvedReal = realpathOrSelf(resolved);
  const relative = path.relative(workspaceReal, resolvedReal);

  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    errors.push(
      `Input "${name}" must point inside the checked-out repository (received "${candidate}").`,
    );
    return null;
  }

  return { absolute: resolvedReal, relative: relative === '' ? '.' : toPosix(relative) };
}

function realpathOrSelf(target) {
  try {
    return fs.realpathSync(target);
  } catch {
    return path.resolve(target);
  }
}

/**
 * Builds the validated configuration. Throws a single `UserError` listing
 * every problem, so a consumer fixing their workflow sees all of them at once.
 */
export function loadConfig(env = process.env) {
  const errors = [];
  const workspace = env.GITHUB_WORKSPACE && env.GITHUB_WORKSPACE.length > 0
    ? env.GITHUB_WORKSPACE
    : process.cwd();

  if (!dirExists(workspace)) {
    throw new UserError(`Workspace directory "${workspace}" does not exist.`);
  }

  const scanPathInput = readInput(env, 'path', '.');
  const scanPath = resolveInsideWorkspace(workspace, scanPathInput, 'path', errors);
  if (scanPath && !dirExists(scanPath.absolute)) {
    errors.push(
      `Input "path" points at "${scanPathInput}", which is not a directory in the checked-out repository. Did the workflow run actions/checkout first?`,
    );
  }

  const severity = parseEnum(readInput(env, 'severity', 'high'), 'severity', THRESHOLDS, errors);

  const sast = parseBoolean(readInput(env, 'sast', 'true'), 'sast', errors);
  const trivy = parseBoolean(readInput(env, 'trivy', 'true'), 'trivy', errors);
  const dependencyAudit = parseBoolean(
    readInput(env, 'dependency-audit', 'true'),
    'dependency-audit',
    errors,
  );
  const secretScan = parseBoolean(readInput(env, 'secret-scan', 'true'), 'secret-scan', errors);
  const monorepo = parseBoolean(readInput(env, 'monorepo', 'true'), 'monorepo', errors);
  const requireIgnoreExpiry = parseBoolean(
    readInput(env, 'require-ignore-expiry', 'false'),
    'require-ignore-expiry',
    errors,
  );
  const failOnError = parseBoolean(readInput(env, 'fail-on-error', 'true'), 'fail-on-error', errors);

  if (!sast && !trivy && !dependencyAudit && !secretScan) {
    errors.push(
      'All scanners are disabled (sast, trivy, dependency-audit and secret-scan are all "false"); there is nothing to do.',
    );
  }

  // An explicit Trivy severity list wins; otherwise it is derived from the
  // global threshold so the two inputs can never disagree.
  const trivySeverityInput = readInput(env, 'trivy-severity', '');
  let trivySeverities = trivySeverityList(severity);
  if (trivySeverityInput.length > 0) {
    const requested = splitList(trivySeverityInput).map((item) => item.toUpperCase());
    const invalid = requested.filter((item) => !TRIVY_SEVERITIES.includes(item));
    if (invalid.length > 0) {
      errors.push(
        `Input "trivy-severity" contains unsupported values: ${invalid.join(', ')}. Allowed: ${TRIVY_SEVERITIES.join(', ')}.`,
      );
    } else if (requested.length === 0) {
      errors.push('Input "trivy-severity" is set but contains no severities.');
    } else {
      trivySeverities = TRIVY_SEVERITIES.filter((item) => requested.includes(item));
    }
  }

  const trivyScannersInput = readInput(env, 'trivy-scanners', 'vuln,misconfig');
  const requestedScanners = splitList(trivyScannersInput).map((item) => item.toLowerCase());
  const invalidScanners = requestedScanners.filter((item) => !TRIVY_SCANNERS.includes(item));
  if (invalidScanners.length > 0) {
    errors.push(
      `Input "trivy-scanners" contains unsupported values: ${invalidScanners.join(', ')}. Allowed: ${TRIVY_SCANNERS.join(', ')}.`,
    );
  }
  if (trivy && requestedScanners.length === 0) {
    errors.push('Input "trivy-scanners" must list at least one Trivy scanner.');
  }
  const trivyScanners = TRIVY_SCANNERS.filter((item) => requestedScanners.includes(item));

  const auditLevelInput = readInput(env, 'audit-level', '');
  let auditLevel = npmAuditLevel(severity);
  if (auditLevelInput.length > 0) {
    auditLevel = parseEnum(
      auditLevelInput === 'medium' ? 'moderate' : auditLevelInput,
      'audit-level',
      ['info', 'low', 'moderate', 'high', 'critical'],
      errors,
    );
  }

  const sastConfigs = splitList(readInput(env, 'sast-config', ''));
  for (const config of sastConfigs) {
    if (!SAFE_TOKEN.test(config)) {
      errors.push(
        `Input "sast-config" entry "${config}" is not a valid Semgrep config reference. Use registry packs such as "p/owasp-top-ten" or repository-relative rule file paths.`,
      );
    }
  }

  const reportDirInput = readInput(env, 'report-dir', '.web-security');
  const reportDir = resolveInsideWorkspace(workspace, reportDirInput, 'report-dir', errors);

  const ignoreFileInput = readInput(env, 'ignore-file', '');
  let ignoreFile = null;
  let ignoreFileExplicit = false;
  if (ignoreFileInput.length > 0) {
    ignoreFileExplicit = true;
    const resolved = resolveInsideWorkspace(workspace, ignoreFileInput, 'ignore-file', errors);
    if (resolved && !fileExists(resolved.absolute)) {
      errors.push(
        `Input "ignore-file" points at "${ignoreFileInput}", which does not exist. Remove the input to use the default locations, or create the file.`,
      );
    }
    ignoreFile = resolved;
  } else {
    for (const candidate of DEFAULT_IGNORE_FILES) {
      const absolute = path.join(realpathOrSelf(workspace), candidate);
      if (fileExists(absolute)) {
        ignoreFile = { absolute, relative: candidate };
        break;
      }
    }
  }

  if (errors.length > 0) {
    throw new UserError('Invalid inputs for keldynai/web-security.', { details: errors });
  }

  return {
    workspace: realpathOrSelf(workspace),
    scanPath: scanPath.absolute,
    scanPathRelative: scanPath.relative,
    severity,
    scanners: { sast, trivy, dependencyAudit, secretScan },
    monorepo,
    requireIgnoreExpiry,
    failOnError,
    trivySeverities,
    trivyScanners,
    auditLevel,
    sastConfigs,
    reportDir: reportDir.absolute,
    reportDirRelative: reportDir.relative,
    ignoreFile: ignoreFile ? ignoreFile.absolute : null,
    ignoreFileRelative: ignoreFile ? ignoreFile.relative : null,
    ignoreFileExplicit,
  };
}
