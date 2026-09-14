/**
 * Aggregation: scanner state + raw outputs -> one normalised report.
 *
 * This is the only place that decides pass/fail. Every scanner script records
 * what happened (`ok`, `error`, `skipped`) and leaves its raw output behind;
 * nothing else is allowed to fail the job, which is what makes the outcome
 * predictable and the four states (PASS / FAIL / ERROR / SKIPPED) distinct.
 *
 * Ordering matters: findings are collected, merged across scanners, filtered by
 * severity, and only then matched against justified suppressions. A finding
 * below the severity threshold is kept in `report.json` but is not actionable,
 * so nothing is invisible.
 */

import fs from 'node:fs';
import path from 'node:path';

import { applyIgnores } from './ignores.mjs';
import { mergeFindings, sortFindings } from './findings.mjs';
import { countBySeverity, meetsThreshold } from './severity.mjs';
import { tryReadJsonFile } from './util.mjs';
import { normalizeTrivy } from './normalize/trivy.mjs';
import { normalizeSemgrep } from './normalize/semgrep.mjs';
import { normalizeGitleaks } from './normalize/gitleaks.mjs';
import { normalizeDependencyAudit } from './normalize/dependency.mjs';

export const REPORT_SCHEMA_VERSION = 1;

/** Scanner identifiers in the order they are reported. */
export const SCANNER_ORDER = ['sast', 'trivy', 'dependency', 'secrets'];

export const SCANNER_LABELS = {
  sast: 'SAST',
  trivy: 'Trivy',
  dependency: 'Dependency Audit',
  secrets: 'Secrets',
};

/**
 * @param {object} options
 * @param {object} options.config validated config
 * @param {object} options.detect discovery result
 * @param {{entries: Array, warnings: string[]}} options.ignores validated ignores
 * @param {string} options.stateDir directory holding status/ and raw/
 * @param {string} options.today ISO date for expiry evaluation
 */
export function buildReport({ config, detect, ignores, stateDir, today, tools = {} }) {
  const warnings = [...(detect.warnings ?? []), ...(ignores.warnings ?? [])];
  const scanners = [];
  let collected = [];

  for (const name of SCANNER_ORDER) {
    const enabled = isEnabled(name, config);
    const status = readStatus(stateDir, name);

    if (!enabled) {
      scanners.push({
        name,
        label: SCANNER_LABELS[name],
        status: 'disabled',
        state: 'disabled',
        message: 'Disabled by workflow configuration.',
        tool: null,
        findings: 0,
        ignored: 0,
        belowThreshold: 0,
        counts: countBySeverity([]),
        details: [],
      });
      continue;
    }

    if (!status) {
      // An enabled scanner with no status file means a step never ran or was
      // killed. Reporting success here would be the worst kind of bug.
      scanners.push({
        name,
        label: SCANNER_LABELS[name],
        status: 'error',
        state: 'error',
        message:
          'The scanner produced no status file; the step did not complete. Re-run the job and check the log for that step.',
        tool: null,
        findings: 0,
        ignored: 0,
        belowThreshold: 0,
        counts: countBySeverity([]),
        details: [],
      });
      continue;
    }

    const { findings, warnings: scannerWarnings, error } = collectFindings(name, stateDir, config);
    warnings.push(...scannerWarnings);

    const state = error && status.state === 'ok' ? 'error' : status.state;
    // When the scanner itself already reported a failure, its message carries
    // the tail of the tool's own stderr, which is far more useful for
    // debugging than "the output file was unparsable" — that is only a
    // consequence. The normaliser's error is used when the step thought it
    // had succeeded.
    const message = (status.state === 'error' ? status.message : null) ?? error ?? status.message ?? null;

    scanners.push({
      name,
      label: SCANNER_LABELS[name],
      status: state,
      state,
      message,
      tool: status.tool ?? null,
      // The installed version is recorded per tool (`semgrep`, `gitleaks`),
      // which is not the same name as the scanner section (`sast`, `secrets`).
      version: emptyToNull(status.version) ?? tools[status.tool] ?? tools[name] ?? null,
      details: status.projects ?? [],
      findings: 0,
      ignored: 0,
      belowThreshold: 0,
      counts: countBySeverity([]),
    });

    if (state === 'ok') collected = collected.concat(findings);
  }

  // Merge cross-scanner duplicates (Trivy vs npm audit), then apply policy.
  const merged = mergeFindings(collected).map((finding) => ({
    ...finding,
    belowThreshold: !meetsThreshold(finding.severity, config.severity),
  }));

  const { findings, unused } = applyIgnores(merged, ignores.entries, today);
  const ordered = sortFindings(findings);

  const actionable = ordered.filter((finding) => !finding.ignored && !finding.belowThreshold);
  const ignored = ordered.filter((finding) => finding.ignored);
  const informational = ordered.filter((finding) => !finding.ignored && finding.belowThreshold);

  // Per-scanner tallies credit every tool that reported a finding, so the
  // section totals can add up to more than the global count when two scanners
  // agree. The global count is the authoritative one.
  for (const scanner of scanners) {
    if (scanner.state !== 'ok') continue;
    const owned = ordered.filter((finding) => scannerKeys(finding).includes(scanner.name));
    const ownedActionable = owned.filter((finding) => !finding.ignored && !finding.belowThreshold);
    scanner.findings = ownedActionable.length;
    scanner.ignored = owned.filter((finding) => finding.ignored).length;
    scanner.belowThreshold = owned.filter(
      (finding) => !finding.ignored && finding.belowThreshold,
    ).length;
    scanner.counts = countBySeverity(ownedActionable);
    scanner.status = ownedActionable.length > 0 ? 'fail' : 'pass';
  }

  for (const entry of unused) {
    warnings.push(
      `Ignore entry ${entry.id} (scanner: ${entry.scanner}) did not match any finding; remove it once the issue is gone.`,
    );
  }
  if ((detect.nativeSuppressions ?? []).length > 0) {
    warnings.push(
      `Scanner-native suppression files are present and are honoured by the scanner that owns them, outside this Action's justification policy: ${detect.nativeSuppressions.join(', ')}.`,
    );
  }

  const erroredScanners = scanners.filter((scanner) => scanner.state === 'error');
  const hasError = erroredScanners.length > 0 && config.failOnError;

  const result = hasError ? 'error' : actionable.length > 0 ? 'fail' : 'pass';

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    action: 'keldynai/web-security',
    generatedAt: new Date().toISOString(),
    result,
    exitReason: describeResult(result, actionable.length, erroredScanners),
    config: {
      path: config.scanPathRelative,
      severity: config.severity,
      monorepo: config.monorepo,
      scanners: config.scanners,
      trivySeverities: config.trivySeverities,
      trivyScanners: config.trivyScanners,
      auditLevel: config.auditLevel,
      ignoreFile: config.ignoreFileRelative,
      requireIgnoreExpiry: config.requireIgnoreExpiry,
      failOnError: config.failOnError,
    },
    tools,
    discovery: {
      projects: detect.projects.map((project) => ({
        dir: project.dir,
        packageManager: project.packageManager,
        lockfile: project.lockfile,
        yarnMajor: project.yarnMajor ?? null,
      })),
      packagesWithoutLockfile: detect.packagesWithoutLockfile ?? [],
      infrastructure: detect.infrastructure ?? {},
      nativeSuppressions: detect.nativeSuppressions ?? [],
    },
    scanners: scanners.map((scanner) => ({
      name: scanner.name,
      label: scanner.label,
      status: scanner.status,
      message: scanner.message,
      tool: scanner.tool ?? null,
      version: scanner.version ?? null,
      actionable: scanner.findings,
      ignored: scanner.ignored,
      belowThreshold: scanner.belowThreshold,
      severities: scanner.counts,
      projects: scanner.details,
    })),
    summary: {
      actionable: actionable.length,
      ignored: ignored.length,
      belowThreshold: informational.length,
      total: ordered.length,
      severities: countBySeverity(actionable),
      errors: erroredScanners.map((scanner) => ({ scanner: scanner.name, message: scanner.message })),
    },
    warnings,
    findings: ordered,
  };
}

function emptyToNull(value) {
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

function describeResult(result, actionableCount, erroredScanners) {
  if (result === 'error') {
    return `Scanner failure: ${erroredScanners.map((scanner) => scanner.name).join(', ')}`;
  }
  if (result === 'fail') {
    return `${actionableCount} actionable finding${actionableCount === 1 ? '' : 's'} at or above the configured severity`;
  }
  return 'No actionable findings at or above the configured severity';
}

/**
 * The scanner sections a finding is reported under — every tool that reported
 * it, not just the one that reported it first.
 *
 * A vulnerability found by both Trivy and `npm audit` is one finding and one
 * piece of work, but it has to appear in both sections: a summary that said
 * "Dependency Audit: PASS" because Trivy happened to be listed first would tell
 * a maintainer their lockfile is clean when the audit reported a critical
 * advisory. The global totals still count it once.
 */
function scannerKeys(finding) {
  if (finding.category === 'sast') return ['sast'];

  const sources = Array.isArray(finding.sources) && finding.sources.length > 0
    ? finding.sources
    : [finding.scanner];

  const keys = new Set();
  for (const source of sources) {
    if (source === 'secrets') keys.add('secrets');
    else if (source === 'trivy') keys.add('trivy');
    else if (source === 'sast') keys.add('sast');
    else keys.add('dependency');
  }
  return [...keys];
}

function isEnabled(name, config) {
  switch (name) {
    case 'sast':
      return config.scanners.sast;
    case 'trivy':
      return config.scanners.trivy;
    case 'dependency':
      return config.scanners.dependencyAudit;
    case 'secrets':
      return config.scanners.secretScan;
    default:
      return false;
  }
}

export function readStatus(stateDir, name) {
  return tryReadJsonFile(path.join(stateDir, 'status', `${name}.json`), null);
}

function collectFindings(name, stateDir, config) {
  const rawDir = path.join(stateDir, 'raw');
  switch (name) {
    case 'trivy':
      return fromFile(path.join(rawDir, 'trivy.json'), (document) =>
        normalizeTrivy(document, { scanRoot: config.scanPath }),
      );
    case 'sast':
      return fromFile(path.join(rawDir, 'semgrep.json'), normalizeSemgrep);
    case 'secrets':
      return fromFile(
        path.join(rawDir, 'gitleaks.json'),
        (document) => normalizeGitleaks(document, { scanRoot: config.scanPath }),
        { emptyIsClean: true },
      );
    case 'dependency':
      return collectDependencyFindings(rawDir);
    default:
      return { findings: [], warnings: [], error: null };
  }
}

function fromFile(file, normalize, { emptyIsClean = false } = {}) {
  if (!fs.existsSync(file)) {
    if (emptyIsClean) return { findings: [], warnings: [], error: null };
    return {
      findings: [],
      warnings: [],
      error: `expected scanner output at ${path.basename(file)} but the file is missing`,
    };
  }

  let document;
  try {
    const text = fs.readFileSync(file, 'utf8').trim();
    if (text.length === 0) {
      if (emptyIsClean) return { findings: [], warnings: [], error: null };
      return { findings: [], warnings: [], error: `${path.basename(file)} is empty` };
    }
    document = JSON.parse(text);
  } catch (error) {
    return {
      findings: [],
      warnings: [],
      error: `${path.basename(file)} is not valid JSON (${error.message})`,
    };
  }

  // A normaliser may decide the output itself proves the scanner failed, even
  // though the process exited successfully. Semgrep does exactly that when
  // semgrep-core dies: exit 0, empty results, an error in the JSON.
  const { findings, warnings, error } = normalize(document);
  return { findings, warnings, error: error ?? null };
}

/**
 * The dependency audit runs once per detected project, so results arrive as a
 * set of `audit-N.meta.json` descriptors plus their raw output files.
 */
function collectDependencyFindings(rawDir) {
  const findings = [];
  const warnings = [];
  const errors = [];

  let metaFiles = [];
  try {
    metaFiles = fs
      .readdirSync(rawDir)
      .filter((name) => /^audit-\d+\.meta\.json$/.test(name))
      .sort();
  } catch {
    return { findings, warnings, error: 'no dependency audit output was produced' };
  }

  for (const metaFile of metaFiles) {
    const meta = tryReadJsonFile(path.join(rawDir, metaFile), null);
    if (!meta) {
      errors.push(`${metaFile} could not be read`);
      continue;
    }

    const label = meta.dir === '.' ? 'repository root' : meta.dir;

    if (meta.state === 'error') {
      errors.push(`${label} (${meta.packageManager}): ${meta.message ?? 'audit failed'}`);
      continue;
    }
    if (meta.state === 'skipped') {
      warnings.push(`Dependency audit skipped for ${label}: ${meta.message ?? 'not applicable'}`);
      continue;
    }

    const outputFile = path.join(rawDir, meta.output ?? '');
    let text = '';
    try {
      text = fs.readFileSync(outputFile, 'utf8');
    } catch (error) {
      errors.push(`${label}: could not read audit output (${error.message})`);
      continue;
    }

    const normalized = normalizeDependencyAudit(text, {
      scanner: meta.packageManager,
      project: meta.dir,
      lockfile: meta.lockfile,
    });

    if (normalized.error) {
      errors.push(`${label} (${meta.packageManager}): ${normalized.error}`);
      continue;
    }
    findings.push(...normalized.findings);
    warnings.push(...normalized.warnings);
  }

  return {
    findings,
    warnings,
    error: errors.length > 0 ? `dependency audit failed for: ${errors.join('; ')}` : null,
  };
}
