/**
 * Semgrep JSON -> normalised findings.
 *
 * Semgrep's own severities (INFO/WARNING/ERROR) are mapped onto the shared
 * scale by `severity.mjs`. The rule id is used as the finding id so that a
 * suppression can name a rule, optionally scoped with `paths:`.
 *
 * Semgrep reports per-file problems (syntax errors in a repository file, a
 * timeout on a generated bundle) in a separate `errors` array. Those are
 * surfaced as warnings: they are coverage gaps worth seeing, but a single
 * unparsable file is not a scanner failure.
 *
 * An error with no file attached is different: it means the engine itself
 * failed, and Semgrep still exits 0 with an empty `results` array when that
 * happens. Reporting it as a warning would mean printing "SAST: PASS" for a
 * scan that never ran, so those are returned as a scanner error instead.
 */

import { createFinding } from '../findings.mjs';
import { oneLine, toPosix } from '../util.mjs';

export function normalizeSemgrep(document) {
  const findings = [];
  const warnings = [];

  if (!document || typeof document !== 'object') {
    return { findings, warnings: ['Semgrep produced no parsable JSON output.'] };
  }

  for (const result of document.results ?? []) {
    const extra = result.extra ?? {};
    const metadata = extra.metadata ?? {};

    findings.push(
      createFinding({
        scanner: 'sast',
        category: 'sast',
        id: result.check_id ?? 'unknown-rule',
        // The fingerprint allows suppressing one specific occurrence rather
        // than the whole rule.
        aliases: [extra.fingerprint].filter(Boolean),
        ruleId: result.check_id ?? null,
        severity: extra.severity,
        title: oneLine(extra.message ?? metadata.message ?? result.check_id, 200),
        path: result.path ? toPosix(String(result.path).replace(/^\.\//, '')) : null,
        line: result.start?.line ?? null,
        url: metadata.shortlink ?? firstReference(metadata.references),
      }),
    );
  }

  const reported = (document.errors ?? []).filter((error) => error && typeof error === 'object');
  const fatal = reported.filter(isEngineFailure);
  const fileLevel = reported.filter((error) => !isEngineFailure(error));

  if (fileLevel.length > 0) {
    const sample = fileLevel
      .slice(0, 3)
      .map((error) => oneLine(error.message ?? error.long_msg ?? error.type ?? 'unknown', 100));
    warnings.push(
      `Semgrep reported ${fileLevel.length} file-level problem(s); those files may not be fully analysed: ${sample.join('; ')}`,
    );
  }

  if (fatal.length > 0) {
    const sample = fatal
      .slice(0, 2)
      .map((error) => oneLine(error.message ?? error.long_msg ?? error.type ?? 'unknown', 300));
    return {
      findings,
      warnings,
      error: `Semgrep failed internally and its results are incomplete: ${sample.join('; ')}`,
    };
  }

  return { findings, warnings };
}

/**
 * True for an error that is about the engine rather than about one repository
 * file. File-level problems carry a path or a span; an out-of-memory
 * semgrep-core, an unreachable rule registry or an invalid rule set does not.
 */
function isEngineFailure(error) {
  if (String(error.level ?? '').toLowerCase() !== 'error') return false;
  const hasFile = Boolean(error.path) || (Array.isArray(error.spans) && error.spans.length > 0);
  return !hasFile;
}

function firstReference(references) {
  if (!Array.isArray(references) || references.length === 0) return null;
  return typeof references[0] === 'string' ? references[0] : null;
}
