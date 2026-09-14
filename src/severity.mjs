/**
 * One severity vocabulary for every scanner.
 *
 * Each tool speaks its own dialect (Semgrep: INFO/WARNING/ERROR, npm:
 * info/low/moderate/high/critical, Trivy: UNKNOWN..CRITICAL, Gitleaks: none at
 * all), so everything is mapped onto a single ordered scale before the
 * severity threshold is applied. Without this, "severity: high" would mean
 * something different in each section of the report.
 */

export const SEVERITIES = ['INFO', 'LOW', 'UNKNOWN', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * UNKNOWN is ranked with LOW: it must not be silently dropped, but an
 * unrated finding should not fail a build configured for HIGH either.
 */
const RANKS = new Map([
  ['INFO', 0],
  ['LOW', 1],
  ['UNKNOWN', 1],
  ['MEDIUM', 2],
  ['HIGH', 3],
  ['CRITICAL', 4],
]);

const ALIASES = new Map([
  ['info', 'INFO'],
  ['informational', 'INFO'],
  ['note', 'INFO'],
  ['low', 'LOW'],
  ['warning', 'MEDIUM'],
  ['moderate', 'MEDIUM'],
  ['medium', 'MEDIUM'],
  ['high', 'HIGH'],
  ['error', 'HIGH'],
  ['critical', 'CRITICAL'],
  ['unknown', 'UNKNOWN'],
]);

/** The four values accepted by the `severity` input, from strictest to loosest. */
export const THRESHOLDS = ['critical', 'high', 'medium', 'low'];

export function normalizeSeverity(value) {
  if (value === undefined || value === null) return 'UNKNOWN';
  const key = String(value).trim().toLowerCase();
  return ALIASES.get(key) ?? 'UNKNOWN';
}

export function severityRank(severity) {
  return RANKS.get(normalizeSeverity(severity)) ?? 1;
}

export function meetsThreshold(severity, threshold) {
  return severityRank(severity) >= severityRank(threshold);
}

/** Trivy takes an explicit severity list, derived from the global threshold. */
export function trivySeverityList(threshold) {
  const minimum = severityRank(threshold);
  const list = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].filter(
    (severity) => severityRank(severity) >= minimum,
  );
  // UNKNOWN ranks with LOW, so only include it when LOW findings are wanted.
  if (minimum <= severityRank('LOW')) list.unshift('UNKNOWN');
  return list;
}

/** `npm audit --audit-level` uses "moderate" where this Action says "medium". */
export function npmAuditLevel(threshold) {
  const mapping = { critical: 'critical', high: 'high', medium: 'moderate', low: 'low' };
  return mapping[String(threshold).toLowerCase()] ?? 'high';
}

/** Counts findings per severity, always returning every key for stable output. */
export function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, INFO: 0 };
  for (const finding of findings) {
    const severity = normalizeSeverity(finding.severity);
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return counts;
}
