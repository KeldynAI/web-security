/**
 * The normalised finding model.
 *
 * Every scanner is translated into this one shape before suppressions,
 * severity thresholds, counting or reporting happen. That is what makes a
 * single ignore file work across five tools, and it is the seam where SARIF
 * output or a new scanner can be added without touching the policy logic.
 *
 * A second job lives here: Trivy and `npm audit` genuinely overlap on Node
 * lockfiles, so identical dependency findings are merged into one record that
 * remembers every scanner that reported it. Without merging, the summary would
 * double-count and a consumer would need two ignore entries for one CVE.
 */

import { normalizeSeverity } from './severity.mjs';
import { uniqueStrings } from './util.mjs';

export const CATEGORIES = ['dependency', 'sast', 'secret', 'misconfig', 'license'];

/** Display precedence when one finding was reported by several scanners. */
const SOURCE_ORDER = ['trivy', 'npm', 'yarn', 'pnpm', 'sast', 'secrets'];

/**
 * GHSA and CVE identifiers. The GHSA part is deliberately permissive about the
 * alphabet: GitHub's identifier alphabet is an implementation detail, and
 * missing a real advisory id would silently prevent a Trivy CVE and an npm
 * GHSA for the same vulnerability from merging.
 */
const ADVISORY_ID_PATTERN = /\b(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d{4,7})\b/gi;

/** The same identifiers, anchored, for checking one candidate string. */
const ADVISORY_ID_EXACT = /^(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d{4,7})$/i;

/**
 * Builds a finding. Unknown/missing fields become `null` rather than being
 * omitted, so `report.json` has a stable schema for downstream consumers.
 */
export function createFinding(input) {
  const id = String(input.id ?? '').trim() || 'UNKNOWN';
  const aliases = uniqueStrings(input.aliases ?? []).filter(
    (alias) => alias.toLowerCase() !== id.toLowerCase(),
  );

  return {
    scanner: input.scanner,
    sources: [input.scanner],
    category: input.category,
    id,
    aliases: aliases.sort(),
    ruleId: input.ruleId ?? null,
    severity: normalizeSeverity(input.severity),
    title: input.title ? String(input.title).replace(/\s+/g, ' ').trim() : null,
    package: input.package ?? null,
    installedVersion: input.installedVersion ?? null,
    fixedVersion: input.fixedVersion ?? null,
    vulnerableRange: input.vulnerableRange ?? null,
    project: input.project ?? null,
    path: input.path ?? null,
    paths: uniqueStrings([input.path, ...(input.paths ?? [])]).sort(),
    line: Number.isInteger(input.line) && input.line > 0 ? input.line : null,
    url: input.url ?? null,
    // Suppression state is filled in later by the ignore engine.
    ignored: false,
    reason: null,
    expires: null,
    belowThreshold: false,
  };
}

/**
 * Writes an advisory identifier the way its issuer does: `CVE-2021-44906` in
 * upper case, `GHSA-xvch-5gv4-984h` with a lower-case suffix. Every scanner's
 * ids go through this, so the same advisory from two scanners merges, and the
 * ignore-file snippet the summary prints can be pasted into a tracker or a
 * search engine unchanged.
 */
export function canonicalAdvisoryId(identifier) {
  const value = String(identifier ?? '').trim();
  if (/^GHSA-/i.test(value)) return `GHSA-${value.slice(5).toLowerCase()}`;
  if (/^(CVE|NPM)-/i.test(value)) return value.toUpperCase();
  return value;
}

/** Pulls GHSA/CVE identifiers out of free-form text. */
export function extractAdvisoryIds(...values) {
  const found = [];
  for (const value of values.flat()) {
    if (typeof value !== 'string') continue;
    const matches = value.matchAll(ADVISORY_ID_PATTERN);
    for (const match of matches) found.push(canonicalAdvisoryId(match[1]));
  }
  return uniqueStrings(found);
}

/**
 * Pulls identifiers out of reference URLs, accepting one only when the URL
 * actually *is* that advisory — that is, when the identifier is the last path
 * segment, as in `github.com/advisories/GHSA-…` or
 * `nvd.nist.gov/vuln/detail/CVE-…`.
 *
 * Scanning the whole URL instead would harvest every identifier that happens
 * to appear in a link, and vendor security-release pages list dozens. Those
 * ids become aliases, and aliases decide both which findings merge and which
 * ignore entries match: one advisory would then be suppressed by a
 * justification written for a completely different vulnerability.
 */
export function extractAdvisoryIdsFromUrls(...values) {
  const found = [];
  for (const value of values.flat()) {
    if (typeof value !== 'string' || value.length === 0) continue;
    const segment = value
      .split(/[?#]/, 1)[0]
      .replace(/\/+$/, '')
      .split('/')
      .pop();
    if (!segment) continue;
    const candidate = segment.replace(/\.(html?|json|txt)$/i, '');
    if (ADVISORY_ID_EXACT.test(candidate)) found.push(canonicalAdvisoryId(candidate));
  }
  return uniqueStrings(found);
}

/**
 * Merges dependency findings that describe the same advisory for the same
 * package in the same project, regardless of which scanner reported it.
 *
 * Merging is keyed on project (not just package) so that a vulnerability in
 * `frontend/` and the same one in `backend/` stay separate findings: they are
 * two pieces of work, and a suppression scoped to one must not silence the
 * other.
 */
export function mergeFindings(findings) {
  const mergeable = [];
  const passthrough = [];

  for (const finding of findings) {
    if (finding.category === 'dependency') mergeable.push(finding);
    else passthrough.push(finding);
  }

  const parents = mergeable.map((_, index) => index);
  const find = (index) => {
    let root = index;
    while (parents[root] !== root) root = parents[root];
    while (parents[index] !== root) {
      const next = parents[index];
      parents[index] = root;
      index = next;
    }
    return root;
  };
  const union = (left, right) => {
    const rootLeft = find(left);
    const rootRight = find(right);
    if (rootLeft !== rootRight) parents[Math.max(rootLeft, rootRight)] = Math.min(rootLeft, rootRight);
  };

  // Two findings belong together when they share any advisory identifier for
  // the same package in the same project.
  const firstSeen = new Map();
  mergeable.forEach((finding, index) => {
    for (const key of mergeKeys(finding)) {
      if (firstSeen.has(key)) union(firstSeen.get(key), index);
      else firstSeen.set(key, index);
    }
  });

  const groups = new Map();
  mergeable.forEach((finding, index) => {
    const root = find(index);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(finding);
  });

  const merged = [...groups.values()].map((group) => (group.length === 1 ? group[0] : mergeGroup(group)));
  return sortFindings([...merged, ...passthrough]);
}

function mergeKeys(finding) {
  const scope = `${finding.project ?? '.'}|${String(finding.package ?? '').toLowerCase()}`;
  return uniqueStrings([finding.id, ...finding.aliases]).map(
    (identifier) => `${scope}|${identifier.toLowerCase()}`,
  );
}

function mergeGroup(group) {
  const ordered = [...group].sort(compareForRepresentative);
  const representative = ordered[0];

  return {
    ...representative,
    sources: SOURCE_ORDER.filter((name) => group.some((finding) => finding.sources.includes(name))),
    scanner: representative.scanner,
    aliases: uniqueStrings(
      group.flatMap((finding) => [finding.id, ...finding.aliases]),
    )
      .filter((alias) => alias.toLowerCase() !== representative.id.toLowerCase())
      .sort(),
    severity: ordered[0].severity,
    installedVersion: firstNonNull(group, 'installedVersion'),
    fixedVersion: firstNonNull(group, 'fixedVersion'),
    vulnerableRange: firstNonNull(group, 'vulnerableRange'),
    url: firstNonNull(group, 'url'),
    title: firstNonNull(group, 'title'),
    paths: uniqueStrings(group.flatMap((finding) => finding.paths)).sort(),
  };
}

/** Highest severity wins; ties are broken by scanner precedence, then id. */
function compareForRepresentative(left, right) {
  const bySeverity = severityWeight(right.severity) - severityWeight(left.severity);
  if (bySeverity !== 0) return bySeverity;
  const bySource = SOURCE_ORDER.indexOf(left.scanner) - SOURCE_ORDER.indexOf(right.scanner);
  if (bySource !== 0) return bySource;
  return left.id.localeCompare(right.id);
}

function severityWeight(severity) {
  return ['INFO', 'LOW', 'UNKNOWN', 'MEDIUM', 'HIGH', 'CRITICAL'].indexOf(normalizeSeverity(severity));
}

function firstNonNull(group, field) {
  for (const finding of group) {
    if (finding[field] !== null && finding[field] !== undefined && finding[field] !== '') {
      return finding[field];
    }
  }
  return null;
}

/** Stable, human-friendly ordering: worst first, then deterministic tiebreaks. */
export function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    if (left.ignored !== right.ignored) return left.ignored ? 1 : -1;
    const bySeverity = severityWeight(right.severity) - severityWeight(left.severity);
    if (bySeverity !== 0) return bySeverity;
    const byCategory = CATEGORIES.indexOf(left.category) - CATEGORIES.indexOf(right.category);
    if (byCategory !== 0) return byCategory;
    const byPath = String(left.path ?? '').localeCompare(String(right.path ?? ''));
    if (byPath !== 0) return byPath;
    const byPackage = String(left.package ?? '').localeCompare(String(right.package ?? ''));
    if (byPackage !== 0) return byPackage;
    const byId = left.id.localeCompare(right.id);
    if (byId !== 0) return byId;
    return (left.line ?? 0) - (right.line ?? 0);
  });
}
