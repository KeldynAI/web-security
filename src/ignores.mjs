/**
 * The justified-suppression engine.
 *
 * Policy, enforced here and nowhere else:
 *   - A finding can only be suppressed by an entry that names the scanner and
 *     carries a written reason. There is no "list of CVE ids" mode.
 *   - An expired entry never suppresses anything, and an expired entry in the
 *     file is an error, so security debt cannot quietly become permanent.
 *   - Anything malformed is an error with a message that says how to fix it,
 *     rather than being skipped (a skipped ignore rule that the author believed
 *     was active is the worst possible outcome for a security tool).
 *
 * This layer is also why the Action does not simply pass a `.trivyignore` to
 * Trivy or let `# nosemgrep` comments through: those mechanisms accept an id
 * with no reason and no expiry.
 */

import { UserError, fileExists, readTextFile, uniqueStrings } from './util.mjs';
import { parseYaml, YamlError } from './yaml.mjs';

/** Scanner names a suppression may target. */
export const SUPPORTED_SCANNERS = ['sast', 'trivy', 'npm', 'yarn', 'pnpm', 'secrets'];

/** Convenience groups, so one entry can cover the package-manager audits. */
export const SCANNER_GROUPS = {
  dependency: ['npm', 'yarn', 'pnpm'],
  any: [...SUPPORTED_SCANNERS],
};

export const ALLOWED_SCANNER_VALUES = [...SUPPORTED_SCANNERS, ...Object.keys(SCANNER_GROUPS)];

const ALLOWED_TOP_LEVEL_KEYS = new Set(['version', 'ignores']);
const ALLOWED_ENTRY_KEYS = new Set(['id', 'scanner', 'reason', 'expires', 'package', 'paths']);

export const SUPPORTED_VERSION = 1;
/** Short enough to allow a real sentence, long enough to reject "n/a". */
export const MIN_REASON_LENGTH = 15;
/** Expiries beyond this horizon defeat the point of expiring at all. */
const MAX_EXPIRY_DAYS = 400;

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{1,200}$/;
const PACKAGE_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9._/@-]{0,200}$/;
const PATH_PATTERN = /^[A-Za-z0-9._*][A-Za-z0-9._*/-]{0,300}$/;
const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Reasons that technically exist but explain nothing. */
const PLACEHOLDER_REASONS = new Set([
  'n/a',
  'na',
  'none',
  'no reason',
  'nothing',
  'tbd',
  'todo',
  'to do',
  'wip',
  'fixme',
  'later',
  'ignore',
  'ignored',
  'ignore it',
  'suppressed',
  'false positive',
  'not applicable',
  'temporary',
  'temp',
  'test',
  'testing',
  'because',
  'reasons',
  'see above',
  'as discussed',
  'known issue',
  'accepted',
  'wontfix',
  "won't fix",
]);

export function todayIso(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

/**
 * Loads and validates an ignore file.
 *
 * @param {string|null} file absolute path, or null when there is no ignore file
 * @param {object} [options]
 * @param {boolean} [options.requireExpiry] treat a missing `expires` as an error
 * @param {string} [options.today] ISO date used for expiry checks
 * @param {string} [options.displayPath] path shown in messages
 * @returns {{path: string|null, entries: Array, warnings: string[]}}
 */
export function loadIgnores(file, options = {}) {
  const { requireExpiry = false, today = todayIso(), displayPath = file } = options;

  if (!file) return { path: null, entries: [], warnings: [] };
  if (!fileExists(file)) {
    throw new UserError(`Ignore file "${displayPath}" does not exist.`);
  }

  const text = readTextFile(file);
  let document;
  try {
    document = file.endsWith('.json') ? JSON.parse(text) : parseYaml(text);
  } catch (error) {
    const suffix = error instanceof YamlError ? error.message : error.message;
    throw new UserError(`Ignore file "${displayPath}" could not be parsed: ${suffix}`, {
      details: [
        'The ignore file must be a YAML mapping with "version" and "ignores" keys.',
        'See https://github.com/keldynai/web-security#ignore-file for the schema.',
      ],
    });
  }

  const result = validateIgnoreDocument(document, { requireExpiry, today, displayPath });
  return { path: file, ...result };
}

/** Validates an already-parsed document. Exposed separately for unit tests. */
export function validateIgnoreDocument(document, options = {}) {
  const { requireExpiry = false, today = todayIso(), displayPath = 'ignore file' } = options;
  const errors = [];
  const warnings = [];

  if (document === null || document === undefined) {
    return { entries: [], warnings: [`Ignore file "${displayPath}" is empty; no suppressions are active.`] };
  }
  if (typeof document !== 'object' || Array.isArray(document)) {
    throw new UserError(
      `Ignore file "${displayPath}" must be a mapping with "version" and "ignores" keys.`,
    );
  }

  for (const key of Object.keys(document)) {
    if (!ALLOWED_TOP_LEVEL_KEYS.has(key)) {
      errors.push(
        `Unknown top-level key "${key}". Supported keys: ${[...ALLOWED_TOP_LEVEL_KEYS].join(', ')}.`,
      );
    }
  }

  if (!Object.hasOwn(document, 'version')) {
    errors.push('Missing "version: 1" at the top of the file.');
  } else if (Number(document.version) !== SUPPORTED_VERSION) {
    errors.push(
      `Unsupported ignore-file version "${document.version}"; this Action understands version ${SUPPORTED_VERSION}.`,
    );
  }

  const rawEntries = document.ignores;
  const entries = [];

  if (rawEntries === undefined || rawEntries === null) {
    warnings.push(`Ignore file "${displayPath}" has no "ignores" list; no suppressions are active.`);
  } else if (!Array.isArray(rawEntries)) {
    errors.push('"ignores" must be a list of entries.');
  } else {
    const seen = new Map();
    rawEntries.forEach((rawEntry, index) => {
      const entry = validateEntry(rawEntry, index, { requireExpiry, today, errors, warnings });
      if (!entry) return;

      const fingerprint = [
        entry.id.toLowerCase(),
        entry.scanner,
        (entry.package ?? '').toLowerCase(),
        entry.paths.join('|'),
      ].join('::');

      if (seen.has(fingerprint)) {
        errors.push(
          `${label(index)} duplicates ${label(seen.get(fingerprint))} (same id, scanner, package and paths). Remove one of them.`,
        );
        return;
      }
      seen.set(fingerprint, index);
      entries.push(entry);
    });
  }

  if (errors.length > 0) {
    throw new UserError(`Ignore file "${displayPath}" is invalid.`, { details: errors });
  }

  return { entries, warnings };
}

function label(index) {
  return `ignores[${index}]`;
}

function validateEntry(rawEntry, index, context) {
  const { requireExpiry, today, errors, warnings } = context;

  if (rawEntry === null || typeof rawEntry !== 'object' || Array.isArray(rawEntry)) {
    errors.push(`${label(index)} must be a mapping with "id", "scanner" and "reason" keys.`);
    return null;
  }

  let valid = true;

  for (const key of Object.keys(rawEntry)) {
    if (!ALLOWED_ENTRY_KEYS.has(key)) {
      errors.push(
        `${label(index)} has unknown key "${key}". Supported keys: ${[...ALLOWED_ENTRY_KEYS].join(', ')}.`,
      );
      valid = false;
    }
  }

  // --- id -------------------------------------------------------------------
  const rawId = rawEntry.id;
  let id = null;
  if (rawId === undefined || rawId === null || rawId === '') {
    errors.push(`${label(index)} is missing "id" (for example "CVE-2026-1234" or "GHSA-xxxx-yyyy-zzzz").`);
    valid = false;
  } else if (typeof rawId === 'number') {
    errors.push(`${label(index)} has a numeric id; quote it so it stays a string (id: "${rawId}").`);
    valid = false;
  } else if (typeof rawId !== 'string' || !ID_PATTERN.test(rawId.trim())) {
    errors.push(`${label(index)} has an invalid id "${String(rawId)}".`);
    valid = false;
  } else {
    id = rawId.trim();
  }

  // --- scanner --------------------------------------------------------------
  const rawScanner = rawEntry.scanner;
  let scanner = null;
  if (rawScanner === undefined || rawScanner === null || rawScanner === '') {
    errors.push(
      `${label(index)} is missing "scanner". Use one of: ${ALLOWED_SCANNER_VALUES.join(', ')}.`,
    );
    valid = false;
  } else if (typeof rawScanner !== 'string' || !ALLOWED_SCANNER_VALUES.includes(rawScanner.trim().toLowerCase())) {
    errors.push(
      `${label(index)} references unsupported scanner "${String(rawScanner)}". Use one of: ${ALLOWED_SCANNER_VALUES.join(', ')}.`,
    );
    valid = false;
  } else {
    scanner = rawScanner.trim().toLowerCase();
  }

  // --- reason (the whole point) ---------------------------------------------
  const rawReason = rawEntry.reason;
  let reason = null;
  if (rawReason === undefined || rawReason === null) {
    errors.push(
      `${label(index)} is missing "reason". Every suppression must explain why the finding is acceptable.`,
    );
    valid = false;
  } else if (typeof rawReason !== 'string' || rawReason.trim().length === 0) {
    errors.push(
      `${label(index)} has an empty "reason". Every suppression must explain why the finding is acceptable.`,
    );
    valid = false;
  } else if (rawReason.trim().length < MIN_REASON_LENGTH) {
    errors.push(
      `${label(index)} has a reason of ${rawReason.trim().length} characters; at least ${MIN_REASON_LENGTH} are required so the justification is reviewable.`,
    );
    valid = false;
  } else if (PLACEHOLDER_REASONS.has(rawReason.trim().toLowerCase().replace(/[.!]+$/, ''))) {
    errors.push(
      `${label(index)} has the placeholder reason "${rawReason.trim()}". Describe why this finding is not exploitable in this application.`,
    );
    valid = false;
  } else {
    reason = rawReason.trim().replace(/\s+/g, ' ');
  }

  // --- expires --------------------------------------------------------------
  const rawExpires = rawEntry.expires;
  let expires = null;
  if (rawExpires === undefined || rawExpires === null || rawExpires === '') {
    if (requireExpiry) {
      errors.push(
        `${label(index)} is missing "expires" and "require-ignore-expiry" is enabled. Add an expiry date (YYYY-MM-DD).`,
      );
      valid = false;
    } else {
      warnings.push(
        `${label(index)} (${rawId ?? 'unknown id'}) has no "expires" date; add one so the suppression is re-reviewed.`,
      );
    }
  } else {
    const value = rawExpires instanceof Date
      ? rawExpires.toISOString().slice(0, 10)
      : String(rawExpires).trim();
    if (!isRealDate(value)) {
      errors.push(
        `${label(index)} has an invalid "expires" value "${value}". Use an ISO date such as "2026-12-31".`,
      );
      valid = false;
    } else if (value < today) {
      errors.push(
        `${label(index)} (${rawId ?? 'unknown id'}) expired on ${value}. Re-assess the finding, then either fix it or renew the suppression with a current justification.`,
      );
      valid = false;
    } else {
      expires = value;
      if (daysBetween(today, value) > MAX_EXPIRY_DAYS) {
        warnings.push(
          `${label(index)} (${rawId ?? 'unknown id'}) expires on ${value}, more than ${MAX_EXPIRY_DAYS} days away; consider a shorter review cycle.`,
        );
      }
    }
  }

  // --- optional scoping -----------------------------------------------------
  let packageName = null;
  if (rawEntry.package !== undefined && rawEntry.package !== null) {
    if (typeof rawEntry.package !== 'string' || !PACKAGE_PATTERN.test(rawEntry.package.trim())) {
      errors.push(`${label(index)} has an invalid "package" value "${String(rawEntry.package)}".`);
      valid = false;
    } else {
      packageName = rawEntry.package.trim();
    }
  }

  let paths = [];
  if (rawEntry.paths !== undefined && rawEntry.paths !== null) {
    const list = Array.isArray(rawEntry.paths) ? rawEntry.paths : [rawEntry.paths];
    if (list.length === 0) {
      errors.push(`${label(index)} has an empty "paths" list; remove the key to match any path.`);
      valid = false;
    }
    for (const candidate of list) {
      if (typeof candidate !== 'string' || candidate.trim().length === 0) {
        errors.push(`${label(index)} has a non-string entry in "paths".`);
        valid = false;
      } else if (candidate.includes('..') || !PATH_PATTERN.test(candidate.trim())) {
        errors.push(
          `${label(index)} has an invalid path "${candidate}". Use repository-relative paths such as "frontend/" or "src/**/*.ts".`,
        );
        valid = false;
      } else {
        paths.push(candidate.trim());
      }
    }
    paths = uniqueStrings(paths).sort();
  }

  if (!valid) return null;

  return {
    id,
    scanner,
    scanners: expandScanner(scanner),
    reason,
    expires,
    package: packageName,
    paths,
    index,
  };
}

export function expandScanner(scanner) {
  return SCANNER_GROUPS[scanner] ? [...SCANNER_GROUPS[scanner]] : [scanner];
}

function isRealDate(value) {
  const match = DATE_PATTERN.exec(value);
  if (!match) return false;
  const [, year, month, day] = match;
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day)));
  return (
    date.getUTCFullYear() === Number(year) &&
    date.getUTCMonth() === Number(month) - 1 &&
    date.getUTCDate() === Number(day)
  );
}

function daysBetween(fromIso, toIso) {
  const from = Date.parse(`${fromIso}T00:00:00Z`);
  const to = Date.parse(`${toIso}T00:00:00Z`);
  return Math.round((to - from) / 86_400_000);
}

/**
 * Decides whether a normalised finding is covered by a suppression.
 * Returns the matching entry, or null.
 *
 * A finding reported by several scanners (Trivy and `npm audit` frequently
 * agree) is suppressed when an entry covers *any* of its sources; otherwise a
 * justified `scanner: trivy` entry would leave an identical npm finding
 * actionable and the summary would contradict itself.
 */
export function findMatchingIgnore(finding, entries, today = todayIso()) {
  const findingIds = new Set(
    uniqueStrings([finding.id, finding.ruleId, ...(finding.aliases ?? [])]).map((value) =>
      value.toLowerCase(),
    ),
  );
  const sources = finding.sources?.length > 0 ? finding.sources : [finding.scanner];

  for (const entry of entries) {
    // Defence in depth: validation already rejects expired entries, but an
    // expired entry must never suppress a finding even if validation changes.
    if (entry.expires && entry.expires < today) continue;
    if (!entry.scanners.some((name) => sources.includes(name))) continue;
    if (!findingIds.has(entry.id.toLowerCase())) continue;
    if (entry.package && entry.package.toLowerCase() !== String(finding.package ?? '').toLowerCase()) {
      continue;
    }
    if (entry.paths.length > 0 && !entry.paths.some((pattern) => pathMatches(finding.path, pattern))) {
      continue;
    }
    return entry;
  }

  return null;
}

/** Directory-prefix match with `*` (one segment) and `**` (any depth) globs. */
export function pathMatches(findingPath, pattern) {
  if (!findingPath) return false;
  const normalizedPath = String(findingPath).replace(/^\.\//, '');
  const normalizedPattern = pattern.replace(/^\.\//, '');

  if (!normalizedPattern.includes('*')) {
    if (normalizedPattern.endsWith('/')) return normalizedPath.startsWith(normalizedPattern);
    return (
      normalizedPath === normalizedPattern || normalizedPath.startsWith(`${normalizedPattern}/`)
    );
  }

  const regex = new RegExp(
    `^${normalizedPattern
      .split('**')
      .map((chunk) =>
        chunk
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          .replace(/\*/g, '[^/]*'),
      )
      .join('.*')}$`,
  );
  return regex.test(normalizedPath);
}

/**
 * Annotates findings with their suppression state.
 * Returns the annotated findings plus the entries that matched nothing, which
 * are reported so stale suppressions get cleaned up.
 */
export function applyIgnores(findings, entries, today = todayIso()) {
  const used = new Set();

  const annotated = findings.map((finding) => {
    const match = findMatchingIgnore(finding, entries, today);
    if (!match) {
      return { ...finding, ignored: false, reason: null, expires: null, ignoreIndex: null };
    }
    used.add(match.index);
    return {
      ...finding,
      ignored: true,
      reason: match.reason,
      expires: match.expires,
      ignoreIndex: match.index,
    };
  });

  const unused = entries.filter((entry) => !used.has(entry.index));
  return { findings: annotated, unused };
}
