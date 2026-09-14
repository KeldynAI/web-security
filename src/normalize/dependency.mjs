/**
 * npm / Yarn / pnpm audit output -> normalised findings.
 *
 * Five different output shapes exist in the wild and a single web repository
 * can easily contain three of them:
 *
 *   1. npm >= 7           `{ vulnerabilities: { <pkg>: { via: [...] } } }`
 *   2. npm 6 and pnpm     `{ advisories: { <id>: {...} } }`
 *   3. Yarn Classic       NDJSON, `{ "type": "auditAdvisory", "data": {...} }`
 *   4. Yarn Berry         NDJSON, `{ "value": "<pkg>", "children": {...} }`
 *   5. Yarn Berry (npm-compatible mode)  same as (2)
 *
 * All five are handled here rather than in five shell scripts, which is the
 * main reason the audit logic is JavaScript: the alternative is `jq`
 * expressions duplicated per package manager.
 *
 * Advisory identifiers are normalised towards GHSA/CVE wherever the tool
 * provides them, because those are the identifiers a human writes in the
 * ignore file, and they are what allows a Trivy CVE and an npm GHSA for the
 * same package to merge into one finding.
 */

import {
  canonicalAdvisoryId,
  createFinding,
  extractAdvisoryIds,
  extractAdvisoryIdsFromUrls,
} from '../findings.mjs';
import { oneLine, uniqueStrings } from '../util.mjs';

/**
 * @param {string} text raw stdout of the audit command
 * @param {object} meta `{ scanner, project, lockfile }`
 * @returns {{findings: Array, warnings: string[], error: string|null}}
 */
export function normalizeDependencyAudit(text, meta) {
  const warnings = [];
  const raw = String(text ?? '').trim();

  if (raw.length === 0) {
    return { findings: [], warnings, error: 'the audit command produced no output' };
  }

  const parsed = parseAuditPayload(raw);
  if (parsed.error) return { findings: [], warnings, error: parsed.error };
  if (parsed.documents.length === 0) {
    return {
      findings: [],
      warnings,
      error: `the audit output could not be parsed as JSON (first bytes: ${oneLine(raw.slice(0, 120), 120)})`,
    };
  }

  const findings = [];
  for (const document of parsed.documents) {
    if (isPlainObject(document?.error)) {
      return { findings: [], warnings, error: describeToolError(document.error) };
    }
    if (typeof document?.error === 'string') {
      return { findings: [], warnings, error: oneLine(document.error, 200) };
    }
    if (document?.type === 'error') {
      return { findings: [], warnings, error: oneLine(stringifyData(document.data), 200) };
    }

    findings.push(...normalizeDocument(document, meta, warnings));
  }

  return { findings: dedupe(findings), warnings, error: null };
}

/** Parses either a single JSON document or newline-delimited JSON. */
function parseAuditPayload(raw) {
  try {
    return { documents: [JSON.parse(raw)], error: null };
  } catch {
    /* Fall through to NDJSON. */
  }

  const documents = [];
  let unparsable = 0;
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      unparsable += 1;
      continue;
    }
    try {
      documents.push(JSON.parse(trimmed));
    } catch {
      unparsable += 1;
    }
  }

  if (documents.length === 0 && unparsable > 0) {
    return { documents: [], error: 'the audit output was neither JSON nor newline-delimited JSON' };
  }
  return { documents, error: null };
}

function normalizeDocument(document, meta, warnings) {
  if (!isPlainObject(document)) return [];

  if (isPlainObject(document.vulnerabilities)) {
    return normalizeNpmV7(document.vulnerabilities, meta);
  }
  if (isPlainObject(document.advisories)) {
    return Object.values(document.advisories)
      .filter(isPlainObject)
      .map((advisory) => normalizeAdvisory(advisory, meta));
  }
  if (document.type === 'auditAdvisory' && isPlainObject(document.data?.advisory)) {
    return [normalizeAdvisory(document.data.advisory, meta, document.data.resolution)];
  }
  if (typeof document.value === 'string' && isPlainObject(document.children)) {
    return [normalizeYarnBerry(document.value, document.children, meta)];
  }

  // Summary/progress records are expected and uninteresting.
  const known = ['auditSummary', 'auditAction', 'auditAdvisory', 'info', 'warning', 'success', 'step'];
  if (document.type && !known.includes(document.type)) {
    warnings.push(`Ignored unrecognised ${meta.scanner} audit record of type "${oneLine(document.type, 40)}".`);
  }
  return [];
}

/** npm >= 7: advisories hang off each vulnerable package as objects in `via`. */
function normalizeNpmV7(vulnerabilities, meta) {
  const findings = [];

  for (const [packageName, entry] of Object.entries(vulnerabilities)) {
    if (!isPlainObject(entry)) continue;
    const fixedVersion = isPlainObject(entry.fixAvailable) ? entry.fixAvailable.version ?? null : null;

    for (const via of entry.via ?? []) {
      // String entries mean "vulnerable because of another package"; the
      // advisory itself is reported on that other package's entry.
      if (!isPlainObject(via)) continue;

      const identifiers = uniqueStrings([
        ...extractAdvisoryIdsFromUrls(via.url ?? ''),
        via.source !== undefined ? `NPM-${via.source}` : null,
      ]);

      findings.push(
        createFinding({
          scanner: meta.scanner,
          category: 'dependency',
          id: identifiers[0] ?? `NPM-${packageName}`,
          aliases: identifiers,
          severity: via.severity ?? entry.severity,
          title: via.title,
          package: via.dependency ?? via.name ?? packageName,
          // npm's audit report (v2) does not include installed versions.
          installedVersion: null,
          fixedVersion,
          vulnerableRange: via.range ?? entry.range ?? null,
          project: meta.project,
          path: meta.lockfile,
          paths: [meta.project],
          url: via.url ?? null,
        }),
      );
    }
  }

  return findings;
}

/** npm 6 / pnpm / Yarn Classic advisory objects. */
function normalizeAdvisory(advisory, meta, resolution = null) {
  const identifiers = uniqueStrings([
    advisory.github_advisory_id,
    ...(Array.isArray(advisory.cves) ? advisory.cves : []),
    ...extractAdvisoryIdsFromUrls(advisory.url ?? ''),
    advisory.id !== undefined ? `NPM-${advisory.id}` : null,
  ]).map(canonicalAdvisoryId);

  const installedVersion = Array.isArray(advisory.findings) && advisory.findings.length > 0
    ? advisory.findings[0]?.version ?? null
    : resolution?.version ?? null;

  return createFinding({
    scanner: meta.scanner,
    category: 'dependency',
    id: identifiers[0] ?? `NPM-${advisory.module_name ?? 'unknown'}`,
    aliases: identifiers,
    severity: advisory.severity,
    title: advisory.title,
    package: advisory.module_name ?? null,
    installedVersion,
    fixedVersion: minimumPatchedVersion(advisory.patched_versions),
    vulnerableRange: advisory.vulnerable_versions ?? null,
    project: meta.project,
    path: meta.lockfile,
    paths: [meta.project],
    url: advisory.url ?? null,
  });
}

/** Yarn Berry: `{ value: "lodash", children: { ID, Issue, Severity, ... } }`. */
function normalizeYarnBerry(packageName, children, meta) {
  const rawId = children.ID ?? children.id;
  const identifiers = uniqueStrings([
    ...extractAdvisoryIds(String(rawId ?? '')),
    rawId !== undefined && rawId !== null && !/^(GHSA|CVE)-/i.test(String(rawId))
      ? `NPM-${rawId}`
      : null,
  ]);

  const treeVersions = children['Tree Versions'] ?? children.treeVersions;

  return createFinding({
    scanner: meta.scanner,
    category: 'dependency',
    id: identifiers[0] ?? `NPM-${packageName}`,
    aliases: identifiers,
    severity: children.Severity ?? children.severity,
    title: children.Issue ?? children.issue,
    package: packageName,
    installedVersion: Array.isArray(treeVersions) ? treeVersions[0] ?? null : treeVersions ?? null,
    fixedVersion: null,
    vulnerableRange: children['Vulnerable Versions'] ?? children.vulnerableVersions ?? null,
    project: meta.project,
    path: meta.lockfile,
    paths: [meta.project],
    url: null,
  });
}

/** ">=4.17.21" -> "4.17.21"; anything more complex is left unresolved. */
function minimumPatchedVersion(patched) {
  if (typeof patched !== 'string') return null;
  const match = /^>=\s*([0-9][\w.+-]*)$/.exec(patched.trim());
  return match ? match[1] : null;
}

function dedupe(findings) {
  const seen = new Set();
  const result = [];
  for (const finding of findings) {
    const key = `${finding.id}|${finding.package}|${finding.project}|${finding.installedVersion ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
}

function describeToolError(error) {
  const parts = [error.code, error.summary, error.detail].filter(
    (part) => typeof part === 'string' && part.trim().length > 0,
  );
  return oneLine(parts.join(': '), 300) || 'the audit command reported an unspecified error';
}

function stringifyData(data) {
  if (typeof data === 'string') return data;
  try {
    return JSON.stringify(data);
  } catch {
    return String(data);
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
