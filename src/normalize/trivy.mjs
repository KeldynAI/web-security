/**
 * Trivy JSON -> normalised findings.
 *
 * One Trivy run produces vulnerability, misconfiguration and (optionally)
 * secret results in a single document, keyed by "Class". Each class maps onto
 * a different finding category so the summary can report them separately.
 *
 * Secret findings deliberately drop Trivy's `Match`/`Code` fields: they can
 * contain the credential itself, and this report is designed to be uploaded as
 * a CI artifact.
 */

import path from 'node:path';

import {
  canonicalAdvisoryId,
  createFinding,
  extractAdvisoryIdsFromUrls,
} from '../findings.mjs';
import { toPosix } from '../util.mjs';

export function normalizeTrivy(document, options = {}) {
  const { scanRoot = '.' } = options;
  const findings = [];
  const warnings = [];

  if (!document || typeof document !== 'object') {
    return { findings, warnings: ['Trivy produced no parsable JSON output.'] };
  }

  const results = Array.isArray(document.Results) ? document.Results : [];
  for (const result of results) {
    const target = relativeTarget(result.Target, scanRoot);
    const project = projectDirectory(target);

    for (const vulnerability of result.Vulnerabilities ?? []) {
      findings.push(normalizeVulnerability(vulnerability, target, project));
    }
    for (const misconfiguration of result.Misconfigurations ?? []) {
      // Trivy also reports PASS/EXCEPTION statuses; only failures are findings.
      if (misconfiguration.Status && misconfiguration.Status !== 'FAIL') continue;
      findings.push(normalizeMisconfiguration(misconfiguration, target));
    }
    for (const secret of result.Secrets ?? []) {
      findings.push(normalizeSecret(secret, target));
    }
  }

  return { findings, warnings };
}

function normalizeVulnerability(vulnerability, target, project) {
  const identifier = canonicalAdvisoryId(vulnerability.VulnerabilityID ?? '');
  // Trivy has no dedicated field for GHSA aliases, but its references include
  // the GitHub advisory URL; harvesting that lets the same vulnerability
  // reported by `npm audit` (as a GHSA) and by Trivy (as a CVE) merge into one
  // finding. Only references that are themselves an advisory page count --
  // vendor release notes link to many unrelated CVEs.
  const aliases = extractAdvisoryIdsFromUrls(
    vulnerability.PrimaryURL ?? '',
    ...(vulnerability.References ?? []),
  );

  return createFinding({
    scanner: 'trivy',
    category: 'dependency',
    id: identifier,
    aliases,
    severity: vulnerability.Severity,
    title: vulnerability.Title || vulnerability.Description,
    package: vulnerability.PkgName ?? null,
    installedVersion: vulnerability.InstalledVersion ?? null,
    fixedVersion: vulnerability.FixedVersion ?? null,
    project,
    path: vulnerability.PkgPath ? toPosix(vulnerability.PkgPath) : target,
    paths: [target],
    url: vulnerability.PrimaryURL ?? null,
  });
}

function normalizeMisconfiguration(misconfiguration, target) {
  const identifier = misconfiguration.AVDID || misconfiguration.ID || 'UNKNOWN';
  const aliases = [misconfiguration.ID, misconfiguration.AVDID].filter(Boolean);

  return createFinding({
    scanner: 'trivy',
    category: 'misconfig',
    id: identifier,
    aliases,
    ruleId: misconfiguration.ID ?? null,
    severity: misconfiguration.Severity,
    title: misconfiguration.Title || misconfiguration.Message,
    path: target,
    line: misconfiguration.CauseMetadata?.StartLine ?? null,
    url: misconfiguration.PrimaryURL ?? null,
  });
}

function normalizeSecret(secret, target) {
  return createFinding({
    scanner: 'trivy',
    category: 'secret',
    id: secret.RuleID ?? 'unknown-secret',
    ruleId: secret.RuleID ?? null,
    // Trivy rates secrets, but a committed credential is never low risk.
    severity: secret.Severity ?? 'HIGH',
    title: secret.Title || secret.Category || 'Potential hardcoded secret',
    path: target,
    line: secret.StartLine ?? null,
  });
}

function relativeTarget(target, scanRoot) {
  if (!target) return null;
  const cleaned = String(target).replace(/^\.\//, '');
  if (!path.isAbsolute(cleaned)) return toPosix(cleaned);
  const relative = path.relative(scanRoot, cleaned);
  return toPosix(relative.startsWith('..') ? cleaned : relative);
}

/**
 * Maps a lockfile target such as `frontend/package-lock.json` to the project
 * directory `frontend`, which is the unit dependency findings are merged and
 * suppressed by.
 */
function projectDirectory(target) {
  if (!target) return '.';
  const directory = path.posix.dirname(target);
  return directory === '' || directory === '.' ? '.' : directory;
}
