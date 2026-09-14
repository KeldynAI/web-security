/**
 * Gitleaks JSON -> normalised findings.
 *
 * The `Secret` and `Match` fields are never copied into a finding. They hold
 * the candidate credential in plaintext, and `report.json` is meant to be
 * uploadable as a build artifact; the file path, line and rule are enough to
 * find and rotate the secret.
 *
 * Gitleaks does not assign severities, so every leak is treated as HIGH: a
 * committed credential needs a decision, not a triage backlog. Findings can
 * still be suppressed by rule id (plus `paths:`) or by their stable
 * fingerprint, with a justification like everything else.
 */

import path from 'node:path';

import { createFinding } from '../findings.mjs';
import { toPosix } from '../util.mjs';

export function normalizeGitleaks(document, options = {}) {
  const { scanRoot = '.' } = options;
  const findings = [];
  const warnings = [];

  // An empty report file is Gitleaks' way of saying "no leaks".
  if (document === null || document === undefined || document === '') {
    return { findings, warnings };
  }
  if (!Array.isArray(document)) {
    return { findings, warnings: ['Gitleaks produced unexpected JSON output (expected an array).'] };
  }

  for (const leak of document) {
    const file = relativeFile(leak.File ?? leak.file, scanRoot);
    const line = leak.StartLine ?? null;
    findings.push(
      createFinding({
        scanner: 'secrets',
        category: 'secret',
        id: leak.RuleID ?? 'unknown-rule',
        // Gitleaks' own fingerprint embeds whatever path it was given, which
        // differs between runners; recompute it from the relative path so a
        // fingerprint-scoped suppression stays valid.
        aliases: file && line ? [`${file}:${leak.RuleID}:${line}`] : [],
        ruleId: leak.RuleID ?? null,
        severity: 'HIGH',
        title: leak.Description ?? 'Potential hardcoded secret',
        path: file,
        line,
      }),
    );
  }

  return { findings, warnings };
}

/** Gitleaks echoes the target path it was given, which may be absolute. */
function relativeFile(file, scanRoot) {
  if (!file) return null;
  const cleaned = String(file).replace(/^\.\//, '');
  if (!path.isAbsolute(cleaned)) return toPosix(cleaned);
  const relative = path.relative(scanRoot, cleaned);
  return toPosix(relative.startsWith('..') ? cleaned : relative);
}
