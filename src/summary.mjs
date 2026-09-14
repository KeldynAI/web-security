/**
 * Human-facing output: job log, `$GITHUB_STEP_SUMMARY` and inline annotations.
 *
 * Three rules shape everything here:
 *   1. Suppressed findings are always printed, with their justification and
 *      expiry. A suppression that nobody can see is indistinguishable from a
 *      vulnerability nobody noticed.
 *   2. Every actionable finding is printed together with the exact ignore-file
 *      entry that would suppress it, so the documented path of least
 *      resistance still requires writing a reason.
 *   3. Anything interpolated into a workflow command is escaped. Finding paths
 *      come from repository content, which is attacker-controlled on a pull
 *      request, and must never be able to emit their own workflow commands.
 */

import { SCANNER_LABELS } from './report.mjs';
import { oneLine } from './util.mjs';

const SEVERITY_DISPLAY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'INFO'];
const MAX_ANNOTATIONS = 20;
const MAX_LISTED_FINDINGS = 50;

const STATUS_TEXT = {
  pass: 'PASS',
  fail: 'FAIL — security findings',
  error: 'ERROR — scanner failed',
  skipped: 'SKIPPED — not applicable',
  disabled: 'SKIPPED — disabled',
};

const STATUS_ICON = {
  pass: '✅',
  fail: '❌',
  error: '🟠',
  skipped: '⚪',
  disabled: '⚪',
};

export function renderConsole(report) {
  const lines = [];
  lines.push('');
  lines.push('Web Security Summary');
  lines.push('====================');

  for (const scanner of report.scanners) {
    lines.push('');
    lines.push(scanner.label);
    lines.push(`  ${STATUS_TEXT[scanner.status] ?? scanner.status}`);

    if (scanner.status === 'fail') {
      lines.push(`  ${severityBreakdown(scanner.severities)}`);
      lines.push(`  ${scanner.actionable} actionable`);
    }
    if (scanner.ignored > 0) {
      lines.push(`  ${scanner.ignored} ignored with justification`);
    }
    if (scanner.belowThreshold > 0) {
      lines.push(`  ${scanner.belowThreshold} below the "${report.config.severity}" threshold (not actionable)`);
    }
    if (scanner.message && scanner.status !== 'pass' && scanner.status !== 'fail') {
      lines.push(`  ${oneLine(scanner.message, 300)}`);
    }
    for (const project of scanner.projects ?? []) {
      const label = project.dir === '.' ? 'repository root' : project.dir;
      lines.push(`  - ${label}: ${project.tool ?? project.packageManager} ${project.state}`);
    }
  }

  const actionable = report.findings.filter((finding) => !finding.ignored && !finding.belowThreshold);
  const ignored = report.findings.filter((finding) => finding.ignored);

  if (actionable.length > 0) {
    lines.push('');
    lines.push('Actionable security findings');
    lines.push('----------------------------');
    for (const finding of actionable.slice(0, MAX_LISTED_FINDINGS)) {
      lines.push(...describeFinding(finding));
    }
    if (actionable.length > MAX_LISTED_FINDINGS) {
      lines.push(`… and ${actionable.length - MAX_LISTED_FINDINGS} more (see ${report.config.reportPath ?? 'the JSON report'}).`);
    }
  }

  if (ignored.length > 0) {
    lines.push('');
    lines.push('Ignored security findings');
    lines.push('-------------------------');
    for (const finding of ignored) {
      lines.push(`${finding.id}${finding.package ? ` (${finding.package})` : ''}`);
      // One rule suppressed in several places produces several identical
      // headings, so the location is what tells them apart.
      if (finding.path) {
        lines.push(`Location: ${finding.line ? `${finding.path}:${finding.line}` : finding.path}`);
      }
      lines.push(`Scanner: ${finding.sources.join(', ')}`);
      lines.push(`Severity: ${finding.severity}`);
      lines.push(`Reason: ${finding.reason}`);
      lines.push(`Expires: ${finding.expires ?? 'never (no expiry date set)'}`);
      lines.push('');
    }
  }

  if (report.warnings.length > 0) {
    lines.push('');
    lines.push('Warnings');
    lines.push('--------');
    for (const warning of report.warnings) lines.push(`- ${oneLine(warning, 300)}`);
  }

  lines.push('');
  lines.push(`Result: ${resultWord(report.result)}`);
  lines.push(report.exitReason);
  lines.push('');

  return lines.join('\n');
}

function describeFinding(finding) {
  const lines = [];
  const location = finding.line ? `${finding.path}:${finding.line}` : finding.path ?? 'n/a';
  lines.push(`[${finding.severity}] ${finding.id}${finding.package ? ` — ${finding.package}` : ''}`);
  if (finding.title) lines.push(`  ${oneLine(finding.title, 200)}`);
  lines.push(`  Location: ${location}`);
  if (finding.installedVersion || finding.fixedVersion || finding.vulnerableRange) {
    const parts = [];
    if (finding.installedVersion) parts.push(`installed ${finding.installedVersion}`);
    if (finding.vulnerableRange) parts.push(`vulnerable ${finding.vulnerableRange}`);
    parts.push(finding.fixedVersion ? `fixed in ${finding.fixedVersion}` : 'no fixed version published');
    lines.push(`  ${parts.join(', ')}`);
  }
  if (finding.url) lines.push(`  ${finding.url}`);
  lines.push(`  Reported by: ${finding.sources.join(', ')}`);
  lines.push('  To accept this risk, add a justified entry to the ignore file:');
  for (const snippetLine of ignoreSnippet(finding).split('\n')) {
    lines.push(`    ${snippetLine}`);
  }
  lines.push('');
  return lines;
}

/**
 * The copy-pasteable ignore entry for a finding. `reason` is intentionally a
 * placeholder the author has to replace: the validator rejects placeholder and
 * too-short reasons, so this cannot be pasted through unmodified.
 */
export function ignoreSnippet(finding) {
  const scanner = finding.sources.length > 1 ? 'dependency' : finding.sources[0];
  const lines = [`- id: "${finding.id}"`, `  scanner: ${scanner}`];
  if (finding.package) lines.push(`  package: "${finding.package}"`);
  if (finding.category !== 'dependency' && finding.path) {
    lines.push(`  paths: ["${finding.path}"]`);
  }
  lines.push('  reason: "<why this is acceptable in this application>"');
  lines.push(`  expires: "${defaultExpiry()}"`);
  return lines.join('\n');
}

function defaultExpiry(now = new Date()) {
  const date = new Date(now.getTime());
  date.setUTCDate(date.getUTCDate() + 90);
  return date.toISOString().slice(0, 10);
}

export function renderMarkdown(report) {
  const lines = [];
  lines.push('## Web Security');
  lines.push('');
  lines.push(
    `**Result: ${resultWord(report.result)}** — ${report.exitReason}. Severity threshold: \`${report.config.severity}\`.`,
  );
  lines.push('');
  lines.push('| Scanner | Result | Actionable | Ignored | Below threshold |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const scanner of report.scanners) {
    lines.push(
      `| ${scanner.label}${scanner.version ? ` (${scanner.version})` : ''} | ${STATUS_ICON[scanner.status] ?? ''} ${STATUS_TEXT[scanner.status] ?? scanner.status} | ${scanner.actionable} | ${scanner.ignored} | ${scanner.belowThreshold} |`,
    );
  }
  lines.push('');

  if (report.discovery.projects.length > 0) {
    lines.push('<details><summary>Detected projects</summary>');
    lines.push('');
    lines.push('| Directory | Package manager | Lockfile |');
    lines.push('| --- | --- | --- |');
    for (const project of report.discovery.projects) {
      const manager = project.packageManager === 'yarn'
        ? `yarn ${project.yarnMajor && project.yarnMajor >= 2 ? '(berry)' : '(classic)'}`
        : project.packageManager;
      lines.push(`| \`${escapeMarkdown(project.dir)}\` | ${manager} | \`${escapeMarkdown(project.lockfile)}\` |`);
    }
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  const actionable = report.findings.filter((finding) => !finding.ignored && !finding.belowThreshold);
  if (actionable.length > 0) {
    lines.push(`### Actionable findings (${actionable.length})`);
    lines.push('');
    lines.push('| Severity | Id | Package / Rule | Location | Fix | Reported by |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    for (const finding of actionable.slice(0, MAX_LISTED_FINDINGS)) {
      const location = finding.line ? `${finding.path}:${finding.line}` : finding.path ?? '—';
      const fix = finding.fixedVersion ? `\`${escapeMarkdown(finding.fixedVersion)}\`` : '—';
      const subject = finding.package ?? finding.ruleId ?? '—';
      const id = finding.url
        ? `[${escapeMarkdown(finding.id)}](${finding.url})`
        : `\`${escapeMarkdown(finding.id)}\``;
      lines.push(
        `| ${finding.severity} | ${id} | \`${escapeMarkdown(oneLine(subject, 60))}\` | \`${escapeMarkdown(location)}\` | ${fix} | ${finding.sources.join(', ')} |`,
      );
    }
    if (actionable.length > MAX_LISTED_FINDINGS) {
      lines.push('');
      lines.push(`_${actionable.length - MAX_LISTED_FINDINGS} further findings are in the JSON report._`);
    }
    lines.push('');
  }

  const ignored = report.findings.filter((finding) => finding.ignored);
  if (ignored.length > 0) {
    lines.push(`### Ignored with justification (${ignored.length})`);
    lines.push('');
    lines.push('| Id | Location | Scanner | Reason | Expires |');
    lines.push('| --- | --- | --- | --- | --- |');
    for (const finding of ignored) {
      // Without the location, one rule suppressed in five files is five
      // identical rows.
      const location = finding.path
        ? `\`${escapeMarkdown(finding.line ? `${finding.path}:${finding.line}` : finding.path)}\``
        : '—';
      lines.push(
        `| \`${escapeMarkdown(finding.id)}\` | ${location} | ${finding.sources.join(', ')} | ${escapeMarkdown(oneLine(finding.reason, 160))} | ${finding.expires ?? '**never**'} |`,
      );
    }
    lines.push('');
  }

  if (report.warnings.length > 0) {
    lines.push('<details><summary>Warnings</summary>');
    lines.push('');
    for (const warning of report.warnings) lines.push(`- ${escapeMarkdown(oneLine(warning, 300))}`);
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  lines.push(
    '_This Action provides a baseline set of automated security checks. It is not a replacement for threat modelling, code review, penetration testing, runtime protections or a mature application-security programme._',
  );
  lines.push('');

  return lines.join('\n');
}

/**
 * Emits `::error` / `::warning` workflow commands so findings appear inline on
 * the pull request. This uses only log output, so it needs no extra
 * permissions and works for pull requests from forks.
 */
export function renderAnnotations(report) {
  const lines = [];
  const actionable = report.findings.filter(
    (finding) => !finding.ignored && !finding.belowThreshold && finding.path,
  );

  for (const finding of actionable.slice(0, MAX_ANNOTATIONS)) {
    const properties = [
      `file=${escapeProperty(finding.path)}`,
      finding.line ? `line=${finding.line}` : null,
      `title=${escapeProperty(`Web Security: ${finding.severity} ${finding.id}`)}`,
    ]
      .filter(Boolean)
      .join(',');
    const message = [
      finding.title ? oneLine(finding.title, 200) : finding.id,
      finding.package ? `Package: ${finding.package}` : null,
      finding.fixedVersion ? `Fixed in: ${finding.fixedVersion}` : null,
      `Reported by: ${finding.sources.join(', ')}`,
    ]
      .filter(Boolean)
      .join(' | ');
    lines.push(`::error ${properties}::${escapeData(message)}`);
  }

  for (const error of report.summary.errors) {
    lines.push(
      `::error title=${escapeProperty(`Web Security: ${error.scanner} failed`)}::${escapeData(oneLine(error.message ?? 'scanner error', 300))}`,
    );
  }

  return lines.join('\n');
}

export function resultWord(result) {
  if (result === 'pass') return 'PASSED';
  if (result === 'fail') return 'FAILED';
  return 'ERROR';
}

function severityBreakdown(severities) {
  const parts = SEVERITY_DISPLAY_ORDER.filter((severity) => (severities[severity] ?? 0) > 0).map(
    (severity) => `${severities[severity]} ${severity}`,
  );
  return parts.length > 0 ? parts.join(', ') : 'no findings above the threshold';
}

/** GitHub workflow-command escaping (see @actions/core). */
function escapeData(value) {
  return String(value ?? '')
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

function escapeProperty(value) {
  return escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/** Keeps repository-controlled strings from breaking the summary tables. */
function escapeMarkdown(value) {
  return String(value ?? '')
    .replace(/\r?\n/g, ' ')
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`');
}
