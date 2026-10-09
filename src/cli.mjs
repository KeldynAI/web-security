#!/usr/bin/env node
/**
 * Single entry point for every Node-side operation the Action performs.
 *
 * Subcommands
 *   preflight       validate inputs, discover the repository, validate the
 *                   ignore file, and publish the plan as step outputs
 *   audit-plan      emit the detected projects as TSV for the audit loop
 *   tool-manifest   emit pinned version/url/checksum for an installer
 *   record-status   write a scanner's outcome to the state directory
 *   record-audit    write one dependency-audit project outcome
 *   aggregate       normalise all scanner output into one report and verdict
 *
 * Nothing here shells out, and nothing here fails a job: `preflight` fails on
 * invalid configuration (fast feedback, before any scanner downloads), and
 * `aggregate` records a verdict that `scripts/enforce.sh` acts on.
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { loadConfig } from './config.mjs';
import { discover, formatProjectTable } from './detect.mjs';
import { loadIgnores, todayIso } from './ignores.mjs';
import { buildReport } from './report.mjs';
import { renderAnnotations, renderConsole, renderMarkdown, resultWord } from './summary.mjs';
import {
  UserError,
  appendGithubKeyValue,
  appendGithubText,
  parseArgs,
  readJsonFile,
  writeJsonFile,
} from './util.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ACTION_ROOT = path.resolve(HERE, '..');
const TOOLS_FILE = path.join(ACTION_ROOT, 'tools.json');

function stateDir() {
  const value = process.env.WEB_SECURITY_STATE;
  if (!value) throw new Error('WEB_SECURITY_STATE is not set; the Action steps ran out of order.');
  return value;
}

function statePath(...parts) {
  return path.join(stateDir(), ...parts);
}

// --------------------------------------------------------------------------
// preflight
// --------------------------------------------------------------------------

function commandPreflight() {
  fs.writeFileSync(statePath('started-at'), String(Date.now()), 'utf8');
  const tools = readJsonFile(TOOLS_FILE);
  const config = loadConfig(process.env);

  const banner = [
    '',
    'Web Security (keldynai/web-security)',
    `  Semgrep:  ${tools.semgrep.version}${config.scanners.sast ? '' : ' (disabled)'}`,
    `  Trivy:    ${tools.trivy.version}${config.scanners.trivy ? '' : ' (disabled)'}`,
    `  Gitleaks: ${tools.gitleaks.version}${config.scanners.secretScan ? '' : ' (disabled)'}`,
    '',
    'Discover repository',
    `  Scan path:        ${config.scanPathRelative}`,
    `  Severity:         ${config.severity} (Trivy: ${config.trivySeverities.join(',')}; audit level: ${config.auditLevel})`,
    `  Monorepo scan:    ${config.monorepo ? 'enabled' : 'disabled (root project only)'}`,
    `  Ignore file:      ${config.ignoreFileRelative ?? 'none found'}`,
  ];

  const detected = discover(config.scanPath, {
    monorepo: config.monorepo,
    workspace: config.workspace,
  });

  banner.push('');
  banner.push('  Detected projects:');
  banner.push(formatProjectTable(detected.projects));

  const infrastructure = describeInfrastructure(detected.infrastructure);
  banner.push('');
  banner.push('  Infrastructure and configuration files:');
  banner.push(infrastructure.length > 0 ? `    ${infrastructure.join('\n    ')}` : '    (none detected)');

  if (detected.packagesWithoutLockfile.length > 0) {
    banner.push('');
    banner.push(
      `  package.json without a lockfile (not audited): ${detected.packagesWithoutLockfile.join(', ')}`,
    );
  }

  console.log(banner.join('\n'));

  const ignores = loadIgnores(config.ignoreFile, {
    requireExpiry: config.requireIgnoreExpiry,
    today: todayIso(),
    displayPath: config.ignoreFileRelative ?? config.ignoreFile,
  });

  if (ignores.entries.length > 0) {
    console.log('');
    console.log(`  Loaded ${ignores.entries.length} justified suppression(s) from ${config.ignoreFileRelative}.`);
  }
  for (const warning of [...detected.warnings, ...ignores.warnings]) {
    console.log(`  Warning: ${warning}`);
  }
  if (detected.nativeSuppressions.length > 0) {
    console.log('');
    console.log(
      `  Note: scanner-native suppression files found (${detected.nativeSuppressions.join(', ')}). Gitleaks' own ignores are disabled by this Action; other files are honoured by their scanner and are not covered by the justification policy.`,
    );
  }

  // Persist the validated plan; later steps never re-read raw inputs.
  fs.mkdirSync(statePath('status'), { recursive: true });
  fs.mkdirSync(statePath('raw'), { recursive: true });
  writeJsonFile(statePath('config.json'), config);
  writeJsonFile(statePath('detect.json'), detected);
  writeJsonFile(statePath('ignores.json'), { entries: ignores.entries, warnings: ignores.warnings });

  // An enabled-but-inapplicable scanner is SKIPPED, not PASS.
  const runDependency = config.scanners.dependencyAudit && detected.projects.length > 0;
  if (config.scanners.dependencyAudit && !runDependency) {
    console.log('');
    console.log('  No Node lockfile detected, so the npm/Yarn audit is skipped.');
    writeJsonFile(statePath('status', 'dependency.json'), {
      scanner: 'dependency',
      state: 'skipped',
      message: 'No package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml was found.',
      exitCode: 0,
      projects: [],
    });
  }

  // Later steps consume these validated values, never the raw inputs.
  const outputFile = process.env.GITHUB_OUTPUT;
  const outputs = {
    'state-dir': stateDir(),
    'scan-path': config.scanPath,
    'report-dir': config.reportDir,
    'run-sast': String(config.scanners.sast),
    'run-trivy': String(config.scanners.trivy),
    'run-dependency': String(runDependency),
    'run-secrets': String(config.scanners.secretScan),
    'trivy-severity': config.trivySeverities.join(','),
    'trivy-scanners': config.trivyScanners.join(','),
    'audit-level': config.auditLevel,
    'sast-config': config.sastConfigs.join(','),
    'project-count': String(detected.projects.length),
  };
  for (const [key, value] of Object.entries(outputs)) {
    appendGithubKeyValue(outputFile, key, value);
  }

  return 0;
}

function describeInfrastructure(infrastructure) {
  const labels = {
    dockerfiles: 'Dockerfile',
    compose: 'Docker Compose file',
    terraform: 'Terraform file',
    kubernetes: 'Kubernetes manifest',
    helm: 'Helm chart',
    workflows: 'GitHub Actions workflow',
  };

  return Object.entries(labels)
    .map(([key, label]) => {
      const files = infrastructure[key] ?? [];
      if (files.length === 0) return null;
      const plural = files.length === 1 ? label : `${label}s`;
      const sample = files.slice(0, 3).join(', ');
      const more = files.length > 3 ? `, +${files.length - 3} more` : '';
      return `${files.length} ${plural}: ${sample}${more}`;
    })
    .filter(Boolean);
}

// --------------------------------------------------------------------------
// audit-plan
// --------------------------------------------------------------------------

/**
 * Emits one record per project for `run-dependency-audit.sh`.
 *
 * Fields are separated by ASCII Unit Separator rather than a tab: Bash treats
 * tabs as IFS whitespace and collapses runs of them, which would silently
 * shift every column after an empty field (such as `yarnMajor` for an npm
 * project). US is not whitespace, so empty fields survive, and directory names
 * containing spaces stay intact.
 */
export const AUDIT_PLAN_SEPARATOR = '\u001f';

function commandAuditPlan() {
  const detected = readJsonFile(statePath('detect.json'));
  const lines = [];

  detected.projects.forEach((project, index) => {
    if (/[\n\r\u001f]/.test(project.dir)) {
      throw new UserError(
        `Project directory "${project.dir}" contains a newline or control character, which is not supported.`,
      );
    }
    // The lockfile is emitted as a repository-relative path, because that is
    // what a finding's location and a `paths:` suppression are matched against.
    const lockfilePath = project.dir === '.'
      ? project.lockfile
      : `${project.dir}/${project.lockfile}`;

    lines.push(
      [
        String(index),
        project.dir,
        project.packageManager,
        project.yarnMajor ?? '',
        lockfilePath,
        project.packageManagerField ?? '',
      ].join(AUDIT_PLAN_SEPARATOR),
    );
  });

  if (lines.length > 0) process.stdout.write(`${lines.join('\n')}\n`);
  return 0;
}

// --------------------------------------------------------------------------
// tool-manifest
// --------------------------------------------------------------------------

function commandToolManifest(args) {
  const tools = readJsonFile(TOOLS_FILE);
  const name = args.name;
  const tool = tools[name];
  if (!tool) throw new UserError(`Unknown tool "${name}".`);

  if (tool.installer === 'pypi') {
    process.stdout.write(`${tool.version}\n${tool.package}\n${tool.binary}\n`);
    return 0;
  }

  const platform = `${args.os ?? 'linux'}-${args.arch ?? 'x64'}`;
  const asset = tool.assets[platform];
  if (!asset) {
    throw new UserError(
      `${name} ${tool.version} has no pinned download for platform "${platform}". Supported: ${Object.keys(tool.assets).join(', ')}. Run this Action on a linux x64 or arm64 runner.`,
    );
  }

  const url = tool.urlTemplate.replace('{version}', tool.version).replace('{file}', asset.file);
  process.stdout.write(`${tool.version}\n${url}\n${asset.sha256}\n${tool.binary}\n${asset.file}\n`);
  return 0;
}

// --------------------------------------------------------------------------
// record-status / record-audit
// --------------------------------------------------------------------------

const SCANNER_STATES = ['ok', 'error', 'skipped'];

/**
 * Scanner scripts report their outcome through these subcommands instead of
 * building JSON in shell, which keeps message quoting and escaping in one
 * place. Free-form text (tool stderr) is passed by file, never as an argument.
 */
function commandRecordStatus(args) {
  const scanner = requireArg(args, 'scanner');
  const state = requireEnum(args, 'state', SCANNER_STATES);

  const status = {
    scanner,
    state,
    exitCode: Number.parseInt(args['exit-code'] ?? '0', 10) || 0,
    message: readMessage(args['message-file']),
    tool: args.tool ?? null,
    version: args.version ?? null,
    projects: args['projects-from-audit'] ? collectAuditProjects() : [],
  };

  writeJsonFile(statePath('status', `${scanner}.json`), status);
  return 0;
}

function commandRecordAudit(args) {
  const index = Number.parseInt(requireArg(args, 'index'), 10);
  if (!Number.isInteger(index) || index < 0) {
    throw new UserError('--index must be a non-negative integer.');
  }

  const meta = {
    index,
    dir: requireArg(args, 'dir'),
    packageManager: requireArg(args, 'package-manager'),
    lockfile: args.lockfile ?? null,
    tool: args.tool ?? null,
    version: args.version ?? null,
    state: requireEnum(args, 'state', SCANNER_STATES),
    exitCode: Number.parseInt(args['exit-code'] ?? '0', 10) || 0,
    message: readMessage(args['message-file']),
    output: args.output ?? null,
  };

  writeJsonFile(statePath('raw', `audit-${String(index).padStart(3, '0')}.meta.json`), meta);
  return 0;
}

/** Re-reads the per-project audit descriptors to summarise the whole scanner. */
function collectAuditProjects() {
  const rawDir = statePath('raw');
  let files = [];
  try {
    files = fs.readdirSync(rawDir).filter((name) => /^audit-\d+\.meta\.json$/.test(name)).sort();
  } catch {
    return [];
  }
  return files
    .map((name) => {
      try {
        return readJsonFile(path.join(rawDir, name));
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .map((meta) => ({
      dir: meta.dir,
      packageManager: meta.packageManager,
      tool: meta.version ? `${meta.tool} ${meta.version}` : meta.tool,
      state: meta.state,
      message: meta.message,
    }));
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new UserError(`--${name} is required.`);
  }
  return value;
}

function requireEnum(args, name, allowed) {
  const value = requireArg(args, name);
  if (!allowed.includes(value)) {
    throw new UserError(`--${name} must be one of: ${allowed.join(', ')}.`);
  }
  return value;
}

/** Tool output can contain anything, so it is read from a file and truncated. */
function readMessage(file) {
  if (!file) return null;
  try {
    const text = fs.readFileSync(file, 'utf8').trim();
    if (text.length === 0) return null;
    const lines = text.split('\n').slice(-12).join(' | ');
    return lines.length > 1200 ? `${lines.slice(0, 1199)}…` : lines;
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------------
// aggregate
// --------------------------------------------------------------------------

function commandAggregate() {
  const config = readJsonFile(statePath('config.json'));
  const detected = readJsonFile(statePath('detect.json'));
  const ignores = readJsonFile(statePath('ignores.json'));
  const tools = readToolVersions();

  const report = buildReport({
    config,
    detect: detected,
    ignores,
    stateDir: stateDir(),
    today: todayIso(),
    tools,
  });

  const reportFile = path.join(config.reportDir, 'report.json');
  report.config.reportPath = path.join(config.reportDirRelative, 'report.json');
  writeJsonFile(reportFile, report);

  const summaryMarkdown = renderMarkdown(report);
  fs.writeFileSync(path.join(config.reportDir, 'summary.md'), summaryMarkdown, 'utf8');
  copyRawOutputs(statePath('raw'), path.join(config.reportDir, 'raw'));

  const annotations = renderAnnotations(report);
  if (annotations.length > 0) console.log(annotations);
  console.log(renderConsole(report));
  appendGithubText(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown);

  const outputFile = process.env.GITHUB_OUTPUT;
  appendGithubKeyValue(outputFile, 'result', report.result === 'pass' ? 'pass' : 'fail');
  appendGithubKeyValue(outputFile, 'status', report.result);
  appendGithubKeyValue(outputFile, 'findings', String(report.summary.actionable));
  appendGithubKeyValue(outputFile, 'ignored-findings', String(report.summary.ignored));
  appendGithubKeyValue(outputFile, 'report', report.config.reportPath);

  writeJsonFile(statePath('result.json'), {
    result: report.result,
    actionable: report.summary.actionable,
    ignored: report.summary.ignored,
    errors: report.summary.errors,
    reason: report.exitReason,
    resultWord: resultWord(report.result),
  });

  return 0;
}

function readToolVersions() {
  try {
    return readJsonFile(statePath('tools.json'));
  } catch {
    return {};
  }
}

/**
 * Copies raw scanner output next to report.json so a consumer can upload one
 * directory as an artifact for triage.
 */
function copyRawOutputs(sourceDir, targetDir) {
  let entries;
  try {
    entries = fs.readdirSync(sourceDir, { withFileTypes: true });
  } catch {
    return;
  }
  fs.mkdirSync(targetDir, { recursive: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    fs.copyFileSync(path.join(sourceDir, entry.name), path.join(targetDir, entry.name));
  }
}

// --------------------------------------------------------------------------

const COMMANDS = {
  preflight: commandPreflight,
  'audit-plan': commandAuditPlan,
  'tool-manifest': commandToolManifest,
  'record-status': commandRecordStatus,
  'record-audit': commandRecordAudit,
  aggregate: commandAggregate,
};

function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  const handler = COMMANDS[command];

  if (!handler) {
    process.stderr.write(
      `Usage: cli.mjs <${Object.keys(COMMANDS).join('|')}> [options]\n`,
    );
    return 2;
  }

  try {
    return handler(args);
  } catch (error) {
    if (error instanceof UserError) {
      process.stderr.write(`\nWeb Security: ${error.message}\n`);
      for (const detail of error.details ?? []) {
        process.stderr.write(`  - ${detail}\n`);
      }
      process.stderr.write('\n');
      return 1;
    }
    process.stderr.write(`\nWeb Security: internal error in "${command}": ${error.stack ?? error.message}\n`);
    return 1;
  }
}

process.exitCode = main();
