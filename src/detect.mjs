/**
 * Repository discovery.
 *
 * Answers three questions before anything is scanned:
 *   1. Which directories are independent JavaScript package trees, and which
 *      package manager owns each one (from lockfiles, never from guessing)?
 *   2. Which infrastructure/configuration files exist, so the log can say what
 *      Trivy is going to look at?
 *   3. Which scanner-native suppression files exist, because those bypass this
 *      Action's "no ignore without justification" policy and must be surfaced.
 *
 * The walk is filesystem-only: no project code is executed and no lockfile is
 * installed. Symlinked directories are never followed, which avoids both
 * traversal loops and a crafted symlink pulling the scan outside the workspace.
 */

import fs from 'node:fs';
import path from 'node:path';

import { UserError, fileExists, toPosix } from './util.mjs';

/** Generated, vendored or cache directories that only produce noise. */
export const EXCLUDED_DIRS = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'bower_components',
  'vendor',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.astro',
  '.angular',
  '.output',
  '.vercel',
  '.netlify',
  '.turbo',
  '.nx',
  '.cache',
  '.parcel-cache',
  '.yarn',
  '.pnpm-store',
  '.venv',
  'venv',
  '__pycache__',
  '.terraform',
  '.gradle',
  'target',
  'tmp',
  '.tmp',
  '.idea',
  '.vscode',
]);

/**
 * Lockfile precedence. A repository that contains several lockfiles in one
 * directory is usually mid-migration; the audit follows this order and the
 * ambiguity is reported rather than hidden.
 */
const LOCKFILES = [
  { file: 'pnpm-lock.yaml', packageManager: 'pnpm' },
  { file: 'yarn.lock', packageManager: 'yarn' },
  { file: 'package-lock.json', packageManager: 'npm' },
  { file: 'npm-shrinkwrap.json', packageManager: 'npm' },
];

/**
 * Suppression mechanisms belonging to the scanners themselves. They allow a
 * finding to be silenced with no reason and no expiry, which is exactly what
 * this Action exists to prevent, so their presence is always reported.
 */
const NATIVE_SUPPRESSION_FILES = new Set([
  '.trivyignore',
  '.trivyignore.yaml',
  '.trivyignore.yml',
  'trivy.yaml',
  'trivy.yml',
  'trivy-secret.yaml',
  '.semgrepignore',
  '.gitleaksignore',
  '.gitleaks.toml',
]);

const COMPOSE_PATTERN = /^(?:docker-)?compose(?:\.[\w.-]+)?\.ya?ml$/i;
const TERRAFORM_PATTERN = /\.(?:tf|tfvars|tf\.json)$/i;
const YAML_PATTERN = /\.ya?ml$/i;
const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_PROJECTS = 50;
/** Upper bound on YAML files sniffed for Kubernetes manifests, for runtime. */
const MAX_YAML_SNIFF = 400;
const YAML_SNIFF_BYTES = 4096;

/**
 * Walks `rootDir` and returns everything the scanners need to know.
 *
 * @param {string} rootDir absolute path to scan
 * @param {object} [options]
 * @param {boolean} [options.monorepo] detect nested package trees recursively
 * @param {string} [options.workspace] repository root, for display paths
 */
export function discover(rootDir, options = {}) {
  const {
    monorepo = true,
    maxDepth = DEFAULT_MAX_DEPTH,
    maxProjects = DEFAULT_MAX_PROJECTS,
    workspace = rootDir,
  } = options;

  const context = {
    monorepo,
    maxDepth,
    root: rootDir,
    projects: [],
    packagesWithoutLockfile: [],
    nativeSuppressions: [],
    warnings: [],
    depthLimited: [],
    infrastructure: {
      dockerfiles: [],
      compose: [],
      terraform: [],
      kubernetes: [],
      helm: [],
      workflows: [],
    },
    yamlSniffed: 0,
  };

  walk(rootDir, '', 0, context);

  // Deterministic ordering keeps logs and report.json diffable between runs.
  context.projects.sort((left, right) => left.dir.localeCompare(right.dir));
  context.packagesWithoutLockfile.sort();
  context.nativeSuppressions.sort();
  for (const key of Object.keys(context.infrastructure)) {
    context.infrastructure[key].sort();
  }

  // A package.json inside a directory that already has a lockfile is a
  // workspace member, not an un-audited project; do not nag about it.
  context.packagesWithoutLockfile = context.packagesWithoutLockfile.filter(
    (candidate) => !context.projects.some((project) => isInside(candidate, project.dir)),
  );

  if (context.projects.length > maxProjects) {
    throw new UserError(
      `Detected ${context.projects.length} package trees, which is above the safety limit of ${maxProjects}.`,
      {
        details: [
          'Auditing this many projects in a single pull-request job is usually unintended.',
          'Set "monorepo: false" to audit only the root project, or set "path" to the sub-project you want to scan.',
        ],
      },
    );
  }

  for (const project of context.projects) {
    if (project.lockfiles.length > 1) {
      context.warnings.push(
        `${project.dir === '.' ? 'repository root' : project.dir} contains multiple lockfiles (${project.lockfiles.join(', ')}); auditing with ${project.packageManager}.`,
      );
    }
  }

  if (context.depthLimited.length > 0) {
    const examples = context.depthLimited.slice(0, 3).map((dir) => `"${dir}"`).join(', ');
    const more = context.depthLimited.length > 3 ? `, and ${context.depthLimited.length - 3} more` : '';
    const count = context.depthLimited.length;
    context.warnings.push(
      `Reached the directory depth limit of ${maxDepth} in ${count} ${count === 1 ? 'directory' : 'directories'}; package trees nested below them are not audited (${examples}${more}).`,
    );
  }

  return {
    root: toPosix(path.relative(workspace, rootDir)) || '.',
    projects: context.projects,
    packagesWithoutLockfile: context.packagesWithoutLockfile,
    infrastructure: context.infrastructure,
    nativeSuppressions: context.nativeSuppressions,
    warnings: context.warnings,
  };
}

function walk(dir, relativeDir, depth, context) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    context.warnings.push(`Could not read directory "${relativeDir || '.'}": ${error.message}`);
    return;
  }

  const fileNames = new Set();
  const directories = [];

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      directories.push(entry.name);
    } else if (entry.isFile()) {
      fileNames.add(entry.name);
    }
  }

  const displayDir = relativeDir === '' ? '.' : relativeDir;
  const isRoot = depth === 0;

  if (isRoot || context.monorepo) {
    collectProject(dir, displayDir, fileNames, context);
  }
  classifyFiles(dir, displayDir, fileNames, context);

  if (depth >= context.maxDepth) {
    // Recorded rather than warned about per directory: a deeply nested tree
    // produces dozens of these, and a summary buried in identical warnings is
    // a summary nobody reads. They are collapsed into one warning at the end.
    if (directories.some((name) => !EXCLUDED_DIRS.has(name))) {
      context.depthLimited.push(displayDir);
    }
    return;
  }

  for (const name of directories.sort()) {
    if (EXCLUDED_DIRS.has(name)) continue;
    walk(path.join(dir, name), relativeDir === '' ? name : `${relativeDir}/${name}`, depth + 1, context);
  }
}

function collectProject(dir, displayDir, fileNames, context) {
  const found = LOCKFILES.filter((candidate) => fileNames.has(candidate.file));
  const hasPackageJson = fileNames.has('package.json');

  if (found.length === 0) {
    if (hasPackageJson) context.packagesWithoutLockfile.push(displayDir);
    return;
  }

  const primary = found[0];
  const project = {
    dir: displayDir,
    packageManager: primary.packageManager,
    lockfile: primary.file,
    lockfiles: found.map((candidate) => candidate.file),
    hasPackageJson,
    packageManagerField: readPackageManagerField(path.join(dir, 'package.json')),
    yarnMajor: null,
  };

  if (primary.packageManager === 'yarn') {
    project.yarnMajor = detectYarnMajor(dir, project.packageManagerField);
  }

  context.projects.push(project);
}

/** Reads the `packageManager` field without executing anything. */
function readPackageManagerField(packageJsonPath) {
  if (!fileExists(packageJsonPath)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const value = parsed?.packageManager;
    return typeof value === 'string' && /^[a-z]+@[\w.+-]+$/i.test(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Works out whether a `yarn.lock` belongs to Yarn Classic (1.x) or a modern
 * Berry release, because the two have completely different audit commands.
 *
 * Signals, in order of reliability:
 *   1. `packageManager: "yarn@4.x"` in package.json
 *   2. a `.yarnrc.yml` file (Berry only; Classic uses `.yarnrc`)
 *   3. the `__metadata:` block that Berry writes into yarn.lock
 *
 * Returns `null` when nothing indicates Berry, which is treated as Classic.
 */
export function detectYarnMajor(dir, packageManagerField) {
  const fieldMatch = /^yarn@v?(\d+)/i.exec(packageManagerField ?? '');
  if (fieldMatch) return Number(fieldMatch[1]);

  if (fileExists(path.join(dir, '.yarnrc.yml'))) return 2;

  const lockfile = path.join(dir, 'yarn.lock');
  try {
    const handle = fs.openSync(lockfile, 'r');
    try {
      const buffer = Buffer.alloc(2048);
      const bytes = fs.readSync(handle, buffer, 0, buffer.length, 0);
      const head = buffer.subarray(0, bytes).toString('utf8');
      if (/^__metadata:/m.test(head)) return 2;
      if (/yarn lockfile v1/.test(head)) return 1;
    } finally {
      fs.closeSync(handle);
    }
  } catch {
    /* Unreadable lockfile: fall through to the Classic default. */
  }

  return null;
}

function classifyFiles(dir, displayDir, fileNames, context) {
  const infrastructure = context.infrastructure;
  const isWorkflowDir = displayDir === '.github/workflows';

  for (const name of [...fileNames].sort()) {
    const relative = displayDir === '.' ? name : `${displayDir}/${name}`;

    if (NATIVE_SUPPRESSION_FILES.has(name)) {
      context.nativeSuppressions.push(relative);
    }

    if (name === 'Dockerfile' || name === 'Containerfile' || /^Dockerfile[.\w-]*$/.test(name) || /\.[Dd]ockerfile$/.test(name)) {
      infrastructure.dockerfiles.push(relative);
      continue;
    }
    if (COMPOSE_PATTERN.test(name)) {
      infrastructure.compose.push(relative);
      continue;
    }
    if (TERRAFORM_PATTERN.test(name)) {
      infrastructure.terraform.push(relative);
      continue;
    }
    if (name === 'Chart.yaml') {
      infrastructure.helm.push(relative);
      continue;
    }
    if (isWorkflowDir && YAML_PATTERN.test(name)) {
      infrastructure.workflows.push(relative);
      continue;
    }
    if (YAML_PATTERN.test(name) && looksLikeKubernetesManifest(path.join(dir, name), context)) {
      infrastructure.kubernetes.push(relative);
    }
  }
}

/** Cheap content sniff: a Kubernetes manifest declares apiVersion and kind. */
function looksLikeKubernetesManifest(file, context) {
  if (context.yamlSniffed >= MAX_YAML_SNIFF) return false;
  context.yamlSniffed += 1;
  try {
    const handle = fs.openSync(file, 'r');
    try {
      const buffer = Buffer.alloc(YAML_SNIFF_BYTES);
      const bytes = fs.readSync(handle, buffer, 0, buffer.length, 0);
      const head = buffer.subarray(0, bytes).toString('utf8');
      return /^apiVersion:\s*\S+/m.test(head) && /^kind:\s*\S+/m.test(head);
    } finally {
      fs.closeSync(handle);
    }
  } catch {
    return false;
  }
}

function isInside(candidate, parent) {
  if (parent === '.') return candidate !== '.';
  return candidate === parent || candidate.startsWith(`${parent}/`);
}

/** Renders the "Detected projects" table shown in the job log. */
export function formatProjectTable(projects) {
  if (projects.length === 0) return '  (no Node.js lockfiles detected)';
  const width = Math.max(...projects.map((project) => project.dir.length));
  return projects
    .map((project) => {
      const label = project.packageManager === 'yarn'
        ? `yarn${project.yarnMajor && project.yarnMajor >= 2 ? ' (berry)' : ' (classic)'}`
        : project.packageManager;
      return `  ${project.dir.padEnd(width)}  ${label}  [${project.lockfile}]`;
    })
    .join('\n');
}
