/** Package-manager and repository detection. */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { discover, detectYarnMajor } from '../src/detect.mjs';
import { UserError } from '../src/util.mjs';
import {
  K8S_MANIFEST,
  NPM_LOCK,
  PNPM_LOCK,
  YARN_BERRY_LOCK,
  YARN_CLASSIC_LOCK,
  createTree,
  packageJson,
} from './helpers/fixtures.mjs';

test('detects a plain npm project from package-lock.json', () => {
  const root = createTree({ 'package.json': packageJson(), 'package-lock.json': NPM_LOCK });
  const result = discover(root);

  assert.equal(result.projects.length, 1);
  assert.equal(result.projects[0].dir, '.');
  assert.equal(result.projects[0].packageManager, 'npm');
  assert.equal(result.projects[0].lockfile, 'package-lock.json');
});

test('detects npm from npm-shrinkwrap.json', () => {
  const root = createTree({ 'package.json': packageJson(), 'npm-shrinkwrap.json': NPM_LOCK });
  const result = discover(root);

  assert.equal(result.projects[0].packageManager, 'npm');
  assert.equal(result.projects[0].lockfile, 'npm-shrinkwrap.json');
});

test('detects Yarn Classic from the v1 lockfile header', () => {
  const root = createTree({ 'package.json': packageJson(), 'yarn.lock': YARN_CLASSIC_LOCK });
  const result = discover(root);

  assert.equal(result.projects[0].packageManager, 'yarn');
  assert.equal(result.projects[0].yarnMajor, 1);
});

test('detects Yarn Berry from the __metadata block', () => {
  const root = createTree({ 'package.json': packageJson(), 'yarn.lock': YARN_BERRY_LOCK });
  const result = discover(root);

  assert.equal(result.projects[0].packageManager, 'yarn');
  assert.equal(result.projects[0].yarnMajor, 2);
});

test('prefers the packageManager field over lockfile heuristics', () => {
  const root = createTree({
    'package.json': packageJson({ packageManager: 'yarn@4.1.0' }),
    'yarn.lock': YARN_CLASSIC_LOCK,
  });
  const result = discover(root);

  assert.equal(result.projects[0].yarnMajor, 4);
  assert.equal(result.projects[0].packageManagerField, 'yarn@4.1.0');
});

test('detects Yarn Berry from .yarnrc.yml even with a Classic-looking lockfile', () => {
  const root = createTree({
    'package.json': packageJson(),
    'yarn.lock': YARN_CLASSIC_LOCK,
    '.yarnrc.yml': 'nodeLinker: node-modules\n',
  });
  assert.equal(detectYarnMajor(root, null), 2);
});

test('detects pnpm and reports when several lockfiles compete', () => {
  const root = createTree({
    'package.json': packageJson(),
    'pnpm-lock.yaml': PNPM_LOCK,
    'yarn.lock': YARN_CLASSIC_LOCK,
    'package-lock.json': NPM_LOCK,
  });
  const result = discover(root);

  assert.equal(result.projects.length, 1);
  assert.equal(result.projects[0].packageManager, 'pnpm');
  assert.deepEqual(result.projects[0].lockfiles, ['pnpm-lock.yaml', 'yarn.lock', 'package-lock.json']);
  assert.match(result.warnings.join('\n'), /multiple lockfiles/);
});

test('reports a package.json with no lockfile instead of guessing', () => {
  const root = createTree({ 'package.json': packageJson() });
  const result = discover(root);

  assert.deepEqual(result.projects, []);
  assert.deepEqual(result.packagesWithoutLockfile, ['.']);
});

test('finds nested monorepo projects with their own package managers', () => {
  const root = createTree({
    frontend: { 'package.json': packageJson(), 'package-lock.json': NPM_LOCK },
    backend: { 'package.json': packageJson(), 'package-lock.json': NPM_LOCK },
    docs: { 'package.json': packageJson(), 'yarn.lock': YARN_CLASSIC_LOCK },
  });
  const result = discover(root);

  assert.deepEqual(
    result.projects.map((project) => [project.dir, project.packageManager]),
    [
      ['backend', 'npm'],
      ['docs', 'yarn'],
      ['frontend', 'npm'],
    ],
  );
});

test('monorepo: false audits only the root project', () => {
  const root = createTree({
    'package.json': packageJson(),
    'package-lock.json': NPM_LOCK,
    frontend: { 'package.json': packageJson(), 'yarn.lock': YARN_CLASSIC_LOCK },
  });
  const result = discover(root, { monorepo: false });

  assert.equal(result.projects.length, 1);
  assert.equal(result.projects[0].dir, '.');
});

test('never treats generated or vendored directories as projects', () => {
  const root = createTree({
    'package.json': packageJson(),
    'package-lock.json': NPM_LOCK,
    node_modules: { 'some-dep': { 'package.json': packageJson(), 'package-lock.json': NPM_LOCK } },
    dist: { 'package.json': packageJson(), 'package-lock.json': NPM_LOCK },
    '.next': { cache: { 'package-lock.json': NPM_LOCK } },
    coverage: { 'package-lock.json': NPM_LOCK },
  });
  const result = discover(root);

  assert.deepEqual(result.projects.map((project) => project.dir), ['.']);
});

test('workspace members without their own lockfile are not flagged', () => {
  const root = createTree({
    'package.json': packageJson({ workspaces: ['packages/*'] }),
    'package-lock.json': NPM_LOCK,
    packages: {
      ui: { 'package.json': packageJson() },
      api: { 'package.json': packageJson() },
    },
  });
  const result = discover(root);

  assert.deepEqual(result.projects.map((project) => project.dir), ['.']);
  assert.deepEqual(result.packagesWithoutLockfile, []);
});

test('the same package tree is never audited twice', () => {
  const root = createTree({
    'package.json': packageJson(),
    'package-lock.json': NPM_LOCK,
    'npm-shrinkwrap.json': NPM_LOCK,
  });
  const result = discover(root);

  assert.equal(result.projects.length, 1);
});

test('classifies infrastructure and configuration files', () => {
  const root = createTree({
    Dockerfile: 'FROM node:20\nUSER root\n',
    'api.Dockerfile': 'FROM node:20\n',
    'docker-compose.yml': 'services: {}\n',
    'main.tf': 'resource "aws_s3_bucket" "b" {}\n',
    k8s: { 'deployment.yaml': K8S_MANIFEST, 'notes.yaml': 'just: data\n' },
    chart: { 'Chart.yaml': 'name: web\n' },
    '.github': { workflows: { 'ci.yml': 'on: push\n' } },
  });
  const result = discover(root);

  assert.deepEqual(result.infrastructure.dockerfiles, ['Dockerfile', 'api.Dockerfile']);
  assert.deepEqual(result.infrastructure.compose, ['docker-compose.yml']);
  assert.deepEqual(result.infrastructure.terraform, ['main.tf']);
  assert.deepEqual(result.infrastructure.kubernetes, ['k8s/deployment.yaml']);
  assert.deepEqual(result.infrastructure.helm, ['chart/Chart.yaml']);
  assert.deepEqual(result.infrastructure.workflows, ['.github/workflows/ci.yml']);
});

test('surfaces scanner-native suppression files', () => {
  const root = createTree({
    '.trivyignore': 'CVE-2020-0001\n',
    '.semgrepignore': 'src/\n',
    '.gitleaksignore': 'abc:file:rule:1\n',
    'trivy.yaml': 'severity:\n  - LOW\n',
  });
  const result = discover(root);

  assert.deepEqual(result.nativeSuppressions.sort(), [
    '.gitleaksignore',
    '.semgrepignore',
    '.trivyignore',
    'trivy.yaml',
  ]);
});

test('refuses to audit an implausible number of package trees', () => {
  const tree = {};
  for (let index = 0; index < 4; index += 1) {
    tree[`project-${index}`] = { 'package.json': packageJson(), 'package-lock.json': NPM_LOCK };
  }
  const root = createTree(tree);

  assert.throws(() => discover(root, { maxProjects: 3 }), (error) => {
    assert.ok(error instanceof UserError);
    assert.match(error.message, /above the safety limit/);
    return true;
  });
});

test('does not follow symlinked directories', (t) => {
  const root = createTree({
    'package.json': packageJson(),
    'package-lock.json': NPM_LOCK,
    real: { nested: { 'package.json': packageJson(), 'package-lock.json': NPM_LOCK } },
  });

  try {
    fs.symlinkSync(`${root}/real`, `${root}/link`, 'dir');
  } catch {
    t.skip('symlinks are not supported in this environment');
    return;
  }

  const result = discover(root);
  assert.deepEqual(result.projects.map((project) => project.dir), ['.', 'real/nested']);
});

test('collapses depth-limit notices into a single warning', () => {
  // A deep tree (a vendored virtualenv, a build cache) hits the limit in many
  // directories at once. One warning per directory would bury everything else
  // in the summary.
  const branch = { b: { c: { d: { nested: { 'package.json': packageJson() } } } } };
  const root = createTree({
    'package.json': packageJson(),
    'package-lock.json': NPM_LOCK,
    one: branch,
    two: branch,
    three: branch,
    four: branch,
  });

  const result = discover(root, { maxDepth: 4 });
  const depthWarnings = result.warnings.filter((warning) => /depth limit/.test(warning));

  assert.equal(depthWarnings.length, 1);
  assert.match(depthWarnings[0], /in 4 directories/);
  assert.match(depthWarnings[0], /and 1 more/);
});
