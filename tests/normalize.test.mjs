/**
 * Scanner output normalisation.
 *
 * The JSON shapes below are trimmed copies of real scanner output, including
 * the four incompatible audit formats a single monorepo can produce.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { normalizeTrivy } from '../src/normalize/trivy.mjs';
import { normalizeSemgrep } from '../src/normalize/semgrep.mjs';
import { normalizeGitleaks } from '../src/normalize/gitleaks.mjs';
import { normalizeDependencyAudit } from '../src/normalize/dependency.mjs';

const NPM_META = { scanner: 'npm', project: 'frontend', lockfile: 'frontend/package-lock.json' };

// --------------------------------------------------------------------------
// Trivy
// --------------------------------------------------------------------------

test('normalises Trivy vulnerabilities, misconfigurations and secrets', () => {
  const { findings } = normalizeTrivy({
    SchemaVersion: 2,
    Results: [
      {
        Target: 'frontend/package-lock.json',
        Class: 'lang-pkgs',
        Type: 'npm',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2026-1234',
            PkgName: 'lodash',
            InstalledVersion: '4.17.20',
            FixedVersion: '4.17.21',
            Severity: 'HIGH',
            Title: 'Prototype pollution in lodash',
            PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2026-1234',
            References: ['https://github.com/advisories/GHSA-abcd-1234-5678'],
          },
        ],
      },
      {
        Target: 'Dockerfile',
        Class: 'config',
        Type: 'dockerfile',
        Misconfigurations: [
          {
            ID: 'DS002',
            AVDID: 'AVD-DS-0002',
            Title: 'Image user should not be root',
            Severity: 'HIGH',
            Status: 'FAIL',
            CauseMetadata: { StartLine: 3 },
            PrimaryURL: 'https://avd.aquasec.com/misconfig/ds002',
          },
          { ID: 'DS026', Title: 'No HEALTHCHECK', Severity: 'LOW', Status: 'PASS' },
        ],
      },
      {
        Target: 'src/config.ts',
        Class: 'secret',
        Secrets: [
          {
            RuleID: 'github-pat',
            Category: 'GitHub',
            Severity: 'CRITICAL',
            Title: 'GitHub Personal Access Token',
            StartLine: 12,
            Match: 'const token = "****"',
            Code: { Lines: [{ Content: 'const token = "****"' }] },
          },
        ],
      },
    ],
  });

  assert.equal(findings.length, 3);

  const [vulnerability, misconfiguration, secret] = findings;

  assert.equal(vulnerability.id, 'CVE-2026-1234');
  assert.deepEqual(vulnerability.aliases, ['GHSA-abcd-1234-5678']);
  assert.equal(vulnerability.category, 'dependency');
  assert.equal(vulnerability.project, 'frontend');
  assert.equal(vulnerability.fixedVersion, '4.17.21');

  assert.equal(misconfiguration.id, 'AVD-DS-0002');
  assert.equal(misconfiguration.category, 'misconfig');
  assert.equal(misconfiguration.line, 3);

  assert.equal(secret.id, 'github-pat');
  assert.equal(secret.category, 'secret');
  // The candidate credential must never be copied into the report.
  assert.equal(JSON.stringify(secret).includes('const token'), false);
});

test('does not adopt unrelated CVEs listed in a reference page', () => {
  // Trivy's references often include a vendor security release that lists many
  // unrelated CVEs. Harvesting those as aliases would let an ignore entry
  // written for one vulnerability suppress a different one.
  const { findings } = normalizeTrivy({
    Results: [
      {
        Target: 'frontend/package-lock.json',
        Class: 'lang-pkgs',
        Type: 'npm',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2021-44906',
            PkgName: 'minimist',
            Severity: 'CRITICAL',
            PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2021-44906',
            References: [
              'https://github.com/advisories/GHSA-xvch-5gv4-984h',
              'https://nodejs.org/en/blog/vulnerability/november-2022-security-releases/',
              'https://security.example.com/notes?ids=CVE-2022-3517,CVE-2022-43548',
            ],
          },
        ],
      },
    ],
  });

  // Only the GitHub advisory for this vulnerability, which is what lets the
  // npm audit copy of it merge in. (The id itself is not repeated as an alias.)
  assert.deepEqual(findings[0].aliases, ['GHSA-xvch-5gv4-984h']);
});

test('ignores passing Trivy misconfiguration checks', () => {
  const { findings } = normalizeTrivy({
    Results: [
      {
        Target: 'Dockerfile',
        Class: 'config',
        Misconfigurations: [{ ID: 'DS026', Severity: 'LOW', Status: 'PASS' }],
      },
    ],
  });
  assert.deepEqual(findings, []);
});

test('reports unparsable Trivy output rather than pretending it was clean', () => {
  const { findings, warnings } = normalizeTrivy(null);
  assert.deepEqual(findings, []);
  assert.match(warnings.join(' '), /no parsable JSON/);
});

// --------------------------------------------------------------------------
// Semgrep
// --------------------------------------------------------------------------

test('normalises Semgrep results and maps its severities', () => {
  const { findings, warnings } = normalizeSemgrep({
    results: [
      {
        check_id: 'javascript.lang.security.detect-eval-with-expression.detect-eval-with-expression',
        path: './src/render.js',
        start: { line: 42 },
        extra: {
          severity: 'ERROR',
          message: 'Detected eval with a non-literal   expression',
          fingerprint: 'abc123',
          metadata: { cwe: ['CWE-95'], shortlink: 'https://sg.run/abc' },
        },
      },
      {
        check_id: 'javascript.express.security.audit.express-cookie-settings',
        path: 'src/app.js',
        start: { line: 7 },
        extra: { severity: 'WARNING', message: 'Cookie without httpOnly', metadata: {} },
      },
    ],
    errors: [{ level: 'warn', message: 'Syntax error in vendor/legacy.js' }],
  });

  assert.equal(findings[0].severity, 'HIGH');
  assert.equal(findings[0].category, 'sast');
  assert.equal(findings[0].path, 'src/render.js');
  assert.equal(findings[0].line, 42);
  assert.equal(findings[0].title, 'Detected eval with a non-literal expression');
  assert.deepEqual(findings[0].aliases, ['abc123']);
  assert.equal(findings[1].severity, 'MEDIUM');
  assert.match(warnings.join(' '), /1 file-level problem/);
});

test('treats a per-file Semgrep problem as a warning, not a failure', () => {
  const { findings, warnings, error } = normalizeSemgrep({
    results: [],
    errors: [
      {
        level: 'error',
        type: 'SyntaxError',
        message: 'Syntax error',
        path: 'src/generated/bundle.js',
      },
    ],
  });

  assert.deepEqual(findings, []);
  assert.equal(error ?? null, null, 'one unparsable file is not a scanner failure');
  assert.match(warnings.join(' '), /1 file-level problem/);
});

test('an engine failure is an error even though Semgrep exits successfully', () => {
  // semgrep-core running out of memory is reported like this: exit code 0, an
  // empty results array, and an error with no file attached. Reporting that as
  // a clean scan would be the worst kind of bug in a security tool.
  const { findings, error } = normalizeSemgrep({
    results: [],
    errors: [
      {
        code: 2,
        level: 'error',
        type: 'SemgrepError',
        message: 'Error while matching: semgrep-core exit code: 2',
      },
    ],
  });

  assert.deepEqual(findings, []);
  assert.match(error, /failed internally/);
});

// --------------------------------------------------------------------------
// Gitleaks
// --------------------------------------------------------------------------

test('normalises Gitleaks findings without copying the secret', () => {
  const { findings } = normalizeGitleaks([
    {
      RuleID: 'github-pat',
      Description: 'Uncovered a GitHub Personal Access Token',
      File: 'src/config.ts',
      StartLine: 3,
      // Deliberately not a realistic credential: this repository scans itself
      // in CI, and a plausible-looking literal here would be a finding.
      Secret: 'sentinel-must-not-be-copied',
      Match: 'token = sentinel-must-not-be-copied',
      Fingerprint: 'src/config.ts:github-pat:3',
    },
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'HIGH');
  assert.equal(findings[0].category, 'secret');
  assert.equal(findings[0].path, 'src/config.ts');
  assert.deepEqual(findings[0].aliases, ['src/config.ts:github-pat:3']);
  assert.equal(JSON.stringify(findings).includes('sentinel-must-not-be-copied'), false);
});

test('rewrites absolute Gitleaks paths relative to the scan root', () => {
  const { findings } = normalizeGitleaks(
    [{ RuleID: 'aws-access-token', File: '/home/runner/work/app/app/src/aws.ts', StartLine: 1 }],
    { scanRoot: '/home/runner/work/app/app' },
  );
  assert.equal(findings[0].path, 'src/aws.ts');
});

test('an empty Gitleaks report means no leaks', () => {
  assert.deepEqual(normalizeGitleaks([]).findings, []);
  assert.deepEqual(normalizeGitleaks(null).findings, []);
});

// --------------------------------------------------------------------------
// Dependency audits: the four output formats
// --------------------------------------------------------------------------

test('normalises npm 7+ audit output', () => {
  const text = JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {
      lodash: {
        name: 'lodash',
        severity: 'high',
        via: [
          {
            source: 1673,
            name: 'lodash',
            dependency: 'lodash',
            title: 'Prototype Pollution',
            url: 'https://github.com/advisories/GHSA-abcd-1234-5678',
            severity: 'high',
            range: '<4.17.21',
          },
        ],
        range: '<4.17.21',
        fixAvailable: { name: 'lodash', version: '4.17.21', isSemVerMajor: false },
      },
      // A package that is only vulnerable through another package: the string
      // entry must not become a second finding.
      'my-app': { name: 'my-app', severity: 'high', via: ['lodash'], fixAvailable: true },
    },
  });

  const { findings, error } = normalizeDependencyAudit(text, NPM_META);

  assert.equal(error, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'GHSA-abcd-1234-5678');
  assert.deepEqual(findings[0].aliases, ['NPM-1673']);
  assert.equal(findings[0].severity, 'HIGH');
  assert.equal(findings[0].package, 'lodash');
  assert.equal(findings[0].fixedVersion, '4.17.21');
  assert.equal(findings[0].vulnerableRange, '<4.17.21');
  assert.equal(findings[0].project, 'frontend');
  assert.equal(findings[0].path, 'frontend/package-lock.json');
});

test('normalises npm 6 / pnpm advisory output', () => {
  const text = JSON.stringify({
    advisories: {
      1673: {
        id: 1673,
        github_advisory_id: 'GHSA-abcd-1234-5678',
        cves: ['CVE-2026-1234'],
        title: 'Prototype Pollution',
        module_name: 'lodash',
        severity: 'high',
        vulnerable_versions: '<4.17.21',
        patched_versions: '>=4.17.21',
        url: 'https://npmjs.com/advisories/1673',
        findings: [{ version: '4.17.20', paths: ['lodash'] }],
      },
    },
    metadata: { vulnerabilities: { high: 1 } },
  });

  const { findings } = normalizeDependencyAudit(text, { ...NPM_META, scanner: 'pnpm' });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'GHSA-abcd-1234-5678');
  assert.ok(findings[0].aliases.includes('CVE-2026-1234'));
  assert.equal(findings[0].installedVersion, '4.17.20');
  assert.equal(findings[0].fixedVersion, '4.17.21');
  assert.equal(findings[0].scanner, 'pnpm');
});

test('normalises Yarn Classic newline-delimited output', () => {
  const text = [
    JSON.stringify({ type: 'info', data: 'auditing' }),
    JSON.stringify({
      type: 'auditAdvisory',
      data: {
        resolution: { id: 1673, path: 'lodash' },
        advisory: {
          id: 1673,
          github_advisory_id: 'GHSA-abcd-1234-5678',
          title: 'Prototype Pollution',
          module_name: 'lodash',
          severity: 'high',
          vulnerable_versions: '<4.17.21',
          patched_versions: '>=4.17.21',
          findings: [{ version: '4.17.20' }],
        },
      },
    }),
    JSON.stringify({ type: 'auditSummary', data: { vulnerabilities: { high: 1 } } }),
  ].join('\n');

  const { findings, error } = normalizeDependencyAudit(text, { ...NPM_META, scanner: 'yarn' });

  assert.equal(error, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'GHSA-abcd-1234-5678');
  assert.equal(findings[0].scanner, 'yarn');
});

test('normalises Yarn Berry value/children output', () => {
  const text = [
    JSON.stringify({
      value: 'lodash',
      children: {
        ID: 1673,
        Issue: 'Prototype Pollution',
        Severity: 'high',
        'Vulnerable Versions': '<4.17.21',
        'Tree Versions': ['4.17.20'],
        Dependents: ['app@workspace:.'],
      },
    }),
    JSON.stringify({
      value: 'minimist',
      children: {
        ID: 'GHSA-xxxx-yyyy-zzzz',
        Issue: 'Prototype Pollution',
        Severity: 'critical',
        'Tree Versions': ['1.2.0'],
      },
    }),
  ].join('\n');

  const { findings } = normalizeDependencyAudit(text, { ...NPM_META, scanner: 'yarn' });

  assert.equal(findings.length, 2);
  assert.equal(findings[0].id, 'NPM-1673');
  assert.equal(findings[0].installedVersion, '4.17.20');
  assert.equal(findings[1].id, 'GHSA-xxxx-yyyy-zzzz');
  assert.equal(findings[1].severity, 'CRITICAL');
});

test('a clean audit produces no findings and no error', () => {
  const { findings, error } = normalizeDependencyAudit(
    JSON.stringify({ auditReportVersion: 2, vulnerabilities: {}, metadata: {} }),
    NPM_META,
  );
  assert.deepEqual(findings, []);
  assert.equal(error, null);
});

test('surfaces an audit tool error instead of reporting zero findings', () => {
  const npmError = normalizeDependencyAudit(
    JSON.stringify({
      error: {
        code: 'ENOLOCK',
        summary: 'This command requires an existing lockfile.',
        detail: 'Try running npm install first.',
      },
    }),
    NPM_META,
  );
  assert.match(npmError.error, /ENOLOCK: This command requires an existing lockfile/);
  assert.deepEqual(npmError.findings, []);

  const yarnError = normalizeDependencyAudit(
    JSON.stringify({ type: 'error', data: 'Registry returned 503' }),
    { ...NPM_META, scanner: 'yarn' },
  );
  assert.match(yarnError.error, /Registry returned 503/);
});

test('treats unusable output as an error', () => {
  assert.match(normalizeDependencyAudit('', NPM_META).error, /produced no output/);
  assert.match(
    normalizeDependencyAudit('npm ERR! code ENOTFOUND\nnpm ERR! network', NPM_META).error,
    /neither JSON nor newline-delimited JSON/,
  );
});

test('deduplicates repeated advisories within one audit', () => {
  const advisory = {
    source: 1673,
    name: 'lodash',
    dependency: 'lodash',
    title: 'Prototype Pollution',
    url: 'https://github.com/advisories/GHSA-abcd-1234-5678',
    severity: 'high',
    range: '<4.17.21',
  };
  const text = JSON.stringify({
    vulnerabilities: {
      lodash: { name: 'lodash', severity: 'high', via: [advisory, advisory] },
    },
  });

  assert.equal(normalizeDependencyAudit(text, NPM_META).findings.length, 1);
});
