#!/usr/bin/env bash
#
# Builds a deliberately insecure repository used by the end-to-end workflow.
# Each planted problem targets one scanner, so a scanner that silently stops
# producing findings makes the "expected to fail" job pass and the assertion
# step catch it.
#
# The fixture is generated rather than committed, because a committed fixture
# containing a credential-shaped string and a vulnerable lockfile would be
# reported by this repository's own self-scan.
set -Eeuo pipefail

target="${1:-.ci-fixture}"

rm -rf -- "$target"
mkdir -p -- "$target/src" "$target/frontend" "$target/deploy"
cd -- "$target"

# --- Trivy: Dockerfile misconfiguration ------------------------------------
# Runs as root (AVD-DS-0002) and installs from an unpinned `latest` base.
cat > Dockerfile <<'DOCKERFILE'
FROM node:latest
USER root
COPY . /app
RUN chmod 777 /app
CMD ["node", "/app/src/insecure.js"]
DOCKERFILE

# --- Trivy: Kubernetes misconfiguration ------------------------------------
cat > deploy/pod.yaml <<'MANIFEST'
apiVersion: v1
kind: Pod
metadata:
  name: fixture
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: app
      image: node:latest
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
MANIFEST

# --- Semgrep: code injection, command injection, traversal, XSS, weak crypto
# Written as a real Express application on purpose. Semgrep's rules are
# framework-aware and match a request value flowing into a sink, so an abstract
# `eval(someArgument)` in a bare function matches nothing and would make this
# fixture silently stop testing the SAST scanner.
cat > src/insecure.js <<'SOURCE'
const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();

app.get('/run', (req, res) => {
  exec('ls ' + req.query.dir, (error, stdout) => res.send(stdout));
});

app.get('/eval', (req, res) => {
  res.send(eval(req.query.expr));
});

app.get('/file', (req, res) => {
  res.sendFile(req.query.name);
});

app.get('/hash', (req, res) => {
  res.send(crypto.createHash('md5').update(req.query.value).digest('hex'));
});

app.get('/greet', (req, res) => {
  res.send('<h1>' + req.query.name + '</h1>');
});

app.get('/token', (req, res) => {
  res.send(jwt.sign({ user: req.query.user }, 'hardcoded-jwt-signing-value'));
});

module.exports = app;
SOURCE

# --- Gitleaks: a credential-shaped string ----------------------------------
# Assembled from two halves so that this script does not itself contain a
# contiguous token, and named to avoid the keyword patterns that Gitleaks'
# generic rules look for. The value is syntactically valid but has never been
# a real credential.
fake_head='ghp'
fake_tail='aB3dEfGhIjKlMnOpQrStUvWxYz0123456789'
printf 'exports.githubToken = "%s_%s";\n' "$fake_head" "$fake_tail" > src/leaked.js

# --- Dependency audit + Trivy: a known-vulnerable dependency ---------------
# minimist 1.2.0 has a critical prototype-pollution advisory
# (CVE-2021-44906 / GHSA-xvch-5gv4-984h) reported by both npm audit and Trivy,
# which also exercises cross-scanner deduplication.
cat > frontend/package.json <<'PACKAGE'
{
  "name": "fixture-frontend",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "minimist": "1.2.0"
  }
}
PACKAGE

(
  cd frontend
  npm install --package-lock-only --no-audit --no-fund --ignore-scripts --silent
)

# --- Ignore files used by the assertions -----------------------------------
cat > no-ignores.yml <<'IGNORES'
version: 1
ignores: []
IGNORES

# An entry with no justification: the run must be rejected before scanning.
cat > unjustified-ignores.yml <<'IGNORES'
version: 1
ignores:
  - id: "CVE-2021-44906"
    scanner: dependency
IGNORES

echo "fixture built in $(pwd)"
