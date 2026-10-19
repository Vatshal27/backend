'use strict';
const { createHash } = require('node:crypto');

const SECRET_PATTERNS = [
  ['private-key', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, 'Private key material'],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b/, 'GitHub access token'],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, 'AWS access key identifier'],
  ['provider-token', /\b(?:xox[baprs]-[A-Za-z0-9-]{20,}|sk_live_[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{35})\b/, 'Provider credential'],
];
const ASSIGNMENT = /\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|aws_secret_access_key)\b["']?\s*[:=]\s*["']?([^\s"'`,;}{]{8,})/gi;
const PLACEHOLDER = /^(?:\$|<|\{|process\.env\b|os\.(?:environ|getenv)|your[_-]|example|changeme|placeholder|redacted|undefined|null|true$|false$|\*+$)/i;

function makeFinding({ check, rule, file, line = '', type, severity = 'HIGH', explanation, fix, metadata }) {
  return {
    id: `supp-${createHash('sha256').update(JSON.stringify([check, rule, file, line, metadata || null])).digest('hex').slice(0, 20)}`,
    source: 'supplementary', check, rule, type, severity, confidence: 'MEDIUM', verification: 'unverified',
    file, line: String(line), explanation, fix, fixExplanation: fix,
    attackType: 'other', attackPayloads: [], attackStory: [], attackScript: '',
    vulnerableCode: '[REDACTED]', fixedCode: '', ...(metadata ? { metadata } : {}),
  };
}

function scanSecrets(files) {
  const findings = [];
  for (const file of files) {
    file.content.split(/\r?\n/).forEach((text, index) => {
      const matches = SECRET_PATTERNS.filter(([, pattern]) => pattern.test(text));
      if (!matches.length) {
        ASSIGNMENT.lastIndex = 0;
        if ([...text.matchAll(ASSIGNMENT)].some(match => !PLACEHOLDER.test(match[1]))) {
          matches.push(['credential-assignment', null, 'Hardcoded credential candidate']);
        }
      }
      for (const [rule, , type] of matches) findings.push(makeFinding({
        check: 'secrets', rule, file: file.path, line: index + 1, type,
        explanation: 'A credential-shaped value is present in the supplied file. Pattern detection does not establish validity; no provider validation was performed.',
        fix: 'If genuine, revoke or rotate the credential, remove it from source and history, and load it through a secret manager.',
      }));
    });
  }
  return { findings, coverage: { check: 'secrets', status: 'tested', filesTested: files.length, reason: 'Offline credential patterns checked; values withheld. No guarantee that all secret formats are detected.' } };
}

function scanInfrastructure(files) {
  const findings = [];
  let filesTested = 0;
  for (const file of files) {
    const basename = file.path.replace(/\\/g, '/').split('/').pop();
    const docker = /^(?:Dockerfile(?:\..+)?|.+\.dockerfile)$/i.test(basename);
    const config = /\.(?:ya?ml|json|toml|ini|conf)$/i.test(basename) || /^(?:\.npmrc|\.env(?:\..+)?)$/i.test(basename);
    if (!docker && !config) continue;
    filesTested++;
    const lines = file.content.split(/\r?\n/);
    const emit = (rule, index, type, fix, severity = 'MEDIUM') => findings.push(makeFinding({
      check: 'infrastructure', rule, file: file.path, line: index + 1, type, severity,
      explanation: 'An explicit security-sensitive configuration pattern was found. Deployment impact requires manual verification.', fix,
    }));
    lines.forEach((text, index) => {
      if (/^\s*#/.test(text)) return;
      if (docker) {
        if (/^\s*FROM\s+(?:--\S+\s+)?[^\s]+(?=\s|$)/i.test(text) && !/@sha256:[a-f0-9]{64}\b/i.test(text) && !/^\s*FROM\s+scratch\b/i.test(text)) {
          emit('docker-unpinned-base', index, 'Mutable container base image', 'Pin external base images to a verified digest.');
        }
        if (/^\s*USER\s+(?:root|0)(?::\S+)?\s*(?:#.*)?$/i.test(text)) emit('docker-root-user', index, 'Container explicitly runs as root', 'Use a dedicated non-root runtime user.');
        if (/\b(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b/.test(text)) emit('remote-shell', index, 'Remote script piped into a shell', 'Download and verify a pinned artifact rather than executing a network stream.', 'HIGH');
      }
      if (config) {
        if (/\bprivileged["']?\s*:\s*true\b/i.test(text)) emit('privileged-container', index, 'Privileged container configuration', 'Disable privileged mode and grant only required capabilities.', 'HIGH');
        if (/\/var\/run\/docker\.sock\b/.test(text)) emit('docker-socket', index, 'Host Docker socket exposed', 'Remove the host Docker socket mount; it can grant host-level control.', 'HIGH');
        if (basename === '.npmrc' && /^\s*strict-ssl\s*=\s*false\b/i.test(text)) emit('npm-tls-disabled', index, 'npm TLS verification disabled', 'Enable strict-ssl and configure a trusted CA.');
        if (/\bNODE_TLS_REJECT_UNAUTHORIZED["']?\s*[:=]\s*["']?0\b/.test(text)) emit('node-tls-disabled', index, 'Node TLS verification disabled', 'Remove the override and use trusted certificates.', 'HIGH');
      }
    });
  }
  return { findings, coverage: { check: 'infrastructure', status: filesTested ? 'tested' : 'skipped', filesTested,
    reason: filesTested ? 'Offline Dockerfile/configuration heuristics only; no deployment, image, or full YAML semantic validation.' : 'No supported Dockerfile or configuration files supplied.' } };
}

module.exports = { scanSecrets, scanInfrastructure, makeFinding };
