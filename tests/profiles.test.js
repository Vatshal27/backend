'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
let api = {};
try { api = require('../security/profiles'); } catch (error) {
  if (error.code !== 'MODULE_NOT_FOUND' || !error.message.includes("'../security/profiles'")) throw error;
}

test('profiles disclose executable capabilities and context-dependent gaps', async () => {
  assert.equal(typeof api.getScanProfiles, 'function');
  const profiles = api.getScanProfiles();
  assert.deepEqual(profiles.map(p => p.id), ['source', 'dependencies', 'secrets', 'infrastructure', 'comprehensive']);
  const all = profiles.find(p => p.id === 'comprehensive');
  for (const id of ['authentication', 'api', 'browser']) {
    const check = all.checks.find(c => c.id === id);
    assert.equal(check.available, false);
    assert.match(check.explanation, /context|not implemented/i);
  }
  assert.equal(profiles.find(p => p.id === 'dependencies').checks[0].available, true);
  const result = await api.runSupplementaryChecks({ files: [], profile: 'source' });
  assert.deepEqual(result.findings, []);
  assert.equal(result.coverage[0].status, 'skipped');
  assert.match(result.coverage[0].reason, /existing|parent/i);
  await assert.rejects(api.runSupplementaryChecks({ files: [], profile: 'typo' }), /Unknown scan profile/);
});

test('secret checks identify credential candidates without storing their values', async () => {
  const github = 'ghp_' + 'Ab9'.repeat(12);
  const aws = 'AKIA' + 'Z7'.repeat(8);
  const password = 'unusual-production-password-99';
  const events = [];
  const result = await api.runSupplementaryChecks({
    profile: 'secrets', onEvent: event => events.push(event),
    files: [{ path: 'src/config.js', content: [
      `const token = '${github}';`, `AWS_ACCESS_KEY_ID=${aws}`,
      `password = "${password}"`, '-----BEGIN RSA PRIVATE KEY-----',
      'api_key = "YOUR_API_KEY"', 'password = process.env.PASSWORD',
    ].join('\n') }],
  });
  assert.equal(result.coverage[0].status, 'tested');
  assert.equal(result.findings.length, 4);
  for (const finding of result.findings) {
    assert.equal(finding.file, 'src/config.js');
    assert.match(finding.line, /^[1-4]$/);
    assert.equal(finding.source, 'supplementary');
    assert.equal(finding.verification, 'unverified');
    assert.equal(finding.vulnerableCode, '[REDACTED]');
    assert.ok(finding.id && finding.type && finding.explanation && finding.fix);
  }
  assert.ok(events.some(e => e.type === 'check-completed'));
  for (const value of [github, aws, password]) assert.ok(!JSON.stringify({ result, events }).includes(value));
});

test('labeled source-secret corpus checks candidate detection and safe negatives (not validity)', async () => {
  const corpus = [
    { path: 'fixtures/vuln.js', content: 'const password = "synthetic-secret-value-9843";\n' },
    { path: 'fixtures/fixed.js', content: 'const password = process.env.APP_PASSWORD;\n' },
    { path: 'fixtures/docs.js', content: 'const example = "YOUR_API_KEY";\n// password = "placeholder-secret"\n' },
  ];
  const result = await api.runSupplementaryChecks({ profile: 'secrets', files: corpus });
  assert.deepEqual(result.findings.map(item => [item.file, item.line, item.rule]), [
    ['fixtures/vuln.js', '1', 'credential-assignment'],
  ]);
  assert.equal(result.coverage[0].status, 'tested');
  assert.equal(result.findings[0].verification, 'unverified');
  assert.doesNotMatch(JSON.stringify(result), /synthetic-secret-value-9843/);
});

test('infrastructure checks Dockerfile and explicit unsafe configuration without running code', async () => {
  const result = await api.runSupplementaryChecks({ profile: 'infrastructure', files: [
    { path: 'Dockerfile', content: 'FROM node:latest\nRUN curl https://example.invalid/install | sh\nUSER root\n' },
    { path: 'compose.yaml', content: 'services:\n  app:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n' },
    { path: '.npmrc', content: 'strict-ssl=false' },
    { path: '.env', content: 'NODE_TLS_REJECT_UNAUTHORIZED=0' },
    { path: 'README.md', content: 'privileged: true' },
  ] });
  assert.equal(result.coverage[0].status, 'tested');
  assert.equal(result.coverage[0].filesTested, 4);
  assert.deepEqual(result.findings.map(f => f.rule).sort(), [
    'docker-unpinned-base', 'docker-root-user', 'remote-shell', 'privileged-container',
    'docker-socket', 'npm-tls-disabled', 'node-tls-disabled',
  ].sort());
  const safe = await api.runSupplementaryChecks({ profile: 'infrastructure', files: [
    { path: 'Dockerfile', content: 'FROM node@sha256:' + 'a'.repeat(64) + '\nUSER node' },
    { path: 'compose.yaml', content: '# privileged: true\nservices:\n  app:\n    privileged: false' },
  ] });
  assert.equal(safe.findings.length, 0);
});
