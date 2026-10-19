'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

test('redact recursively removes credential fields and inline secrets without mutating input', () => {
  const { redact } = require('../security/redact');
  const secrets = ['tiny', 'token-value', 'cookie-value', 'db-pass', 'url-pass', 'private-material', 'json-secret', 'env-secret', 'basic-value'];
  const input = {
    nested: [{ password: secrets[0], apiKey: secrets[1], headers: { Cookie: 'session=cookie-value' } }],
    response: 'Authorization: Basic basic-value\nSet-Cookie: session=cookie-value; HttpOnly\n',
    text: 'postgresql://user:db-pass@host/db https://user:url-pass@host/path?access_token=token-value&ok=1',
    body: '{"password":"json-secret","ok":true}',
    env: 'DB_PASSWORD=env-secret',
    keyMaterial: '-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----',
    count: 4, enabled: false, nothing: null, rationale: 'SQL syntax error',
  };
  const output = redact(input);
  for (const secret of secrets) assert.ok(!JSON.stringify(output).includes(secret), secret);
  assert.equal(input.nested[0].password, 'tiny');
  assert.equal(output.count, 4);
  assert.equal(output.enabled, false);
  assert.equal(output.nothing, null);
  assert.equal(output.rationale, 'SQL syntax error');
  assert.deepEqual(redact(output), output);
  const circular = { password: 'tiny' }; circular.self = circular;
  assert.doesNotThrow(() => JSON.stringify(redact(circular)));
});

test('every evidence/report boundary redacts nested fields, requests, events and findings', () => {
  const { normalizeEvidence } = require('../docker/evidence');
  const { buildReport } = require('../docker/report');
  const { compileReports } = require('../docker/reporting/compiler');
  const { createMachineReport } = require('../docker/reporting/machine-report');
  const { renderMarkdownReport } = require('../docker/reporting/markdown-report');
  const secret = 'do-not-persist-me';
  const attack = { id: 'redaction', status: 'success', runtimeVerdict: 'confirmed',
    request: { url: `http://localhost/?token=${secret}`, headers: { Authorization: `Bearer ${secret}` } },
    response: { statusCode: 500, body: `{"password":"${secret}"}`, headers: { 'Set-Cookie': secret } },
    baselineResponse: { body: `password=${secret}` },
    evidence: [{ type: 'finding', content: 'SQL error', metadata: { password: secret } }],
    rationale: `password=${secret}`,
  };
  const normalized = normalizeEvidence([attack]);
  assert.ok(!JSON.stringify(normalized).includes(secret), 'normalized evidence');
  assert.deepEqual(normalizeEvidence(normalized), normalized, 'normalization is idempotent');
  const report = buildReport({ mode: 'project-validation', attacks: [attack],
    findings: [{ id: 'source', explanation: `password=${secret}` }],
    events: [{ description: `token=${secret}` }],
  });
  assert.ok(!JSON.stringify(report).includes(secret), 'raw report');
  const compiled = compileReports({ projectReport: report,
    findings: [{ explanation: `password=${secret}` }], project: { name: `token=${secret}` } });
  assert.ok(!JSON.stringify(compiled).includes(secret), 'compiled report');
  const unredacted = { ...compiled, project: { name: `token=${secret}` } };
  assert.ok(!JSON.stringify(createMachineReport(unredacted)).includes(secret), 'machine report');
  assert.ok(!renderMarkdownReport(unredacted).includes(secret), 'markdown report');
  assert.ok(attack.response.body.includes(secret), 'source remains untouched');
});

test('runtime evidence reports discovered sensitive data with locations and masked samples only', () => {
  const { normalizeEvidence } = require('../docker/evidence');
  const body = JSON.stringify({
    error: 'SQL syntax error',
    profile: { email: 'user@example.test', password: 'DO_NOT_LEAK_password_1234' },
    note: 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345, phone: +1 (415) 555-0123',
  });
  const [attack] = normalizeEvidence([{
    id: 'exposure-test', attackType: 'sqli',
    request: { method: 'GET', url: 'http://127.0.0.1:8080/search?q=test' },
    response: { statusCode: 500, headers: { 'content-type': 'application/json' }, body },
  }]);
  assert.equal(attack.sensitiveData.length, 4);
  assert.deepEqual(attack.sensitiveData.map(item => item.dataType).sort(), ['Application Secret', 'Authentication Token', 'Email Address', 'Phone Number'].sort());
  assert.ok(attack.sensitiveData.every(item => item.location && item.maskedValue));
  assert.ok(attack.sensitiveData.some(item => item.fieldPath === '$.profile.password'));
  assert.equal(JSON.stringify(attack).includes('DO_NOT_LEAK_password_1234'), false);
  assert.equal(JSON.stringify(attack).includes('abcdefghijklmnopqrstuvwxyz012345'), false);
  assert.equal(JSON.stringify(attack).includes('+1 (415) 555-0123'), false);
  assert.equal(attack.response.bodyPreview.includes('user@example.test'), false);
  assert.equal(attack.response.bodyPreview.includes('555-0123'), false);
});

test('sensitive-data runtime verdict is differential and baseline values are not reported as new leaks', () => {
  const { evaluateRuntimeEvidence } = require('../docker/validation/runtime-evidence');
  const attack = { attackType: 'sensitive_data' };
  const baseline = { body: JSON.stringify({ email: 'person@example.test', password: 'baseline-pass-value-123' }) };
  const repeated = evaluateRuntimeEvidence(attack, { body: baseline.body }, { baselineResponse: baseline });
  assert.equal(repeated.verdict, 'not_reproduced');
  const leaked = evaluateRuntimeEvidence(attack, { body: JSON.stringify({ email: 'person@example.test', password: 'baseline-pass-value-123', apiKey: 'NEW_SECRET_KEY_987654' }) }, { baselineResponse: baseline });
  assert.equal(leaked.verdict, 'observed_exposure');
  assert.match(leaked.rationale, /Application Secret/);
});

test('project runtime findings never submit local source secrets as runtime probes', () => {
  const { createAttackPlan } = require('../docker/planner');
  const plans = createAttackPlan([
    { id: 'secret-1', source: 'supplementary', check: 'secrets', type: 'Hardcoded credential candidate' },
  ], 'http://127.0.0.1:8080');
  assert.ok(!plans.some(plan => plan.findingId === 'secret-1'));
});
