'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { getAttackDefinition } = require('../docker/attacks/catalog');
const { prepareProject, evaluateAttack } = require('../docker/runner');
const { createAttackPlan } = require('../docker/planner');

test('Project Validation plans standalone sensitive-data assessment without requiring a static finding', () => {
  const plans = createAttackPlan([], 'http://127.0.0.1:8080');
  assert.ok(plans.some(plan => plan.attackType === 'sensitive_data' && plan.source === 'runtime'));
});

function request(target, input) {
  return new Promise((resolve, reject) => {
    const url = new URL(input.path, target);
    const req = http.request(url, { method: input.method, headers: input.headers || {} }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('read-only Project Validation probes report supported passive exposure over a local authorized target', async t => {
  const fixture = http.createServer((req, res) => {
    if (req.method === 'OPTIONS') { res.writeHead(204, { Allow: 'GET, OPTIONS, TRACE' }); res.end(); }
    else if (req.url === '/files') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<title>Index of /files</title><a href="backup.zip">backup.zip</a>'); }
    else {
      const headers = { 'Content-Type': 'text/html', 'Set-Cookie': 'sid=fixture-session; Path=/' };
      if (req.headers.origin) { headers['Access-Control-Allow-Origin'] = req.headers.origin; headers['Access-Control-Allow-Credentials'] = 'true'; }
      res.writeHead(200, headers);
      res.end('<html><body>Traceback (most recent call last): user@example.test</body></html>');
    }
  });
  await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => fixture.close(resolve)));
  const target = `http://127.0.0.1:${fixture.address().port}`;
  const route = { method: 'GET', url: `${target}/`, source: 'root', parameters: [] };
  for (const attackType of ['security_headers', 'cookie_security', 'debug_exposure', 'sensitive_data', 'unsafe_http_methods', 'directory_listing', 'cors']) {
    const definition = getAttackDefinition(attackType);
    const plan = { id: `runtime-${attackType}`, findingId: `runtime-${attackType}`, attackType, attackName: definition.name, source: 'runtime' };
    const selectedRoute = attackType === 'directory_listing' ? { ...route, url: `${target}/files` } : route;
    const { prepared, skipped } = prepareProject([], [plan], [selectedRoute]);
    assert.equal(prepared.length, 1, `${attackType} prepared`);
    assert.equal(skipped.length, 0, `${attackType} skipped`);
    const item = prepared[0];
    assert.ok(['GET', 'OPTIONS'].includes(item.request.method));
    assert.equal(item.request.body, undefined);
    const response = await request(target, item.request);
    const baselineResponse = item.baselineRequest ? await request(target, item.baselineRequest) : null;
    const result = evaluateAttack({ ...item, request: { method: item.request.method, url: new URL(item.request.path, target).toString() },
      response, baselineResponse, status: 'executed', execution: 'executed', executed: true,
      evidence: [{ type: 'response', content: 'local test fixture' }], finishedAt: new Date().toISOString() }, true);
    assert.equal(result.runtimeVerdict, attackType === 'cors' ? 'observed_exposure' : 'observed_exposure', `${attackType} runtime verdict`);
    if (attackType === 'cors') assert.deepEqual(item.request.headers, { Origin: 'https://sentinelai.invalid' });
    assert.ok(result.evidence?.length);
  }
});
