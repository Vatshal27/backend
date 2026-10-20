'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecurityRouter } = require('../jobs/routes');
const { createJobManager } = require('../jobs/manager');

async function harness(t) {
  const manager = createJobManager({ sanitize: v => v });
  const app = express();
  app.use(express.json());
  app.use('/security', createSecurityRouter({ manager,
    capabilities: () => ({ profiles: [{ id: 'source' }], labs: [{ id: 'sql_injection', supported: true }] }),
    execute: async (request, { emit }) => {
      emit({ stage: 'test', description: 'Actual execution' });
      return { profile: request.profile, findings: [] };
    } }));
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(async () => { await manager.close(); await new Promise(resolve => server.close(resolve)); });
  return { url: `http://127.0.0.1:${server.address().port}/security`, manager };
}

test('HTTP capability and job routes preserve observable execution lifecycle', async t => {
  const { url } = await harness(t);
  const capabilities = await (await fetch(`${url}/capabilities`)).json();
  assert.equal(capabilities.profiles[0].id, 'source');
  const response = await fetch(`${url}/jobs`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'scan', profile: 'source', files: [{ path: 'app.js', content: 'const a = 1;' }] }) });
  assert.equal(response.status, 202);
  const { job } = await response.json();
  await new Promise(resolve => setImmediate(resolve));
  const detail = await (await fetch(`${url}/jobs/${job.id}`)).json();
  assert.equal(detail.job.status, 'completed');
  assert.ok(detail.job.events.some(event => event.stage === 'test'));
  assert.equal((await fetch(`${url}/jobs/missing`)).status, 404);
});

test('local-only middleware rejects non-loopback clients and hostile origins/hosts', async t => {
  const { createLocalOnlyMiddleware } = require('../http/local-only');
  const { app } = require('../server');
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/security/capabilities`;
  const capabilities = await fetch(base);
  assert.equal(capabilities.status, 200);
  assert.deepEqual((await capabilities.json()).profiles.map(profile => profile.id), ['source', 'dependencies', 'secrets', 'infrastructure', 'comprehensive']);
  assert.equal((await fetch(base, { headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await fetch(base, { headers: { Origin: `http://localhost:${server.address().port}` } })).status, 403);
  assert.equal((await fetch(base, { headers: { Host: '127.0.0.1:3000', Origin: 'http://127.0.0.1:3000' } })).status, 403);
  const middleware = createLocalOnlyMiddleware();
  for (const request of [
    { socket: { remoteAddress: '192.0.2.10' }, headers: { host: 'localhost:3000' } },
    { socket: { remoteAddress: '127.0.0.1' }, headers: { host: 'evil.example' } },
  ]) {
    let status;
    middleware(request, { status(code) { status = code; return { json() {} }; } }, () => assert.fail('untrusted request passed'));
    assert.equal(status, 403);
  }
});

test('job submission rejects browser origins, unknown modes and unsafe file paths', async t => {
  const { url } = await harness(t);
  const submit = (body, extra = {}) => fetch(`${url}/jobs`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(body) });
  assert.equal((await submit({ kind: 'scan', files: [] }, { Origin: 'https://untrusted.example' })).status, 403);
  assert.equal((await submit({ kind: 'arbitrary-command' })).status, 400);
  const legacyLab = await submit({ kind: 'lab', scenario: 'unknown' });
  assert.equal(legacyLab.status, 400);
  assert.match((await legacyLab.json()).error, /Safe Simulation and Project Validation/);
  assert.equal((await submit({ kind: 'scan', profile: 'unknown', files: [] })).status, 400);
  for (const path of ['../outside.js', '/etc/passwd', 'C:\\outside.js', '.env', 'config/.env.local', 'id_rsa']) {
    assert.equal((await submit({ kind: 'scan', files: [{ path, content: 'ignored' }] })).status, 400, path);
  }
  assert.equal((await submit({ kind: 'scan', files: [{ path: 'ok.js', content: 42 }] })).status, 400);
});

test('completed jobs expose replayable SSE events ending in a terminal snapshot', async t => {
  const { url } = await harness(t);
  const response = await fetch(`${url}/jobs`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'scan', files: [] }) });
  const { job } = await response.json();
  await new Promise(resolve => setImmediate(resolve));
  const stream = await fetch(`${url}/jobs/${job.id}/events`);
  assert.match(stream.headers.get('content-type'), /text\/event-stream/);
  const text = await stream.text();
  assert.match(text, /event: snapshot/);
  assert.match(text, /"status":"completed"/);
});
