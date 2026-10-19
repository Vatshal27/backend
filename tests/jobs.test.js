'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createJobManager } = require('../jobs/manager');
const tick = () => new Promise(resolve => setImmediate(resolve));

test('jobs execute serially and expose real ordered events without retaining input', async () => {
  let release;
  const manager = createJobManager({ maxConcurrent: 1, sanitize: value => value });
  const first = manager.submit('scan', async ({ emit }) => {
    emit({ stage: 'scanner', status: 'running', description: 'Started scanner' });
    await new Promise(resolve => { release = resolve; });
    return { findings: [] };
  });
  const second = manager.submit('lab', async () => ({ passed: true }));
  await tick();
  assert.equal(manager.get(first.id).status, 'running');
  assert.equal(manager.get(second.id).status, 'queued');
  release();
  await tick();
  await tick();
  const result = manager.get(first.id);
  assert.equal(result.status, 'completed');
  assert.deepEqual(result.result, { findings: [] });
  assert.deepEqual(result.events.map(e => e.sequence), [1, 2, 3, 4]);
  assert.equal(manager.get(second.id).status, 'completed');
  result.events.length = 0;
  assert.equal(manager.get(first.id).events.length, 4);
  await manager.close();
});

test('cancelling queued jobs releases their queue entry immediately', async () => {
  const manager = createJobManager({ maxConcurrent: 1, maxJobs: 2, retentionMs: 0, sanitize: v => v });
  let release;
  manager.submit('scan', () => new Promise(resolve => { release = resolve; }));
  await tick();
  for (let i = 0; i < 5; i++) {
    const queued = manager.submit('lab', async () => assert.fail('Cancelled task ran'));
    manager.cancel(queued.id);
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  assert.equal(manager.stats().queued, 0);
  release({});
  await tick();
  await manager.close();
});

test('running cancellation waits for cleanup before reporting terminal status', async () => {
  const manager = createJobManager({ sanitize: v => v });
  let release;
  const job = manager.submit('lab', async ({ signal }) => {
    await new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
    await new Promise(resolve => { release = resolve; });
    signal.throwIfAborted();
  });
  await tick();
  assert.equal(manager.cancel(job.id).status, 'running');
  await tick();
  release();
  await tick();
  assert.equal(manager.get(job.id).status, 'cancelled');
  await manager.close();
});

test('capacity and event limits are enforced; task exceptions become failed jobs', async () => {
  const manager = createJobManager({ maxJobs: 1, maxEvents: 3, sanitize: v => v });
  const job = manager.submit('scan', async ({ emit }) => {
    for (let i = 0; i < 10; i++) emit({ description: `step ${i}` });
    throw new Error('scanner unavailable');
  });
  assert.throws(() => manager.submit('scan', async () => ({})), /capacity/);
  await tick();
  assert.equal(manager.get(job.id).status, 'failed');
  assert.equal(manager.get(job.id).events.length, 3);
  await manager.close();
});
