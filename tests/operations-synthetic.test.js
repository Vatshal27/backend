'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createJobManager } = require('../jobs/manager');

test('synthetic operational check: concurrency limit, bounded queue and terminal-state cleanup', async () => {
  const manager = createJobManager({ maxConcurrent: 1, maxJobs: 2, timeoutMs: 1000, retentionMs: 10 });
  let release;
  const held = manager.submit('synthetic', async () => new Promise(resolve => { release = resolve; }));
  const queued = manager.submit('synthetic', async () => ({ ok: true }));
  assert.throws(() => manager.submit('synthetic', async () => ({ ok: true })), /capacity reached/);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(manager.stats().active, 1);
  assert.equal(manager.stats().queued, 1);
  release({ ok: true });
  for (let i = 0; i < 100 && manager.get(queued.id)?.status !== 'completed'; i++) await new Promise(r => setTimeout(r, 5));
  assert.equal(manager.get(held.id).status, 'completed');
  assert.equal(manager.get(queued.id).status, 'completed');
  assert.equal(manager.stats().active, 0);
  await new Promise(r => setTimeout(r, 20));
  assert.equal(manager.get(held.id), null);
  assert.equal(manager.get(queued.id), null);

  await manager.close();
});

test('synthetic restart characterization: in-memory jobs do not survive manager replacement', async () => {
  const first = createJobManager();
  const job = first.submit('synthetic', async () => ({ privateInput: 'not retained as input' }));
  await new Promise(r => setTimeout(r, 10));
  assert.equal(first.get(job.id).status, 'completed');
  await first.close();
  const afterRestart = createJobManager();
  assert.equal(afterRestart.get(job.id), null);
  await afterRestart.close();
});
