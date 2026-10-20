'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { writeReportFiles, getManagedReportFiles } = require('../docker/reporting/writer');
const { cleanupExpiredReports } = require('../docker/reporting/retention');

function sample() {
  return { generatedAt: new Date().toISOString(), summary: { findings: 0 }, findings: { all: [], static: [], ai: [], correlated: [] }, projectValidation: {}, selfTest: {} };
}

test('report writer preserves unrelated SentinelAI-named files and updates only its two owned outputs', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinelai-report-test-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const unrelated = path.join(dir, 'SentinelAI-notes.json');
  await fs.writeFile(unrelated, 'keep me');
  const first = await writeReportFiles(sample(), dir);
  assert.equal(await fs.readFile(unrelated, 'utf8'), 'keep me');
  const second = await writeReportFiles(sample(), dir);
  assert.equal(first.json, second.json);
  assert.equal(first.markdown, second.markdown);
  assert.equal(await fs.readFile(unrelated, 'utf8'), 'keep me');
  assert.deepEqual([...getManagedReportFiles()].sort(), ['SentinelAI_Security_Data.json', 'SentinelAI_Security_Report.md']);
});

test('paired report install rolls back on second rename failure', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinelai-report-rollback-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const first = await writeReportFiles(sample(), dir);
  const before = { json: await fs.readFile(first.json), markdown: await fs.readFile(first.markdown) };
  const originalRename = fs.rename;
  let failed = false;
  fs.rename = async (from, to) => {
    if (!failed && to === first.json && from.endsWith('.tmp')) { failed = true; throw new Error('injected JSON rename failure'); }
    return originalRename(from, to);
  };
  try { await assert.rejects(writeReportFiles({ ...sample(), summary: { findings: 2 } }, dir), /injected JSON rename failure/); }
  finally { fs.rename = originalRename; }
  assert.deepEqual(await fs.readFile(first.json), before.json);
  assert.deepEqual(await fs.readFile(first.markdown), before.markdown);
});

test('retention only removes owned report files, preserving unrelated Markdown and JSON', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sentinelai-report-retention-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const old = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
  const own = path.join(dir, 'SentinelAI_Security_Report.md');
  const unrelated = path.join(dir, 'SentinelAI-notes.json');
  await fs.writeFile(own, 'old report');
  await fs.writeFile(unrelated, 'keep');
  await fs.utimes(own, old, old);
  await fs.utimes(unrelated, old, old);
  const result = await cleanupExpiredReports(dir);
  assert.equal(result.deleted, 1);
  await assert.rejects(fs.access(own));
  assert.equal(await fs.readFile(unrelated, 'utf8'), 'keep');
});
