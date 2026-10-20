'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { runSemgrep } = require('../scanner/semgrep');

function invokeWithFakeSemgrep(t, setup) {
  const Module = require('node:module');
  const originalLoad = Module._load;
  let args;
  Module._load = function (request, parent, isMain) {
    if (request === 'child_process') return { execFile: (bin, argv, options, callback) => { args = { bin, argv, options }; setup(callback); } };
    return originalLoad.call(this, request, parent, isMain);
  };
  delete require.cache[require.resolve('../scanner/semgrep')];
  const module = require('../scanner/semgrep');
  t.after(() => { Module._load = originalLoad; delete require.cache[require.resolve('../scanner/semgrep')]; });
  return { module, getArgs: () => args };
}

test('Semgrep uses its rule file relative to the module and handles scan targets with JSON output', async t => {
  const fake = invokeWithFakeSemgrep(t, callback => callback(null, JSON.stringify({ results: [{ check_id: 'sentinel-javascript-eval', path: '/tmp/project/app.js', start: { line: 3 }, extra: { severity: 'ERROR', message: 'eval', metadata: { cwe: 'CWE-95' } } }] }), ''));
  const findings = await fake.module.runSemgrep('/tmp/project');
  const args = fake.getArgs();
  assert.equal(args.bin, 'semgrep');
  assert.equal(args.argv[0], '--config');
  assert.equal(args.argv[1], path.resolve(__dirname, '../scanner/rules/javascript.yml'));
  assert.ok(args.argv.includes('/tmp/project'));
  assert.ok(args.argv.includes('--json'));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].cwe, 'CWE-95');
});

test('Semgrep JSON errors and non-findings execution errors reject instead of claiming empty success', async t => {
  const invalidConfig = invokeWithFakeSemgrep(t, callback => callback(null, JSON.stringify({ results: [], errors: [{ message: 'bad config' }] }), ''));
  await assert.rejects(invalidConfig.module.runSemgrep('/tmp/project'), /bad config/);
  const failed = invokeWithFakeSemgrep(t, callback => callback(Object.assign(new Error('Semgrep crash'), { code: 2 }), JSON.stringify({ results: [] }), 'scanner crashed'));
  await assert.rejects(failed.module.runSemgrep('/tmp/project'), /exit code 2/);
});
