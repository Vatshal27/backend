'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runSupplementaryChecks } = require('../security/profiles');

test('pre-aborted supplemental checks do no work and malformed advisory responses are inconclusive', async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(runSupplementaryChecks({ profile: 'secrets', files: [{ path: 'app.js', content: '' }], signal: controller.signal }), { name: 'AbortError' });
  const lock = { path: 'package-lock.json', content: JSON.stringify({ packages: { '': { dependencies: { demo: '*' } }, 'node_modules/demo': { version: '1.2.3' } } }) };
  const result = await runSupplementaryChecks({ profile: 'dependencies', files: [lock], options: {
    allowAdvisoryNetwork: true, advisoryFetch: async () => { throw new Error('temporarily unavailable'); },
  } });
  assert.equal(result.findings.length, 0);
  assert.equal(result.coverage[0].status, 'inconclusive');
  assert.equal(result.coverage[0].packagesTested, 0);
});

test('invalid, unsupported and unresolved lockfile entries explicitly make offline coverage inconclusive', async () => {
  for (const content of ['{truncated', JSON.stringify({ lockfileVersion: 1, dependencies: { pkg: { version: '1.0.0' } } }),
    JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/pkg': {} } })]) {
    const result = await runSupplementaryChecks({ profile: 'dependencies', files: [{ path: 'package-lock.json', content }] });
    assert.equal(result.coverage[0].status, 'inconclusive');
    assert.match(result.coverage[0].reason, /incomplete|unresolved/i);
  }
});

test('supported exact non-npm lockfile versions are not falsely reported as npm-only unsupported inputs', async () => {
  const result = await runSupplementaryChecks({ profile: 'dependencies', files: [
    { path: 'requirements.txt', content: 'flask==1.0.0' },
    { path: 'Cargo.toml', content: '[dependencies]\nserde = "1.0"' },
  ] });
  assert.equal(result.findings.length, 0);
  assert.equal(result.coverage[0].status, 'inconclusive');
  assert.match(result.coverage[0].reason, /lockfile|coverage/i);
});
