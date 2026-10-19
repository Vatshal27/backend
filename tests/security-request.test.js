'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validateRequest } = require('../jobs/routes');
const caps = { profiles: [{ id: 'source' }], labs: [{ id: 'sql_injection', supported: true }] };

test('capabilities can contain presentation text and validation uses only stable ids', () => {
  const capability = { profiles: [{ id: 'source', label: 'Source analysis', supported: true }],
    labs: [{ id: 'sql_injection', title: 'SQL injection', engine: 'SQLite', supported: true }] };
  assert.throws(() => validateRequest({ kind: 'lab', scenario: 'sql_injection' }, capability), /Safe Simulation and Project Validation/);
  assert.equal(validateRequest({ kind: 'scan', profile: 'source', files: [] }, capability).profile, 'source');
});

test('workbench accepts dependency manifests only under the dependency profiles', () => {
  const file = { path: 'package-lock.json', content: '{}'};
  assert.throws(() => validateRequest({ kind: 'scan', profile: 'source', files: [file] }, caps), /not enabled/);
  assert.equal(validateRequest({ kind: 'scan', profile: 'dependencies', expectedLockfiles: ['package-lock.json'], files: [file] }, {
    profiles: [{ id: 'dependencies' }] }).files.length, 1);
});

test('dependency profiles require evidence that every detected supported npm lockfile was included', () => {
  const dependencyCaps = { profiles: [{ id: 'dependencies' }] };
  assert.throws(() => validateRequest({ kind: 'scan', profile: 'dependencies', files: [] }, dependencyCaps), /expectedLockfiles/);
  assert.throws(() => validateRequest({ kind: 'scan', profile: 'dependencies', expectedLockfiles: ['package-lock.json'], files: [] }, dependencyCaps), /omitted/);
  assert.deepEqual(validateRequest({ kind: 'scan', profile: 'dependencies', expectedLockfiles: ['package-lock.json'],
    files: [{ path: 'package-lock.json', content: '{}' }] }, dependencyCaps).expectedLockfiles, ['package-lock.json']);
});
