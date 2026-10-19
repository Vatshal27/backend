'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getScanProfiles } = require('../security/profiles');

const { validateRequest } = require('../jobs/routes');

test('API describes available and unsupported scan checks accurately', () => {
  const profiles = getScanProfiles();
  const comprehensive = profiles.find(item => item.id === 'comprehensive');
  for (const id of ['authentication', 'api', 'browser']) {
    assert.equal(comprehensive.checks.find(check => check.id === id).available, false);
  }
  assert.match(profiles.find(item => item.id === 'dependencies').checks[0].explanation, /pypi|crates\.io|ruby/i);
  const caps = { profiles: [{ id: 'source', supported: true }] };
  assert.throws(() => validateRequest({ kind: 'scan', profile: 'source', files: [
    { path: 'report.json', content: JSON.stringify({ mode: 'vulnerability-lab', projectVulnerabilityConfirmed: false }) },
  ] }, caps), /File type/);
});
