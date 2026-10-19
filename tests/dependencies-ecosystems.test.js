'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { runSupplementaryChecks } = require('../security/profiles');

test('opt-in OSV inventory queries exact pinned versions for supported Python, Rust, Go, PHP, and Ruby lockfiles', async () => {
  const files = [
    { path: 'requirements.txt', content: 'flask==2.3.1\n# skip this\n' },
    { path: 'Cargo.lock', content: '[[package]]\nname = "serde"\nversion = "1.0.188"\n\n[[package]]\nname = "tokio"\nversion = "1.32.0"\n' },
    { path: 'go.sum', content: 'golang.org/x/net v0.10.0 h1:abc=\ngolang.org/x/net v0.10.0/go.mod h1:def=\n' },
    { path: 'composer.lock', content: JSON.stringify({ packages: [{ name: 'symfony/http-foundation', version: 'v6.3.2' }] }) },
    { path: 'Gemfile.lock', content: 'GEM\n  specs:\n    rack (2.2.8)\n    rails (7.0.8)\n' },
  ];
  const requests = [];
  const result = await runSupplementaryChecks({ profile: 'dependencies', files, options: {
    allowAdvisoryNetwork: true,
    advisoryFetch: async (_url, request) => { requests.push(JSON.parse(request.body)); return { ok: true, json: async () => ({}) }; },
  } });
  assert.deepEqual(requests.map(q => [q.package.ecosystem, q.package.name, q.version]), [
    ['PyPI', 'flask', '2.3.1'], ['crates.io', 'serde', '1.0.188'], ['crates.io', 'tokio', '1.32.0'],
    ['Go', 'golang.org/x/net', 'v0.10.0'], ['Packagist', 'symfony/http-foundation', 'v6.3.2'],
    ['RubyGems', 'rack', '2.2.8'], ['RubyGems', 'rails', '7.0.8'],
  ]);
  assert.equal(result.coverage[0].status, 'tested');
  assert.equal(result.coverage[0].packagesDiscovered, 7);
  assert.equal(result.coverage[0].packagesTested, 7);
  assert.equal(result.coverage.some(row => row.status === 'unsupported'), false);
});
