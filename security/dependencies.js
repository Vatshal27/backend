'use strict';
const { makeFinding } = require('./checks');

const FILES = [
  /(?:^|\/)package-lock\.json$/i,
  /(?:^|\/)requirements\.txt$/i,
  /(?:^|\/)poetry\.lock$/i,
  /(?:^|\/)pdm\.lock$/i,
  /(?:^|\/)uv\.lock$/i,
  /(?:^|\/)pipfile\.lock$/i,
  /(?:^|\/)cargo\.lock$/i,
  /(?:^|\/)go\.sum$/i,
  /(?:^|\/)composer\.lock$/i,
  /(?:^|\/)gemfile\.lock$/i,
];
function isDependencyFile(file) { const path = String(file.path || '').replace(/\\/g, '/'); return FILES.some(pattern => pattern.test(path)); }
function issue(coverage, file, status, reason, line) { coverage.push({ check: 'dependencies', status, file: file.path, ...(line ? { line } : {}), reason }); }
function addPkg(packages, ecosystem, name, version, file, location, direct = false, dev = false) {
  packages.push({ ecosystem, name, version, file: file.path, location, direct, dev });
}
function parseNpm(file, packages, coverage) {
  let lock;
  try { lock = JSON.parse(file.content); } catch { issue(coverage, file, 'inconclusive', 'package-lock.json is invalid or truncated.'); return; }
  if (!lock?.packages || typeof lock.packages !== 'object') { issue(coverage, file, 'inconclusive', 'Unsupported or incomplete package-lock format.'); return; }
  const direct = lock.packages['']?.dependencies || {};
  for (const [location, entry] of Object.entries(lock.packages)) {
    if (!location) continue;
    const name = entry?.name || location.split('node_modules/').at(-1);
    if (typeof name !== 'string' || typeof entry?.version !== 'string') { issue(coverage, file, 'inconclusive', 'A locked npm package lacks an exact name or version.'); continue; }
    addPkg(packages, 'npm', name, entry.version, file, location, Object.hasOwn(direct, name) && location === `node_modules/${name}`, entry.dev === true);
  }
}
function parsePython(file, packages, coverage) {
  for (const [line, source] of file.content.split(/\r?\n/).entries()) {
    const text = source.trim();
    if (!text || text.startsWith('#') || text.startsWith('-')) continue;
    if (text.includes('==') && /(?:\s|[<>=!~])/.test(text.slice(0, text.indexOf('==')))) {
      issue(coverage, file, 'unsupported', 'Requirement options or environment markers are not supported; entry skipped.', line + 1); continue;
    }
    const m = /^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*(?:;.*)?$/.exec(text);
    if (!m) { issue(coverage, file, 'unsupported', 'Only exact pinned name==version requirements are supported; entry skipped.', line + 1); continue; }
    addPkg(packages, 'PyPI', m[1].toLowerCase().replace(/[-_.]+/g, '-'), m[2], file, `line:${line + 1}`, true, false);
  }
}
function parseCargo(file, packages, coverage) {
  let name;
  for (const [line, source] of file.content.split(/\r?\n/).entries()) {
    if (/^\[\[package\]\]\s*$/.test(source.trim())) { name = undefined; continue; }
    const n = /^name\s*=\s*"([^"]+)"\s*$/.exec(source.trim());
    const v = /^version\s*=\s*"([^"]+)"\s*$/.exec(source.trim());
    if (n) { name = n[1]; continue; }
    if (v && name) { addPkg(packages, 'crates.io', name, v[1], file, `package:${name}`); name = undefined; }
  }
}
function parseGo(file, packages) {
  const seen = new Set();
  for (const source of file.content.split(/\r?\n/)) {
    const m = /^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:/.exec(source.trim());
    if (!m || m[3]) continue;
    const key = `${m[1]}@${m[2]}`;
    if (!seen.has(key)) { seen.add(key); addPkg(packages, 'Go', m[1], m[2], file, m[1]); }
  }
}
function parseJsonLock(file, packages, coverage, ecosystem, key) {
  let lock;
  try { lock = JSON.parse(file.content); } catch { issue(coverage, file, 'inconclusive', `${key} is invalid or truncated.`); return; }
  for (const pkg of lock[key] || []) {
    if (typeof pkg.name !== 'string' || typeof pkg.version !== 'string') { issue(coverage, file, 'inconclusive', `${ecosystem} package lacks exact name/version.`); continue; }
    addPkg(packages, ecosystem, pkg.name, pkg.version, file, pkg.name, key === 'packages-dev');
  }
}
function parseGem(file, packages) {
  let inSpecs = false;
  for (const [line, source] of file.content.split(/\r?\n/).entries()) {
    if (/^  specs:\s*$/.test(source)) { inSpecs = true; continue; }
    if (!inSpecs) continue;
    if (/^  [A-Z]/.test(source)) { inSpecs = false; continue; }
    const m = /^    ([A-Za-z0-9_.-]+) \(([^)]+)\)/.exec(source);
    if (m) addPkg(packages, 'RubyGems', m[1], m[2], file, `line:${line + 1}`);
  }
}
function parseLock(file, packages, coverage) {
  const path = file.path.replace(/\\/g, '/').toLowerCase();
  if (/\/package-lock\.json$/.test(`/${path}`)) return parseNpm(file, packages, coverage);
  if (/\/requirements(?:-[^/]*)?\.txt$/.test(`/${path}`)) return parsePython(file, packages, coverage);
  if (/\/(?:cargo\.lock)$/.test(`/${path}`)) return parseCargo(file, packages, coverage);
  if (/\/go\.sum$/.test(`/${path}`)) return parseGo(file, packages);
  if (/\/composer\.lock$/.test(`/${path}`)) return parseJsonLock(file, packages, coverage, 'Packagist', 'packages');
  if (/\/gemfile\.lock$/.test(`/${path}`)) return parseGem(file, packages);
  issue(coverage, file, 'unsupported', 'This lockfile was recognized but its exact package resolver is not implemented.');
}
function detectManifestGaps(files, locks, coverage) {
  const lockPaths = new Set(locks.map(file => file.path.replace(/\\/g, '/').toLowerCase()));
  const manifests = /(?:^|\/)(package\.json|pyproject\.toml|pipfile|cargo\.toml|composer\.json|gemfile|go\.mod|pom\.xml|build\.gradle)$/i;
  for (const file of files) {
    const path = file.path.replace(/\\/g, '/').toLowerCase();
    const name = path.split('/').pop();
    if (!manifests.test(path)) continue;
    const expected = name === 'package.json' ? path.replace(/package\.json$/, 'package-lock.json')
      : ['pyproject.toml', 'pipfile'].includes(name) ? (name === 'pipfile' ? path + '.lock' : path.replace(/pyproject\.toml$/, 'uv.lock'))
        : name === 'cargo.toml' ? path.replace(/cargo\.toml$/, 'cargo.lock')
          : name === 'composer.json' ? path.replace(/composer\.json$/, 'composer.lock')
            : name === 'gemfile' ? path + '.lock' : name === 'go.mod' ? path.replace(/go\.mod$/, 'go.sum') : null;
    if (expected && !lockPaths.has(expected)) issue(coverage, file, 'inconclusive', 'Manifest found without its lockfile; version ranges are not exact and no advisory lookup was performed.');
    if (['pom.xml', 'build.gradle'].includes(name)) issue(coverage, file, 'unsupported', 'Java dependency resolution is unsupported; manifest ranges cannot be queried as exact versions.');
  }
}
function summarize(coverage, discovered, tested) {
  const statuses = coverage.map(item => item.status);
  const status = statuses.includes('inconclusive') || statuses.includes('failed') ? 'inconclusive'
    : statuses.includes('tested') ? 'tested'
      : statuses.includes('unsupported') ? 'unsupported' : 'skipped';
  const summaryReason = statuses.includes('inconclusive') || statuses.includes('failed')
    ? 'Dependency coverage is incomplete; inspect file-level entries below.'
    : statuses.includes('unsupported') ? 'One or more dependency input formats/entries are unsupported; inspect details below.'
      : 'Only exact pinned versions from recognized lockfiles are queried after explicit OSV consent; reachability is not assessed.';
  return { check: 'dependencies', status, packagesDiscovered: discovered, packagesTested: tested, files: coverage,
    reason: summaryReason };
}
async function scanDependencies(files, { signal, options = {} } = {}) {
  const packages = []; const coverage = []; const locks = files.filter(isDependencyFile);
  for (const file of locks) parseLock(file, packages, coverage);
  detectManifestGaps(files, locks, coverage);
  if (signal?.aborted) throw Object.assign(new Error('Dependency scan cancelled.'), { name: 'AbortError' });
  if (options.allowAdvisoryNetwork !== true) {
    coverage.push({ check: 'dependencies', status: 'skipped', reason: packages.length ? 'OSV network lookup disabled; no advisory assessment performed.' : 'No exact package versions were queried.' });
    return { findings: [], coverage: summarize(coverage, packages.length, 0) };
  }
  const findings = []; let tested = 0; const fetcher = options.advisoryFetch || globalThis.fetch;
  for (const pkg of packages) {
    if (signal?.aborted) throw Object.assign(new Error('Dependency scan cancelled.'), { name: 'AbortError' });
    try {
      const response = await fetcher('https://api.osv.dev/v1/query', { method: 'POST', redirect: 'error', signal,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ package: { name: pkg.name, ecosystem: pkg.ecosystem }, version: pkg.version }) });
      if (!response.ok) throw new Error('OSV advisory request failed.');
      const data = await response.json(); if (!data || !Array.isArray(data.vulns || [])) throw new Error('OSV returned malformed advisories.');
      tested++;
      for (const advisory of data.vulns || []) findings.push(makeFinding({ check: 'dependencies', rule: 'osv-advisory', file: pkg.file,
        type: 'Dependency matches an OSV advisory', severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(advisory.database_specific?.severity) ? advisory.database_specific.severity : 'MEDIUM',
        explanation: `OSV advisory matched exact ${pkg.ecosystem} version; reachability/exploitability were not evaluated.`,
        fix: 'Review the advisory and upgrade to a compatible patched version; regenerate and verify the lockfile.',
        metadata: { package: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, location: pkg.location, direct: pkg.direct, dev: pkg.dev, advisory: String(advisory.id || 'OSV advisory').slice(0, 80) } }));
    } catch (error) {
      if (signal?.aborted || error.name === 'AbortError') throw error;
      issue(coverage, pkg, 'failed', `OSV query failed for ${pkg.ecosystem} package ${pkg.name}@${pkg.version}.`);
    }
  }
  coverage.push({ check: 'dependencies', status: 'tested', packagesDiscovered: packages.length, packagesTested: tested, reason: 'Exact locked package versions queried.' });
  return { findings, coverage: summarize(coverage, packages.length, tested) };
}
module.exports = { scanDependencies, inventory: files => { const packages = []; const coverage = []; const locks = files.filter(isDependencyFile); locks.forEach(file => parseLock(file, packages, coverage)); return { packages, coverage, locks: locks.map(file => file.path) }; } };
