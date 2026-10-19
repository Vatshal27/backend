'use strict';
const { scanSecrets, scanInfrastructure } = require('./checks');
const { scanDependencies } = require('./dependencies');

const CAPABILITIES = {
  source: { available: true, explanation: 'Existing static/AI source scanner; executed by the parent pipeline, not supplementary checks.' },
  dependencies: { available: true, explanation: 'Exact pinned versions from supported npm, PyPI requirements, Cargo.lock, Go.sum, Composer.lock, and Gemfile.lock inputs. Ecosystem/version ranges and unsupported manifest formats are reported. OSV lookups require explicit network consent.' },
  secrets: { available: true, explanation: 'Offline secret-pattern detection; candidates are redacted and are not validated with providers.' },
  infrastructure: { available: true, explanation: 'Offline Dockerfile and security-sensitive configuration heuristics, not deployment validation.' },
  authentication: { available: false, explanation: 'Unsupported: authentication testing needs identity, roles, sessions and application context; not implemented.' },
  api: { available: false, explanation: 'Unsupported: API testing needs endpoint specifications, authorization and a safe target context; not implemented.' },
  browser: { available: false, explanation: 'Unsupported: browser testing needs a running target and authenticated browser context; not implemented.' },
};
const PROFILES = {
  source: ['source'],
  dependencies: ['dependencies'],
  secrets: ['secrets'],
  infrastructure: ['infrastructure'],
  comprehensive: Object.keys(CAPABILITIES),
};

function getScanProfiles() {
  return Object.entries(PROFILES).map(([id, checks]) => ({
    id, name: id[0].toUpperCase() + id.slice(1),
    checks: checks.map(check => ({ id: check, ...CAPABILITIES[check] })),
  }));
}

async function runSupplementaryChecks({ files = [], profile = 'source', signal, onEvent, options = {} } = {}) {
  if (!Object.hasOwn(PROFILES, profile)) throw new TypeError('Unknown scan profile');
  if (signal?.aborted) throw Object.assign(new Error('Security checks cancelled.'), { name: 'AbortError' });
  const findings = [];
  const coverage = [];
  for (const check of PROFILES[profile]) {
    if (signal?.aborted) throw Object.assign(new Error('Security checks cancelled.'), { name: 'AbortError' });
    if (['secrets', 'infrastructure', 'dependencies'].includes(check)) {
      const result = check === 'dependencies' ? await scanDependencies(files, { signal, options })
        : check === 'secrets' ? scanSecrets(files) : scanInfrastructure(files);
      findings.push(...result.findings);
      coverage.push(result.coverage);
    } else {
      coverage.push({ check, status: check === 'source' ? 'skipped' : 'unsupported', reason: CAPABILITIES[check].explanation });
    }
    if (check === 'dependencies' && ['unsupported', 'inconclusive'].includes(coverage.at(-1).status)) {
      for (const detail of coverage.at(-1).files || []) {
        if (!coverage.includes(detail)) coverage.push(detail);
      }
    }
    if (onEvent) await onEvent({ type: 'check-completed', check, status: coverage.at(-1).status });
  }
  return { findings, coverage };
}

module.exports = { getScanProfiles, runSupplementaryChecks };
