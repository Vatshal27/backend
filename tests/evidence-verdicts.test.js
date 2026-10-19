'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validateAttacks } = require('../docker/validator');

const supportedAttack = (overrides = {}) => ({
  id: 'probe-1', findingId: 'finding-1', attackType: 'sqli',
  status: 'success', runtimeVerdict: 'confirmed', executed: true,
  rationale: 'Differential database error absent from baseline.',
  response: { statusCode: 500, body: 'SQL syntax error' },
  evidence: [{ type: 'response', content: 'SQL syntax error' }],
  ...overrides,
});

test('transport success is not a security verdict; explicit confirmation needs runtime evidence', () => {
  for (const attack of [
    { id: 'generic', status: 'success' },
    supportedAttack({ evidence: [] }),
    supportedAttack({ response: null }),
    supportedAttack({ executed: false }),
  ]) {
    assert.equal(validateAttacks([], [attack])[0].result, 'inconclusive');
  }
  assert.equal(validateAttacks([], [supportedAttack()])[0].result, 'confirmed');
  assert.equal(validateAttacks([], [{ status: 'failed' }])[0].result, 'failed');
});

test('simulation provenance separates scanner self-tests from project confirmation', () => {
  const { buildReport } = require('../docker/report');
  const { compileReports } = require('../docker/reporting/compiler');
  const simulation = buildReport({ mode: 'simulation', attacks: [supportedAttack()] });
  assert.equal(simulation.summary.confirmed, 0);
  assert.equal(simulation.summary.syntheticConfirmed, 1);
  assert.equal(simulation.validations[0].provenance.synthetic, true);
  assert.equal(simulation.validations[0].projectConfirmed, false);
  const project = buildReport({ mode: 'project-validation', attacks: [
    supportedAttack({ id: 'synthetic', synthetic: true }),
    supportedAttack({ id: 'real' }),
    { id: 'skip', runtimeVerdict: 'not_applicable', executed: false },
    { id: 'broken', status: 'failed' },
    { id: 'unknown', status: 'success' },
  ] });
  assert.equal(project.summary.confirmed, 1);
  assert.equal(project.summary.tested, 2);
  assert.equal(project.summary.runtimeTests, 2);
  assert.equal(project.summary.notApplicable, 1);
  assert.equal(project.summary.skipped, 1);
  assert.equal(project.summary.observedExposures, 0);
  assert.equal(project.runtime.confirmedVulnerabilities.length, 1);
  assert.deepEqual(project.coverage, {
    total: 5, planned: 5, executed: 2, skipped: 1, failed: 1, unknown: 1, notApplicable: 1,
    synthetic: 1, projectExecuted: 1, scope: 'recorded-probes',
  });
  const compiled = compileReports({ simulationReport: simulation, projectReport: project });
  assert.equal(compiled.summary.confirmed, 1);
  assert.equal(compiled.selfTest.detected, 1);
  assert.deepEqual(compiled.coverage, project.coverage);
  assert.deepEqual(compiled.projectValidation.coverage, project.coverage);
  assert.equal(compileReports({ simulationReport: simulation }).summary.confirmed, 0);
});

test('executed cookie probe with no cookie is not applicable, not a vulnerability-negative result', () => {
  const { buildReport } = require('../docker/report');
  const report = buildReport({ mode: 'project-validation', attacks: [{
    id: 'no-cookie', attackType: 'cookie_security', status: 'success', executed: true,
    response: { statusCode: 200, headers: {}, body: '' },
    runtimeVerdict: 'not_applicable', rationale: 'The tested response did not set a cookie.',
  }] });
  assert.equal(report.validations[0].execution, 'executed');
  assert.equal(report.validations[0].result, 'not_applicable');
  assert.equal(report.summary.tested, 1);
  assert.equal(report.summary.notApplicable, 1);
  assert.equal(report.summary.notReproduced, 0);
});

test('generic project validation skips authentication bypass without verified identity context', async () => {
  const { prepareProject } = require('../docker/runner');
  const plan = { id: 'auth', attackType: 'auth_bypass', attackName: 'Authentication Bypass', route: '/', request: { method: 'GET', url: 'http://127.0.0.1:8080/' } };
  const result = prepareProject([], [plan], []);
  assert.equal(result.prepared.length, 0);
  assert.equal(result.skipped[0].runtimeVerdict, 'not_applicable');
  assert.match(result.skipped[0].rationale, /trusted application context/i);
});
