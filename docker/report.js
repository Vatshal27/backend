'use strict';

const { validateAttacks, provenanceFor, executionState } = require('./validator');
const { redact } = require('../security/redact');

function createCoverage(attacks = []) {
  const coverage = { total: attacks.length, planned: attacks.length, executed: 0, skipped: 0, failed: 0,
    unknown: 0, notApplicable: 0, synthetic: 0, projectExecuted: 0, scope: 'recorded-probes' };
  const byAttackType = new Map();
  for (const attack of attacks) {
    const state = executionState(attack);
    if (state === 'failed') coverage.failed += 1;
    else if (state === 'skipped') coverage.skipped += 1;
    else if (state === 'unknown') coverage.unknown += 1;
    else coverage.executed += 1;
    if (attack.runtimeVerdict === 'not_applicable' || attack.notApplicable === true) coverage.notApplicable++;
    if (attack.provenance?.synthetic || attack.synthetic) coverage.synthetic += 1;
    else if (state === 'executed' && attack.provenance?.mode === 'project-validation') coverage.projectExecuted += 1;
    const type = String(attack.attackType || 'unknown');
    const row = byAttackType.get(type) || { attackType: type, planned: 0, executed: 0, skipped: 0, failed: 0, unknown: 0, notApplicable: 0 };
    row.planned++;
    row[state]++;
    if (attack.runtimeVerdict === 'not_applicable' || attack.notApplicable === true) row.notApplicable++;
    byAttackType.set(type, row);
  }
  coverage.byAttackType = [...byAttackType.values()];
  return coverage;
}

function createContainers(
  containers = {}
) {
  const result = [];

  if (
    containers.target
  ) {
    result.push({
      id:
        containers.target.id ||
        '',
      role:
        'target',
      status:
        'running',
    });
  }

  if (
    containers.attacker
  ) {
    result.push({
      id:
        containers.attacker.id ||
        '',
      role:
        'attacker',
      status:
        'completed',
    });
  }

  if (
    containers.scanner
  ) {
    result.push({
      id:
        containers.scanner.id ||
        '',
      role:
        'scanner',
      status:
        'completed',
    });
  }

  return result;
}

function splitFindings(
  findings = []
) {
  const staticFindings = [];
  const aiFindings = [];

  for (
    const finding of
      findings
  ) {
    const source =
      String(
        finding?.source ||
        finding?.origin ||
        ''
      ).toLowerCase();

    if (
      source === 'ai' ||
      source === 'llm'
    ) {
      aiFindings.push(
        finding
      );
    } else {
      staticFindings.push(
        finding
      );
    }
  }

  return {
    staticFindings,
    aiFindings,
  };
}

function createExposures(
  attacks = []
) {
  const exposures = [];

  for (
    const attack of attacks
  ) {
    const items =
      Array.isArray(
        attack?.sensitiveData
      )
        ? attack.sensitiveData
        : [];

    for (
      const item of items
    ) {
      exposures.push({
        id:
          item.id ||
          null,
        attackId:
          attack.id ||
          null,
        endpoint:
          attack.request?.url ||
          attack.target ||
          null,
        category:
          item.category ||
          'sensitive_data',
        dataType:
          item.dataType ||
          'Sensitive Data',
        maskedValue:
          item.maskedValue ||
          '[REDACTED]',
        valueLength: item.valueLength || null,
        location: item.location || null,
        fieldPath: item.fieldPath || null,
        verdict:
          'observed_exposure',
      });
    }
  }

  return exposures;
}

function createSummary(
  findings = [],
  validations = [],
  attacks = [],
  exposures = [],
  startedAt,
  finishedAt
) {
  const safeFindings =
    Array.isArray(
      findings
    )
      ? findings
      : [];

  const safeValidations =
    Array.isArray(
      validations
    )
      ? validations
      : [];

  const safeAttacks =
    Array.isArray(
      attacks
    )
      ? attacks
      : [];

  const safeExposures =
    Array.isArray(
      exposures
    )
      ? exposures
      : [];

  const confirmed =
    safeValidations.filter(
      item =>
        item?.projectConfirmed === true
    ).length;

  const inconclusive =
    safeValidations.filter(
      item =>
        item?.result ===
        'inconclusive'
    ).length;

  const notReproduced =
    safeValidations.filter(
      item =>
        item?.result ===
        'not_reproduced'
    ).length;

  const observedExposures = safeValidations.filter(item => item?.result === 'observed_exposure').length;
  const observedSensitiveData = safeExposures.length;

  const runtimeFailed =
    safeAttacks.filter(
      item =>
        item?.status ===
        'failed'
    ).length;

  const notApplicable = safeValidations.filter(item => item?.result === 'not_applicable').length;
  const executedCount = safeAttacks.filter(item => executionState(item) === 'executed').length;
  const skippedCount = safeAttacks.filter(item => executionState(item) === 'skipped').length;

  const startTime =
    startedAt
      ? new Date(
          startedAt
        ).getTime()
      : null;

  const finishTime =
    finishedAt
      ? new Date(
          finishedAt
        ).getTime()
      : null;

  const durationMs =
    Number.isFinite(
      startTime
    ) &&
    Number.isFinite(
      finishTime
    )
      ? finishTime -
        startTime
      : null;

  return {
    findings:
      safeFindings.length,
    tested:
      executedCount,
    confirmed,
    syntheticConfirmed: safeValidations.filter(item => item.result === 'confirmed' && item.provenance?.synthetic).length,
    observedExposures,
    observedSensitiveData,
    inconclusive,
    notReproduced,
    runtimeTests:
      executedCount,
    runtimeFailed,
    notApplicable,
    executed: executedCount,
    skipped: skippedCount,
    unknown: safeAttacks.filter(item => executionState(item) === 'unknown').length,
    durationMs,
  };
}

function buildReport({
  sandboxId = null,
  mode = null,
  startedAt = null,
  finishedAt = null,
  target = null,
  containers = {},
  events = [],
  attacks = [],
  validations = [],
  findings = [],
  project = null,
} = {}) {
  const safeFindings =
    Array.isArray(
      findings
    )
      ? findings
      : [];

  const safeEvents =
    Array.isArray(
      events
    )
      ? events
      : [];

  const safeAttacks =
    Array.isArray(
      attacks
    )
      ? attacks.map(attack => ({ ...attack, provenance: provenanceFor(attack, mode) }))
      : [];

  // Re-derive verdicts from probes instead of trusting caller-supplied summaries.
  const safeValidations = validateAttacks(safeFindings, safeAttacks).map((validation, index) => ({
    ...validation,
    execution: safeAttacks[index] ? executionState(safeAttacks[index]) : 'unknown',
  }));

  const {
    staticFindings,
    aiFindings,
  } =
    splitFindings(
      safeFindings
    );

  const exposures =
    createExposures(
      safeAttacks
    );

  const summary =
    createSummary(
      safeFindings,
      safeValidations,
      safeAttacks,
      exposures,
      startedAt,
      finishedAt
    );

  return redact({
    schemaVersion:
      '1.1',
    provenance: provenanceFor({}, mode),
    coverage: createCoverage(safeAttacks),
    sandboxId,
    mode,
    startedAt,
    finishedAt,
    project,
    target,
    containers:
      createContainers(
        containers
      ),
    findings:
      safeFindings,
    staticFindings,
    aiFindings,
    exposures,
    runtime: {
      attacks:
        safeAttacks,
      validations:
        safeValidations,
      confirmedVulnerabilities:
        safeValidations.filter(
          item =>
            item?.projectConfirmed === true
        ),
      observedExposures:
        exposures,
      inconclusiveFindings:
        safeValidations.filter(
          item =>
            item?.result ===
            'inconclusive'
        ),
      failedTests:
        safeAttacks.filter(
          item =>
            item?.status ===
            'failed'
        ),
    },
    events:
      safeEvents,
    attacks:
      safeAttacks,
    validations:
      safeValidations,
    summary,
  });
}

module.exports = {
  createCoverage,
  buildReport,
  createSummary,
  createExposures,
  splitFindings,
};