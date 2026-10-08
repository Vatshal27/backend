'use strict';

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
        item?.result ===
        'confirmed'
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

  const observedExposures =
    safeExposures.length;

  const runtimeFailed =
    safeAttacks.filter(
      item =>
        item?.status ===
        'failed'
    ).length;

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
      safeAttacks.length,
    confirmed,
    observedExposures,
    inconclusive,
    notReproduced,
    runtimeTests:
      safeAttacks.length,
    runtimeFailed,
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
      ? attacks
      : [];

  const safeValidations =
    Array.isArray(
      validations
    )
      ? validations
      : [];

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

  return {
    schemaVersion:
      '1.1',
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
            item?.result ===
            'confirmed'
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
  };
}

module.exports = {
  buildReport,
  createSummary,
  createExposures,
  splitFindings,
};