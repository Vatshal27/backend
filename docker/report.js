'use strict';
function createContainers(
  containers = {}
) {
  const result = [];
  if (containers.target) {
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
  if (containers.attacker) {
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
  if (containers.scanner) {
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
    const finding of findings
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
function createSummary(
  findings = [],
  validations = [],
  attacks = [],
  startedAt,
  finishedAt
) {
  const safeFindings =
    Array.isArray(findings)
      ? findings
      : [];
  const safeValidations =
    Array.isArray(validations)
      ? validations
      : [];
  const safeAttacks =
    Array.isArray(attacks)
      ? attacks
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
  const runtimeSuccessful =
    safeAttacks.filter(
      item =>
        item?.status ===
        'success'
    ).length;
  const runtimeInconclusive =
    safeAttacks.filter(
      item =>
        item?.status ===
        'inconclusive'
    ).length;
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
      safeValidations.length,
    confirmed,
    inconclusive,
    notReproduced,
    runtimeTests:
      safeAttacks.length,
    runtimeSuccessful,
    runtimeInconclusive,
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
} = {}) {
  const safeFindings =
    Array.isArray(findings)
      ? findings
      : [];
  const safeEvents =
    Array.isArray(events)
      ? events
      : [];
  const safeAttacks =
    Array.isArray(attacks)
      ? attacks
      : [];
  const safeValidations =
    Array.isArray(validations)
      ? validations
      : [];
  const {
    staticFindings,
    aiFindings,
  } =
    splitFindings(
      safeFindings
    );
  return {
    sandboxId,
    mode,
    startedAt,
    finishedAt,
    target,
    containers:
      createContainers(
        containers
      ),
    findings:
      safeFindings,
    staticFindings,
    aiFindings,
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
    summary:
      createSummary(
        safeFindings,
        safeValidations,
        safeAttacks,
        startedAt,
        finishedAt
      ),
  };
}
module.exports = {
  buildReport,
};