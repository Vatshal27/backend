'use strict';

function createContainers(
  state,
  config
) {
  const containers = [];

  if (state.targetContainer) {
    containers.push({
      id:
        state.targetContainer.id,
      name:
        state.names.target,
      role:
        'target',
      image:
        config.TARGET_IMAGE,
      status:
        'running',
    });
  }

  if (state.attackerContainer) {
    containers.push({
      id:
        state.attackerContainer.id,
      name:
        state.names.attacker,
      role:
        'attacker',
      image:
        config.ATTACK_IMAGE,
      status:
        'completed',
    });
  }

  return containers;
}

function createSummary(
  findings,
  validations,
  startedAt,
  finishedAt
) {
  const confirmed =
    validations.filter(
      item =>
        item.result ===
        'confirmed'
    ).length;

  const inconclusive =
    validations.filter(
      item =>
        item.result ===
        'inconclusive'
    ).length;

  const notReproduced =
    validations.filter(
      item =>
        item.result ===
        'not_reproduced'
    ).length;

  return {
    findings:
      findings.length,

    tested:
      validations.length,

    confirmed,

    inconclusive,

    notReproduced,

    durationMs:
      new Date(
        finishedAt
      ).getTime() -
      new Date(
        startedAt
      ).getTime(),
  };
}

function buildReport({
  sandboxId,
  mode,
  startedAt,
  finishedAt,
  target,
  state,
  events,
  attacks,
  validations,
  findings,
  config,
}) {
  return {
    sandboxId,
    mode,
    startedAt,
    finishedAt,

    target,

    containers:
      createContainers(
        state,
        config
      ),

    events,

    attacks,

    validations,

    summary:
      createSummary(
        findings,
        validations,
        startedAt,
        finishedAt
      ),
  };
}

module.exports = {
  buildReport,
};