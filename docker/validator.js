'use strict';

const VALID_VERDICTS =
  new Set([
    'confirmed',
    'observed_exposure',
    'not_reproduced',
    'inconclusive',
    'failed',
    'not_applicable',
  ]);

function asArray(value) {
  return Array.isArray(value)
    ? value
    : [];
}

function provenanceFor(attack = {}, mode = null) {
  const synthetic = mode === 'simulation' || attack.synthetic === true ||
    attack.simulation === true || attack.provenance?.synthetic === true ||
    attack.mode === 'simulation' || attack.provenance?.mode === 'simulation';
  return {
    mode: synthetic ? 'simulation' : (mode || attack.provenance?.mode || attack.mode || 'unknown'),
    synthetic,
    source: synthetic ? 'controlled-fixture' : 'runtime-probe',
  };
}

function executionState(attack = {}) {
  if (attack.status === 'failed' || attack.runtimeVerdict === 'failed') return 'failed';
  if (attack.executed === false || attack.execution === 'skipped') return 'skipped';
  if (attack.execution === 'executed') return 'executed';
  if (Number.isInteger(attack.response?.statusCode) && attack.response.statusCode >= 100 &&
      attack.response.statusCode <= 599) return 'executed';
  return 'unknown';
}

function attackSource(
  attack
) {
  if (
    attack?.source ===
      'runtime' ||
    attack?.source ===
      'correlated'
  ) {
    return attack.source;
  }

  return String(
    attack?.findingId ||
    ''
  ).startsWith(
    'runtime-'
  )
    ? 'runtime'
    : 'correlated';
}

function runtimeVerdict(
  attack
) {
  if (['confirmed', 'observed_exposure', 'not_reproduced'].includes(attack?.runtimeVerdict)) {
    const hasResponse = Number.isInteger(attack?.response?.statusCode) &&
      attack.response.statusCode >= 100 && attack.response.statusCode <= 599;
    const hasEvidence = asArray(attack.evidence).some(item =>
      item && ['response', 'finding', 'log'].includes(item.type) &&
      typeof item.content === 'string' && item.content.trim());
    if (attack.executed === false || !hasResponse || !hasEvidence || attack.status === 'failed') {
      return attack.status === 'failed' ? 'failed' : 'inconclusive';
    }
  }
  if (
    VALID_VERDICTS.has(
      attack?.runtimeVerdict
    )
  ) {
    return attack.runtimeVerdict;
  }


  if (
    attack?.status ===
    'failed'
  ) {
    return 'failed';
  }

  return 'inconclusive';
}

function defaultConfidence(
  verdict
) {
  switch (verdict) {
    case 'confirmed':
      return 95;

    case 'observed_exposure':
      return 85;

    case 'not_reproduced':
      return 70;

    case 'not_applicable':
    case 'failed':
      return 100;

    default:
      return 50;
  }
}

function defaultRationale(
  verdict
) {
  switch (verdict) {
    case 'confirmed':
      return (
        'Runtime evidence reproduced the supported vulnerability signal.'
      );

    case 'observed_exposure':
      return (
        'Runtime analysis observed a security-relevant exposure.'
      );

    case 'not_reproduced':
      return (
        'The runtime check executed but did not reproduce the supported security signal.'
      );

    case 'not_applicable':
      return (
        'The runtime check was not applicable with the currently available application context.'
      );

    case 'failed':
      return (
        'The runtime check failed before a security conclusion could be reached.'
      );

    default:
      return (
        'The runtime evidence was insufficient for a conclusive verdict.'
      );
  }
}

function validationFromAttack(
  attack
) {
  const verdict =
    runtimeVerdict(
      attack
    );

  const provenance = provenanceFor(attack);
  const execution = executionState(attack);

  return {
    provenance,
    execution,
    projectConfirmed: verdict === 'confirmed' && !provenance.synthetic && provenance.mode === 'project-validation',
    id:
      `validation-${
        attack.id ||
        Math.random()
          .toString(16)
          .slice(2)
      }`,

    findingId:
      attack.findingId ||
      null,

    attackId:
      attack.id ||
      null,

    source:
      attackSource(
        attack
      ),

    attackType:
      attack.attackType ||
      null,

    attackFamily:
      attack.attackFamily ||
      null,

    attackName:
      attack.attackName ||
      attack.attackType ||
      null,

    verdict,

    /*
     * Existing report/UI compatibility.
     */
    result:
      verdict,

    confidence:
      Number.isFinite(
        attack.confidence
      )
        ? attack.confidence
        : defaultConfidence(
            verdict
          ),

    rationale:
      attack.rationale ||
      defaultRationale(
        verdict
      ),

    evidence:
      asArray(
        attack.evidence
      ),

    request:
      attack.request ||
      null,

    response:
      attack.response ||
      null,

    payload:
      attack.payload ??
      null,

    executed: execution === 'executed',

    startedAt:
      attack.startedAt ||
      null,

    finishedAt:
      attack.finishedAt ||
      null,
  };
}

function priority(
  verdict
) {
  switch (verdict) {
    case 'confirmed':
      return 6;

    case 'observed_exposure':
      return 5;

    case 'inconclusive':
      return 4;

    case 'failed':
      return 3;

    case 'not_reproduced':
      return 2;

    case 'not_applicable':
      return 1;

    default:
      return 0;
  }
}

function strongestAttack(
  attacks
) {
  return (
    asArray(attacks)
      .slice()
      .sort(
        (
          a,
          b
        ) =>
          priority(
            runtimeVerdict(b)
          ) -
          priority(
            runtimeVerdict(a)
          )
      )[0] ||
    null
  );
}

function validationForFinding(
  finding,
  relatedAttacks
) {
  if (
    relatedAttacks.length ===
    0
  ) {
    return {
      id:
        `validation-${
          finding.id
        }`,

      findingId:
        finding.id,

      attackId:
        null,

      source:
        'correlated',

      attackType:
        finding.attackType ||
        finding.type ||
        null,

      verdict:
        'inconclusive',

      result:
        'inconclusive',

      confidence:
        35,

      rationale:
        'No applicable runtime probe was executed for this source finding.',

      evidence:
        [],
    };
  }

  const attack =
    strongestAttack(
      relatedAttacks
    );

  const validation =
    validationFromAttack(
      attack
    );

  return {
    ...validation,

    id:
      `validation-${
        finding.id
      }`,

    findingId:
      finding.id,

    source:
      'correlated',
  };
}

function validateAttacks(
  findings,
  attacks
) {
  const safeFindings =
    asArray(findings);

  const safeAttacks =
    asArray(attacks);

  const validations = [];

  const consumed =
    new Set();

  for (
    const finding of
      safeFindings
  ) {
    const related =
      safeAttacks.filter(
        attack =>
          attack.findingId ===
          finding.id
      );

    validations.push(
      validationForFinding(
        finding,
        related
      )
    );

    for (
      const attack of related
    ) {
      if (attack.id) {
        consumed.add(
          attack.id
        );
      }
    }
  }

  for (
    const attack of
      safeAttacks
  ) {
    if (
      attack.id &&
      consumed.has(
        attack.id
      )
    ) {
      continue;
    }

    validations.push(
      validationFromAttack(
        attack
      )
    );
  }

  return validations;
}

module.exports = {
  validateAttacks,
  provenanceFor,
  executionState,
};