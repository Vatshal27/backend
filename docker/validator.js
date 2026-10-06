'use strict';
function resultFromAttack(
  attack
) {
  if (
    attack.status ===
    'success'
  ) {
    return {
      findingId:
        attack.findingId ||
        null,
      source:
        String(
          attack.findingId ||
          ''
        ).startsWith(
          'runtime-'
        )
          ? 'runtime'
          : 'correlated',
      attackType:
        attack.attackType,
      result:
        'confirmed',
      confidence:
        95,
      rationale:
        'Runtime testing reproduced behavior matching the vulnerability signal.',
      attackId:
        attack.id,
    };
  }
  if (
    attack.status ===
    'failed'
  ) {
    return {
      findingId:
        attack.findingId ||
        null,
      source:
        String(
          attack.findingId ||
          ''
        ).startsWith(
          'runtime-'
        )
          ? 'runtime'
          : 'correlated',
      attackType:
        attack.attackType,
      result:
        'inconclusive',
      confidence:
        40,
      rationale:
        'The runtime test failed before sufficient evidence was produced.',
      attackId:
        attack.id,
    };
  }
  return {
    findingId:
      attack.findingId ||
      null,
    source:
      String(
        attack.findingId ||
        ''
      ).startsWith(
        'runtime-'
      )
        ? 'runtime'
        : 'correlated',
    attackType:
      attack.attackType,
    result:
      'inconclusive',
    confidence:
      50,
    rationale:
      'The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.',
    attackId:
      attack.id,
  };
}
function validateAttacks(
  findings,
  attacks
) {
  const safeFindings =
    Array.isArray(findings)
      ? findings
      : [];
  const safeAttacks =
    Array.isArray(attacks)
      ? attacks
      : [];
  const validations = [];
  const processedAttacks =
    new Set();
  for (
    const finding of safeFindings
  ) {
    const related =
      safeAttacks.filter(
        attack =>
          attack.findingId ===
          finding.id
      );
    const confirmed =
      related.find(
        attack =>
          attack.status ===
          'success'
      );
    if (confirmed) {
      validations.push({
        findingId:
          finding.id,
        source:
          'correlated',
        attackType:
          confirmed.attackType,
        result:
          'confirmed',
        confidence:
          95,
        rationale:
          'Controlled runtime validation reproduced the vulnerable behaviour.',
        attackId:
          confirmed.id,
      });
      processedAttacks.add(
        confirmed.id
      );
      continue;
    }
    const failed =
      related.find(
        attack =>
          attack.status ===
          'failed'
      );
    if (failed) {
      validations.push({
        findingId:
          finding.id,
        source:
          'correlated',
        attackType:
          failed.attackType,
        result:
          'inconclusive',
        confidence:
          40,
        rationale:
          'The runtime validator failed before producing sufficient evidence.',
        attackId:
          failed.id,
      });
      processedAttacks.add(
        failed.id
      );
      continue;
    }
    if (
      related.length > 0
    ) {
      const attack =
        related[0];
      validations.push({
        findingId:
          finding.id,
        source:
          'correlated',
        attackType:
          attack.attackType,
        result:
          'not_reproduced',
        confidence:
          70,
        rationale:
          'The controlled runtime test did not reproduce the vulnerable behaviour.',
        attackId:
          attack.id,
      });
      processedAttacks.add(
        attack.id
      );
    } else {
      validations.push({
        findingId:
          finding.id,
        source:
          'static',
        attackType:
          null,
        result:
          'not_reproduced',
        confidence:
          70,
        rationale:
          'No runtime attack produced evidence for this finding.',
        attackId:
          null,
      });
    }
  }
  for (
    const attack of safeAttacks
  ) {
    if (
      processedAttacks.has(
        attack.id
      )
    ) {
      continue;
    }
    validations.push(
      resultFromAttack(
        attack
      )
    );
  }
  return validations;
}
module.exports = {
  validateAttacks,
};