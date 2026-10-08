'use strict';

function attackSource(
  attack
) {
  return String(
    attack?.findingId ||
    ''
  ).startsWith(
    'runtime-'
  )
    ? 'runtime'
    : 'correlated';
}

function routeLooksProtected(
  attack
) {
  if (
    attack?.attackType !==
    'auth_bypass'
  ) {
    return true;
  }

  const requestUrl =
    attack?.request?.url;

  if (
    !requestUrl
  ) {
    return false;
  }

  let pathname;

  try {
    pathname =
      new URL(
        requestUrl
      ).pathname.toLowerCase();
  } catch {
    return false;
  }

  if (
    pathname === '/' ||
    pathname === ''
  ) {
    return false;
  }

  const protectedKeywords = [
    '/admin',
    '/dashboard',
    '/account',
    '/profile',
    '/manage',
    '/management',
    '/settings',
    '/private',
    '/secure',
    '/internal',
    '/users',
    '/user/',
  ];

  return protectedKeywords.some(
    keyword =>
      pathname.includes(
        keyword
      )
  );
}

function attackConfirmed(
  attack
) {
  if (
    attack?.status !==
    'success'
  ) {
    return false;
  }

  if (
    attack.attackType ===
    'auth_bypass'
  ) {
    return routeLooksProtected(
      attack
    );
  }

  return true;
}

function resultFromAttack(
  attack
) {
  if (
    attackConfirmed(
      attack
    )
  ) {
    return {
      findingId:
        attack.findingId ||
        null,
      source:
        attackSource(
          attack
        ),
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
    attack?.status ===
      'success' &&
    attack?.attackType ===
      'auth_bypass'
  ) {
    return {
      findingId:
        attack.findingId ||
        null,
      source:
        attackSource(
          attack
        ),
      attackType:
        attack.attackType,
      result:
        'inconclusive',
      confidence:
        45,
      rationale:
        'The tested route returned successfully, but it was not identified as a protected resource, so authentication bypass cannot be confirmed.',
      attackId:
        attack.id,
    };
  }

  if (
    attack?.status ===
    'failed'
  ) {
    return {
      findingId:
        attack.findingId ||
        null,
      source:
        attackSource(
          attack
        ),
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
      attack?.findingId ||
      null,
    source:
      attackSource(
        attack
      ),
    attackType:
      attack?.attackType ||
      null,
    result:
      'inconclusive',
    confidence:
      50,
    rationale:
      'The runtime test completed but did not produce sufficient evidence to confirm the vulnerability.',
    attackId:
      attack?.id ||
      null,
  };
}

function createExposureValidation(
  attack,
  exposure,
  index
) {
  return {
    findingId:
      `runtime-exposure-${index}`,
    source:
      'runtime',
    attackType:
      'data_exposure',
    result:
      'observed_exposure',
    confidence:
      90,
    rationale:
      `${exposure.dataType} was observed in the runtime response. The stored evidence has been redacted.`,
    attackId:
      attack.id,
    exposure: {
      category:
        exposure.category,
      dataType:
        exposure.dataType,
      maskedValue:
        exposure.maskedValue,
    },
  };
}

function validateAttacks(
  findings,
  attacks
) {
  const safeFindings =
    Array.isArray(
      findings
    )
      ? findings
      : [];

  const safeAttacks =
    Array.isArray(
      attacks
    )
      ? attacks
      : [];

  const validations = [];

  const processedAttacks =
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

    const confirmed =
      related.find(
        attack =>
          attackConfirmed(
            attack
          )
      );

    if (
      confirmed
    ) {
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

    if (
      failed
    ) {
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

      const validation =
        resultFromAttack(
          attack
        );

      validations.push({
        ...validation,
        findingId:
          finding.id,
        source:
          'correlated',
        result:
          validation.result ===
          'confirmed'
            ? 'confirmed'
            : 'not_reproduced',
        confidence:
          validation.result ===
          'confirmed'
            ? validation.confidence
            : 70,
        rationale:
          validation.result ===
          'confirmed'
            ? validation.rationale
            : 'The controlled runtime test did not reproduce the vulnerable behaviour.',
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
    const attack of
      safeAttacks
  ) {
    if (
      !processedAttacks.has(
        attack.id
      )
    ) {
      validations.push(
        resultFromAttack(
          attack
        )
      );
    }
  }

  let exposureIndex = 1;

  for (
    const attack of
      safeAttacks
  ) {
    const exposures =
      Array.isArray(
        attack.sensitiveData
      )
        ? attack.sensitiveData
        : [];

    for (
      const exposure of
        exposures
    ) {
      validations.push(
        createExposureValidation(
          attack,
          exposure,
          exposureIndex
        )
      );

      exposureIndex +=
        1;
    }
  }

  return validations;
}

module.exports = {
  validateAttacks,
};