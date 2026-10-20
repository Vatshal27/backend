'use strict';

const {
  getAttackCatalog,
  getAttackDefinition,
} = require(
  './attacks/catalog'
);

const {
  classifyFinding,
  validatorForType,
} = require(
  './attacks/classifier'
);

function normalizeTargetUrl(
  targetUrl
) {
  if (!targetUrl) {
    return null;
  }

  return new URL(
    targetUrl
  ).toString();
}

function createRuntimeCatalogPlans(
  targetUrl
) {
  return getAttackCatalog().map(
    attack => ({
      findingId:
        `runtime-${attack.id}`,
      source:
        'runtime',
      attackType:
        attack.id,
      attackFamily:
        attack.family,
      attackName:
        attack.name,
      validator:
        attack.validator ||
        'custom',
      target:
        targetUrl,
      activeProbe:
        attack.activeProbe !==
        false,
      applicability:
        'pending',
    })
  );
}

function createFindingPlans(
  findings,
  targetUrl
) {
  const plans = [];

  for (
    const finding of
      Array.isArray(findings)
        ? findings
        : []
  ) {
    if (finding?.source === 'supplementary' && finding?.check === 'secrets') continue;

    const attackType =
      classifyFinding(
        finding
      );

    if (
      attackType ===
      'other'
    ) {
      continue;
    }

    const definition =
      getAttackDefinition(
        attackType
      );

    if (!definition) {
      continue;
    }

    plans.push({
      findingId:
        finding.id,
      source:
        'correlated',
      attackType,
      attackFamily:
        definition.family,
      attackName:
        definition.name,
      validator:
        validatorForType(
          attackType
        ),
      target:
        targetUrl,
      activeProbe:
        definition.activeProbe !==
        false,
      applicability:
        'pending',
    });
  }

  return plans;
}

function planKey(plan) {
  return [
    plan.source,
    plan.findingId,
    plan.attackType,
    plan.target,
  ].join('|');
}

function deduplicatePlans(
  plans
) {
  const unique = [];
  const seen =
    new Set();

  for (
    const plan of plans
  ) {
    const key =
      planKey(plan);

    if (
      seen.has(key)
    ) {
      continue;
    }

    seen.add(key);
    unique.push(plan);
  }

  return unique;
}

function createAttackPlan(
  findings,
  targetUrl
) {
  const target =
    normalizeTargetUrl(
      targetUrl
    );

  return deduplicatePlans([
    ...createRuntimeCatalogPlans(
      target
    ),
    ...createFindingPlans(
      findings,
      target
    ),
  ]);
}

function createCategories(
  findings
) {
  const categories = {};

  for (
    const attack of
      getAttackCatalog()
  ) {
    categories[
      attack.id
    ] = [];
  }

  categories.other = [];

  for (
    const finding of
      Array.isArray(findings)
        ? findings
        : []
  ) {
    const attackType =
      classifyFinding(
        finding
      );

    if (
      !categories[
        attackType
      ]
    ) {
      categories[
        attackType
      ] = [];
    }

    categories[
      attackType
    ].push(
      finding
    );
  }

  return categories;
}

module.exports = {
  createAttackPlan,
  createCategories,
};