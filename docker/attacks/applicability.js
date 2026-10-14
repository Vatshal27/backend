'use strict';

const {
  getAttackDefinition,
} = require('./catalog');

const SAFE_ACTIVE_METHODS =
  new Set([
    'GET',
  ]);

function normalize(value) {
  return String(
    value || ''
  ).toLowerCase();
}

function routeParameters(route) {
  return Array.isArray(
    route?.parameters
  )
    ? route.parameters
    : [];
}

function routeText(route) {
  return [
    route?.url,
    ...routeParameters(route),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function catalogAllowsMethod(
  definition,
  method
) {
  if (
    !Array.isArray(
      definition?.methods
    ) ||
    definition.methods.length === 0
  ) {
    return true;
  }

  return definition.methods.includes(
    String(method || 'GET')
      .toUpperCase()
  );
}

function parameterMatches(
  definition,
  route
) {
  const hints =
    Array.isArray(
      definition?.parameterHints
    )
      ? definition.parameterHints
      : [];

  if (hints.length === 0) {
    return false;
  }

  return routeParameters(
    route
  ).some(
    parameter =>
      hints.some(
        hint =>
          normalize(parameter) ===
          normalize(hint)
      )
  );
}

function routeHintMatches(
  definition,
  route
) {
  const hints =
    Array.isArray(
      definition?.routeHints
    )
      ? definition.routeHints
      : [];

  if (hints.length === 0) {
    return false;
  }

  const text =
    routeText(route);

  return hints.some(
    hint =>
      text.includes(
        normalize(hint)
      )
  );
}

function routeIsApplicable(
  attackType,
  route,
  options = {}
) {
  const {
    allowMutationMethods = false,
  } = options;

  const definition =
    getAttackDefinition(
      attackType
    );

  if (
    !definition ||
    !route
  ) {
    return false;
  }

  const method =
    String(
      route.method ||
      'GET'
    ).toUpperCase();

  if (
    !catalogAllowsMethod(
      definition,
      method
    )
  ) {
    return false;
  }

  if (
    definition.activeProbe !==
    false &&
    !allowMutationMethods &&
    !SAFE_ACTIVE_METHODS.has(
      method
    )
  ) {
    return false;
  }

  if (
    attackType ===
    'auth_bypass'
  ) {
    return routeHintMatches(
      definition,
      route
    );
  }

  const hints =
    Array.isArray(
      definition.parameterHints
    )
      ? definition.parameterHints
      : [];

  if (hints.length > 0) {
    return (
      parameterMatches(
        definition,
        route
      ) ||
      routeHintMatches(
        definition,
        route
      )
    );
  }

  return true;
}

function scoreRoute(
  attackType,
  route,
  options = {}
) {
  const definition =
    getAttackDefinition(
      attackType
    );

  if (
    !definition ||
    !routeIsApplicable(
      attackType,
      route,
      options
    )
  ) {
    return -1;
  }

  let score = 0;
  const text =
    routeText(route);

  for (
    const hint of
      definition.parameterHints || []
  ) {
    if (
      text.includes(
        normalize(hint)
      )
    ) {
      score += 3;
    }
  }

  for (
    const hint of
      definition.routeHints || []
  ) {
    if (
      text.includes(
        normalize(hint)
      )
    ) {
      score += 4;
    }
  }

  if (
    routeParameters(
      route
    ).length > 0
  ) {
    score += 3;
  }

  if (
    route.source === 'form'
  ) {
    score += 4;
  }

  if (
    route.source === 'root'
  ) {
    score -= 2;
  }

  return score;
}

function chooseApplicableRoute(
  attackType,
  routes,
  options = {}
) {
  let best = null;
  let bestScore = -1;

  for (
    const route of
      Array.isArray(routes)
        ? routes
        : []
  ) {
    const score =
      scoreRoute(
        attackType,
        route,
        options
      );

    if (score > bestScore) {
      best = route;
      bestScore = score;
    }
  }

  return best;
}

module.exports = {
  routeIsApplicable,
  scoreRoute,
  chooseApplicableRoute,
};