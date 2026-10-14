'use strict';

const {
  getAttackDefinition,
} = require('./catalog');

function selectParameter(
  attackType,
  parameters
) {
  const definition =
    getAttackDefinition(
      attackType
    );

  const values =
    Array.isArray(parameters)
      ? parameters
      : [];

  if (
    !definition ||
    values.length === 0
  ) {
    return null;
  }

  const hints =
    Array.isArray(
      definition.parameterHints
    )
      ? definition.parameterHints
      : [];

  for (
    const hint of hints
  ) {
    const found =
      values.find(
        parameter =>
          String(parameter)
            .toLowerCase() ===
          String(hint)
            .toLowerCase()
      );

    if (found) {
      return found;
    }
  }

  return values[0];
}

function buildProjectRequest(
  attack,
  route
) {
  if (!route) {
    return null;
  }

  const parsed =
    new URL(route.url);

  const method =
    String(
      route.method ||
      'GET'
    ).toUpperCase();

  const parameter =
    selectParameter(
      attack.attackType,
      route.parameters
    );

  if (method === 'GET') {
    if (
      parameter &&
      attack.payload !== null &&
      attack.payload !== undefined
    ) {
      parsed.searchParams.set(
        parameter,
        attack.payload
      );
    }

    return {
      method: 'GET',
      path:
        parsed.pathname +
        parsed.search,
      parameter,
      headers: {},
    };
  }

  if (
    parameter &&
    attack.payload !== null &&
    attack.payload !== undefined
  ) {
    return {
      method,
      path:
        parsed.pathname +
        parsed.search,
      body:
        `${encodeURIComponent(
          parameter
        )}=${encodeURIComponent(
          attack.payload
        )}`,
      parameter,
      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded',
      },
    };
  }

  return {
    method,
    path:
      parsed.pathname +
      parsed.search,
    parameter: null,
    headers: {},
  };
}

function buildBaselineRequest(
  route
) {
  if (!route) {
    return null;
  }

  const parsed =
    new URL(route.url);

  return {
    method:
      String(
        route.method ||
        'GET'
      ).toUpperCase(),
    path:
      parsed.pathname +
      parsed.search,
    headers: {},
  };
}

module.exports = {
  selectParameter,
  buildProjectRequest,
  buildBaselineRequest,
};