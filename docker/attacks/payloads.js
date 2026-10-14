'use strict';

const { getAttackDefinition } = require('./catalog');

function normalizePayloads(payloads) {
  if (!Array.isArray(payloads)) {
    return [];
  }

  return payloads.filter(
    payload =>
      typeof payload === 'string' &&
      payload.length > 0
  );
}

function getFindingPayloads(finding) {
  return normalizePayloads(
    finding?.attackPayloads
  );
}

function getCatalogPayloads(attackType) {
  const definition =
    getAttackDefinition(attackType);

  return normalizePayloads(
    definition?.payloads
  );
}

function buildPayloadVariants(
  finding,
  attackType
) {
  const findingPayloads =
    getFindingPayloads(finding);

  if (findingPayloads.length > 0) {
    return findingPayloads;
  }

  return getCatalogPayloads(
    attackType
  );
}

function buildPrimaryPayload(
  finding,
  attackType
) {
  return (
    buildPayloadVariants(
      finding,
      attackType
    )[0] || null
  );
}

module.exports = {
  getFindingPayloads,
  getCatalogPayloads,
  buildPayloadVariants,
  buildPrimaryPayload,
};