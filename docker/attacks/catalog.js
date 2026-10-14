'use strict';

const injection =
  require('./catalog/injection');

const file =
  require('./catalog/file');

const accessControl =
  require('./catalog/access-control');

const web =
  require('./catalog/web');

const http =
  require('./catalog/http');

const exposure =
  require('./catalog/exposure');

const ATTACK_CATALOG = [
  ...injection,
  ...file,
  ...accessControl,
  ...web,
  ...http,
  ...exposure,
];

function getAttackCatalog() {
  return ATTACK_CATALOG.filter(
    attack =>
      attack.enabled !== false
  );
}

function getAttackDefinition(
  attackType
) {
  if (!attackType) {
    return null;
  }

  return (
    getAttackCatalog().find(
      attack =>
        attack.id ===
        attackType
    ) || null
  );
}

function getAttackIds() {
  return getAttackCatalog().map(
    attack =>
      attack.id
  );
}

module.exports = {
  ATTACK_CATALOG,
  getAttackCatalog,
  getAttackDefinition,
  getAttackIds,
};