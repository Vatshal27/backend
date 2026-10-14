'use strict';

const {
  getAttackCatalog,
  getAttackDefinition,
} = require('./catalog');

function normalizeText(
  value
) {
  return String(
    value || ''
  )
    .toLowerCase()
    .trim();
}

function classifyFinding(
  finding
) {
  const explicit =
    normalizeText(
      finding?.attackType
    );

  if (explicit) {
    const exact =
      getAttackDefinition(
        explicit
      );

    if (exact) {
      return exact.id;
    }

    for (
      const attack of
        getAttackCatalog()
    ) {
      if (
        attack.aliases.some(
          alias =>
            normalizeText(
              alias
            ) === explicit
        )
      ) {
        return attack.id;
      }
    }
  }

  const text =
    normalizeText(
      [
        finding?.type,
        finding?.title,
        finding?.category,
        finding?.explanation,
        finding?.fix,
        finding?.recommendation,
      ]
        .filter(Boolean)
        .join(' ')
    );

  if (!text) {
    return 'other';
  }

  for (
    const attack of
      getAttackCatalog()
  ) {
    if (
      attack.aliases.some(
        alias =>
          text.includes(
            normalizeText(
              alias
            )
          )
      )
    ) {
      return attack.id;
    }
  }

  return 'other';
}

function validatorForType(
  attackType
) {
  const attack =
    getAttackDefinition(
      attackType
    );

  return (
    attack?.validator ||
    'custom'
  );
}

module.exports = {
  classifyFinding,
  validatorForType,
};