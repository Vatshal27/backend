'use strict';

function normalizeEvidence(
  attacks
) {
  return attacks.map(
    attack => ({
      ...attack,

      evidence:
        Array.isArray(
          attack.evidence
        )
          ? attack.evidence
          : [],
    })
  );
}

function createEvidenceEvent(
  attacks
) {
  const count =
    attacks.reduce(
      (total, attack) =>
        total +
        (
          Array.isArray(
            attack.evidence
          )
            ? attack.evidence.length
            : 0
        ),
      0
    );

  return {
    evidenceCount: count,
    attackCount:
      attacks.length,
  };
}

module.exports = {
  normalizeEvidence,
  createEvidenceEvent,
};