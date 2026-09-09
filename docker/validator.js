'use strict';

function validateAttacks(
  findings,
  attacks
) {
  return findings.map(
    finding => {
      const related =
        attacks.filter(
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
        return {
          findingId:
            finding.id,
          result:
            'confirmed',
          confidence: 95,
          rationale:
            'Controlled runtime validation reproduced the vulnerable behaviour.',
          attackId:
            confirmed.id,
        };
      }

      const failed =
        related.find(
          attack =>
            attack.status ===
            'failed'
        );

      if (failed) {
        return {
          findingId:
            finding.id,
          result:
            'inconclusive',
          confidence: 40,
          rationale:
            'The runtime validator failed before producing sufficient evidence.',
          attackId:
            failed.id,
        };
      }

      return {
        findingId:
          finding.id,
        result:
          'not_reproduced',
        confidence: 70,
        rationale:
          'The controlled runtime test did not reproduce the vulnerable behaviour.',
      };
    }
  );
}

module.exports = {
  validateAttacks,
};