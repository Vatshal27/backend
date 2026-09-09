'use strict';

async function validate(
  finding,
  context
) {
  return {
    findingId:
      finding.id,
    validator:
      'custom',
    status:
      'inconclusive',
    target:
      context.target,
    evidence: [],
  };
}

module.exports = {
  validate,
};