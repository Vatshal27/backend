'use strict';

async function validate(
  finding,
  context
) {
  return {
    findingId:
      finding.id,
    validator:
      'nuclei',
    status:
      'queued',
    target:
      context.target,
    evidence: [],
  };
}

module.exports = {
  validate,
};