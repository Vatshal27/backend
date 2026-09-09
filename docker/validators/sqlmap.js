'use strict';

async function validate(
  finding,
  context
) {
  return {
    findingId:
      finding.id,
    validator:
      'sqlmap',
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