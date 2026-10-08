'use strict';

function clean(
  value
) {
  return String(
    value ?? ''
  )
    .replace(
      /\r?\n/g,
      ' '
    )
    .trim();
}

function safeName(
  value
) {
  return String(
    value ||
    ''
  )
    .trim()
    .replace(
      /[^a-z0-9_-]+/gi,
      '_'
    )
    .replace(
      /^_+|_+$/g,
      ''
    );
}

function formatAttackType(
  value
) {
  const names = {
    sqli:
      'SQL Injection',
    xss:
      'Cross-Site Scripting (XSS)',
    cmdi:
      'Command Injection',
    path_traversal:
      'Path Traversal',
    auth_bypass:
      'Authentication Bypass',
    code_injection:
      'Code Injection',
    data_exposure:
      'Sensitive Data Exposure',
  };

  return (
    names[value] ||
    clean(
      value ||
      'Runtime Check'
    )
  );
}

function formatVerdict(
  value,
  simulation = false
) {
  if (
    simulation &&
    value ===
      'confirmed'
  ) {
    return 'Detected';
  }

  const names = {
    confirmed:
      'Confirmed',
    inconclusive:
      'Inconclusive',
    not_reproduced:
      'Not Reproduced',
    observed_exposure:
      'Observed Exposure',
    failed:
      'Failed',
    success:
      'Successful',
  };

  return (
    names[value] ||
    clean(
      value ||
      'Unknown'
    )
  );
}

module.exports = {
  clean,
  safeName,
  formatAttackType,
  formatVerdict,
};