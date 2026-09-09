'use strict';

function classifyFinding(finding) {
  const explicit = String(
    finding.attackType || ''
  )
    .toLowerCase()
    .trim();

  const aliases = {
    'sql-injection': 'sqli',
    'sql injection': 'sqli',
    'cross-site scripting': 'xss',
    'cross site scripting': 'xss',
    'command-injection': 'cmdi',
    'command injection': 'cmdi',
    'path traversal': 'path_traversal',
    'directory traversal': 'path_traversal',
    'authentication bypass': 'auth_bypass',
    'auth bypass': 'auth_bypass',
    'code injection': 'code_injection',
  };

  if (aliases[explicit]) {
    return aliases[explicit];
  }

  if (
    [
      'sqli',
      'xss',
      'cmdi',
      'path_traversal',
      'auth_bypass',
      'code_injection',
    ].includes(explicit)
  ) {
    return explicit;
  }

  const text = [
    finding.type,
    finding.explanation,
    finding.fix,
  ]
    .join(' ')
    .toLowerCase();

  if (
    /sql|database injection|query injection/.test(
      text
    )
  ) {
    return 'sqli';
  }

  if (
    /xss|cross.?site scripting|html injection/.test(
      text
    )
  ) {
    return 'xss';
  }

  if (
    /command injection|shell injection|child_process|exec/.test(
      text
    )
  ) {
    return 'cmdi';
  }

  if (
    /path traversal|directory traversal/.test(
      text
    )
  ) {
    return 'path_traversal';
  }

  if (
    /authentication bypass|unauthenticated|missing auth/.test(
      text
    )
  ) {
    return 'auth_bypass';
  }

  if (
    /eval|code injection/.test(
      text
    )
  ) {
    return 'code_injection';
  }

  return 'other';
}

function validatorForType(attackType) {
  if (attackType === 'sqli') {
    return 'sqlmap';
  }

  if (attackType === 'xss') {
    return 'zap';
  }

  return 'custom';
}

function createAttackPlan(
  findings,
  targetUrl
) {
  if (!targetUrl) {
    throw new Error(
      'A resolved project runtime URL is required to create an attack plan.'
    );
  }

  let parsedTarget;

  try {
    parsedTarget =
      new URL(targetUrl);
  } catch {
    throw new Error(
      `Invalid project runtime URL: ${targetUrl}`
    );
  }

  const normalizedTarget =
    parsedTarget
      .toString()
      .replace(/\/$/, '');

  return findings.map(
    finding => {
      const attackType =
        classifyFinding(
          finding
        );

      return {
        findingId:
          finding.id,
        attackType,
        validator:
          validatorForType(
            attackType
          ),
        target:
          normalizedTarget,
        rationale:
          `Runtime validation selected for ${
            finding.type ||
            attackType
          }.`,
      };
    }
  );
}

function createCategories(
  findings
) {
  const categories = {
    sqli: [],
    xss: [],
    cmdi: [],
    path_traversal: [],
    auth_bypass: [],
    code_injection: [],
    other: [],
  };

  for (
    const finding of findings
  ) {
    const type =
      classifyFinding(
        finding
      );

    if (!categories[type]) {
      categories[type] = [];
    }

    categories[type].push(
      finding
    );
  }

  return categories;
}

module.exports = {
  classifyFinding,
  createAttackPlan,
  createCategories,
};