'use strict';
function classifyFinding(finding) {
  const explicit =
    String(
      finding?.attackType ||
      ''
    )
      .toLowerCase()
      .trim();
  const aliases = {
    'sql-injection':
      'sqli',
    'sql injection':
      'sqli',
    'cross-site scripting':
      'xss',
    'cross site scripting':
      'xss',
    'command-injection':
      'cmdi',
    'command injection':
      'cmdi',
    'path traversal':
      'path_traversal',
    'directory traversal':
      'path_traversal',
    'authentication bypass':
      'auth_bypass',
    'auth bypass':
      'auth_bypass',
    'code injection':
      'code_injection',
  };
  if (
    aliases[
      explicit
    ]
  ) {
    return aliases[
      explicit
    ];
  }
  if (
    [
      'sqli',
      'xss',
      'cmdi',
      'path_traversal',
      'auth_bypass',
      'code_injection',
    ].includes(
      explicit
    )
  ) {
    return explicit;
  }
  const text = [
    finding?.type,
    finding?.explanation,
    finding?.fix,
  ]
    .filter(Boolean)
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
function validatorForType(
  attackType
) {
  if (
    attackType ===
    'sqli'
  ) {
    return 'sqlmap';
  }
  if (
    attackType ===
    'xss'
  ) {
    return 'zap';
  }
  return 'custom';
}
function createGenericPlans(
  normalizedTarget
) {
  return [
    {
      findingId:
        'runtime-sqli',
      attackType:
        'sqli',
      validator:
        'runtime-generic',
      target:
        normalizedTarget,
      rationale:
        'Generic runtime SQL injection probe.',
    },
    {
      findingId:
        'runtime-xss',
      attackType:
        'xss',
      validator:
        'runtime-generic',
      target:
        normalizedTarget,
      rationale:
        'Generic runtime reflected XSS probe.',
    },
    {
      findingId:
        'runtime-cmdi',
      attackType:
        'cmdi',
      validator:
        'runtime-generic',
      target:
        normalizedTarget,
      rationale:
        'Generic runtime command injection probe.',
    },
    {
      findingId:
        'runtime-path-traversal',
      attackType:
        'path_traversal',
      validator:
        'runtime-generic',
      target:
        normalizedTarget,
      rationale:
        'Generic runtime path traversal probe.',
    },
    {
      findingId:
        'runtime-auth-bypass',
      attackType:
        'auth_bypass',
      validator:
        'runtime-generic',
      target:
        normalizedTarget,
      rationale:
        'Generic runtime unauthenticated access probe.',
    },
    {
      findingId:
        'runtime-code-injection',
      attackType:
        'code_injection',
      validator:
        'runtime-generic',
      target:
        normalizedTarget,
      rationale:
        'Generic runtime code injection probe.',
    },
  ];
}
function createFindingPlans(
  findings,
  normalizedTarget
) {
  return findings
    .map(
      finding => {
        const attackType =
          classifyFinding(
            finding
          );
        if (
          attackType ===
          'other'
        ) {
          return null;
        }
        return {
          findingId:
            finding.id ||
            null,
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
    )
    .filter(Boolean);
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
      new URL(
        targetUrl
      );
  } catch {
    throw new Error(
      `Invalid project runtime URL: ${targetUrl}`
    );
  }
  const normalizedTarget =
    parsedTarget
      .toString()
      .replace(
        /\/$/,
        ''
      );
  const safeFindings =
    Array.isArray(
      findings
    )
      ? findings
      : [];
  const genericPlans =
    createGenericPlans(
      normalizedTarget
    );
  const findingPlans =
    createFindingPlans(
      safeFindings,
      normalizedTarget
    );
  return [
    ...genericPlans,
    ...findingPlans,
  ];
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
  const safeFindings =
    Array.isArray(
      findings
    )
      ? findings
      : [];
  for (
    const finding of safeFindings
  ) {
    const type =
      classifyFinding(
        finding
      );
    if (
      !categories[
        type
      ]
    ) {
      categories[
        type
      ] = [];
    }
    categories[
      type
    ].push(
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