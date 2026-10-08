'use strict';

const BODY_PREVIEW_LIMIT =
  800;

const MAX_EXPOSURES_PER_RESPONSE =
  25;

function maskValue(
  value
) {
  const text =
    String(
      value || ''
    );

  if (
    !text
  ) {
    return '[REDACTED]';
  }

  if (
    text.length <= 6
  ) {
    return '*'.repeat(
      Math.max(
        text.length,
        4
      )
    );
  }

  if (
    text.length <= 12
  ) {
    return (
      text.slice(
        0,
        2
      ) +
      '*'.repeat(
        text.length - 4
      ) +
      text.slice(
        -2
      )
    );
  }

  return (
    text.slice(
      0,
      4
    ) +
    '*'.repeat(
      Math.min(
        12,
        text.length - 8
      )
    ) +
    text.slice(
      -4
    )
  );
}

function detectContentType(
  body
) {
  const text =
    String(
      body || ''
    ).trim();

  if (
    !text
  ) {
    return 'empty';
  }

  if (
    /^<!doctype html>|^<html[\s>]/i.test(
      text
    )
  ) {
    return 'text/html';
  }

  try {
    JSON.parse(
      text
    );

    return 'application/json';
  } catch {
    return 'text/plain';
  }
}

function createExposure(
  dataType,
  category,
  value,
  index
) {
  const text =
    String(
      value || ''
    );

  return {
    id:
      `exposure-${index}`,
    category,
    dataType,
    maskedValue:
      maskValue(
        text
      ),
    valueLength:
      text.length,
    verdict:
      'observed_exposure',
  };
}

function collectMatches(
  body,
  regex,
  dataType,
  category,
  exposures
) {
  regex.lastIndex =
    0;

  let match;

  while (
    (
      match =
        regex.exec(
          body
        )
    ) !== null
  ) {
    const value =
      match[1] ||
      match[0];

    const maskedValue =
      maskValue(
        value
      );

    const exists =
      exposures.some(
        item =>
          item.dataType ===
            dataType &&
          item.maskedValue ===
            maskedValue
      );

    if (
      !exists
    ) {
      exposures.push(
        createExposure(
          dataType,
          category,
          value,
          exposures.length +
            1
        )
      );
    }

    if (
      exposures.length >=
      MAX_EXPOSURES_PER_RESPONSE
    ) {
      break;
    }

    if (
      match.index ===
      regex.lastIndex
    ) {
      regex.lastIndex +=
        1;
    }
  }
}

function detectSensitiveData(
  value
) {
  const body =
    String(
      value || ''
    );

  const exposures = [];

  collectMatches(
    body,
    /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/g,
    'Private Key',
    'credential',
    exposures
  );

  collectMatches(
    body,
    /\b(AKIA[0-9A-Z]{16})\b/g,
    'AWS Access Key',
    'cloud_credential',
    exposures
  );

  collectMatches(
    body,
    /\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b/g,
    'JWT',
    'authentication_token',
    exposures
  );

  collectMatches(
    body,
    /\bBearer\s+([A-Za-z0-9._~+/=-]{12,})/gi,
    'Bearer Token',
    'authentication_token',
    exposures
  );

  collectMatches(
    body,
    /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s/]+:([^@\s/]+)@[^\s"'<>]+/gi,
    'Database Credential',
    'credential',
    exposures
  );

  collectMatches(
    body,
    /\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|password|passwd)\b\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{8,})/gi,
    'Application Secret',
    'credential',
    exposures
  );

  return exposures;
}

function redactSensitiveText(
  value
) {
  let text =
    String(
      value || ''
    );

  text =
    text.replace(
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      '[REDACTED PRIVATE KEY]'
    );

  text =
    text.replace(
      /\bAKIA[0-9A-Z]{16}\b/g,
      match =>
        maskValue(
          match
        )
    );

  text =
    text.replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      match =>
        maskValue(
          match
        )
    );

  text =
    text.replace(
      /\bBearer\s+([A-Za-z0-9._~+/=-]{12,})/gi,
      (
        _match,
        token
      ) =>
        `Bearer ${maskValue(
          token
        )}`
    );

  text =
    text.replace(
      /(\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret|password|passwd)\b\s*[:=]\s*["']?)([A-Za-z0-9._~+/=-]{8,})/gi,
      (
        _match,
        prefix,
        secret
      ) =>
        prefix +
        maskValue(
          secret
        )
    );

  text =
    text.replace(
      /(\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s/]+:)([^@\s/]+)(@[^\s"'<>]+)/gi,
      (
        _match,
        prefix,
        password,
        suffix
      ) =>
        prefix +
        maskValue(
          password
        ) +
        suffix
    );

  return text;
}

function createBodyPreview(
  body
) {
  const redacted =
    redactSensitiveText(
      body
    );

  if (
    redacted.length <=
    BODY_PREVIEW_LIMIT
  ) {
    return redacted;
  }

  return (
    redacted.slice(
      0,
      BODY_PREVIEW_LIMIT
    ) +
    '…'
  );
}

function createEvidenceSnippet(
  exposures
) {
  if (
    !Array.isArray(
      exposures
    ) ||
    !exposures.length
  ) {
    return null;
  }

  return exposures
    .slice(
      0,
      5
    )
    .map(
      item =>
        `${item.dataType}: ${item.maskedValue}`
    )
    .join(
      '; '
    );
}

function compactResponse(
  response
) {
  if (
    !response
  ) {
    return null;
  }

  const body =
    String(
      response.body ||
      ''
    );

  const sensitiveData =
    detectSensitiveData(
      body
    );

  return {
    statusCode:
      response.statusCode ??
      null,
    contentType:
      detectContentType(
        body
      ),
    bodyLength:
      Buffer.byteLength(
        body,
        'utf8'
      ),
    bodyPreview:
      createBodyPreview(
        body
      ),
    evidenceSnippet:
      createEvidenceSnippet(
        sensitiveData
      ),
    sensitiveData,
  };
}

function compactEvidence(
  evidence
) {
  if (
    !Array.isArray(
      evidence
    )
  ) {
    return [];
  }

  return evidence.map(
    item => {
      const content =
        redactSensitiveText(
          item?.content ||
          ''
        );

      return {
        ...item,
        content:
          content.length >
          BODY_PREVIEW_LIMIT
            ? (
                content.slice(
                  0,
                  BODY_PREVIEW_LIMIT
                ) +
                '…'
              )
            : content,
      };
    }
  );
}

function normalizeEvidence(
  attacks
) {
  const safeAttacks =
    Array.isArray(
      attacks
    )
      ? attacks
      : [];

  return safeAttacks.map(
    attack => {
      const response =
        compactResponse(
          attack.response
        );

      return {
        ...attack,
        response,
        sensitiveData:
          response
            ?.sensitiveData ||
          [],
        evidence:
          compactEvidence(
            attack.evidence
          ),
      };
    }
  );
}

function createEvidenceEvent(
  attacks
) {
  const safeAttacks =
    Array.isArray(
      attacks
    )
      ? attacks
      : [];

  const evidenceCount =
    safeAttacks.reduce(
      (
        total,
        attack
      ) =>
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

  const exposureCount =
    safeAttacks.reduce(
      (
        total,
        attack
      ) =>
        total +
        (
          Array.isArray(
            attack.sensitiveData
          )
            ? attack.sensitiveData.length
            : 0
        ),
      0
    );

  return {
    evidenceCount,
    exposureCount,
    attackCount:
      safeAttacks.length,
  };
}

module.exports = {
  normalizeEvidence,
  createEvidenceEvent,
  detectSensitiveData,
  redactSensitiveText,
};