'use strict';

const { redact } = require('../security/redact');

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
  index,
  location = null
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
    location: location || `response-body@${index}`,
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
          exposures.length + 1,
          `response-body@${match.index}`
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
    'Authentication Token',
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
    /["']?\b(?:[\w.-]*api[_-]?key|[\w.-]*access[_-]?token|[\w.-]*secret[_-]?key|[\w.-]*client[_-]?secret|[\w.-]*password|[\w.-]*passwd)["']?\s*[:=]\s*["']?([A-Za-z0-9._~+/_=-]{8,})/gi,
    'Application Secret',
    'credential',
    exposures
  );

  collectMatches(
    body,
    /(?:"|')?([A-Za-z_][\w.-]*(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)(?:"|')?)\s*:\s*(?:"|')([^"']{8,})(?:"|')/gi,
    'Application Secret',
    'credential',
    exposures
  );
  collectMatches(
    body,
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    'Email Address',
    'personal_data',
    exposures
  );
  collectMatches(
    body,
    /(?<!\d)(\+?\d[\d .()/-]{7,}\d)(?!\d)/g,
    'Phone Number',
    'personal_data',
    exposures
  );

  let parsed;
  try { parsed = JSON.parse(body); } catch { parsed = null; }
  if (parsed && typeof parsed === 'object') {
    let visited = 0;
    const walk = (value, path = '$', depth = 0) => {
      if (depth > 12 || visited++ > 2000 || exposures.length >= MAX_EXPOSURES_PER_RESPONSE) return;
      if (Array.isArray(value)) {
        value.slice(0, 100).forEach((item, index) => walk(item, `${path}[${index}]`, depth + 1));
        return;
      }
      if (!value || typeof value !== 'object') return;
      for (const [key, item] of Object.entries(value).slice(0, 200)) {
        const fieldPath = `${path}.${key}`;
        if (typeof item === 'string') {
          const keyLower = key.toLowerCase();
          let dataType = null;
          let category = 'credential';
          if (/(?:password|passwd|pwd|secret|token|api[_-]?key|credential|private[_-]?key)/i.test(key)) {
            dataType = /token|jwt/i.test(key) ? 'Authentication Token' : /key/i.test(key) ? 'Application Key' : 'Application Secret';
          } else if (/email|e-mail/i.test(key) || /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(item)) {
            dataType = 'Email Address'; category = 'personal_data';
          } else if (/phone|mobile|telephone/i.test(key) || /(?<!\d)\+?\d[\d .()/-]{7,}\d(?!\d)/.test(item)) {
            dataType = 'Phone Number'; category = 'personal_data';
          }
          if (dataType === 'Phone Number' && !/(?:phone|mobile|telephone)/i.test(key) && item.length > 30) dataType = null;
          if (dataType) {
            const maskedValue = maskValue(item);
            const existing = exposures.find(exposure => exposure.dataType === dataType && exposure.maskedValue === maskedValue);
            if (existing) {
              existing.fieldPath = fieldPath;
              existing.location = fieldPath;
            } else if (!(dataType === 'Application Secret' && exposures.some(exposure => exposure.category === 'credential' && exposure.dataType === 'Application Secret' && exposure.maskedValue === maskedValue))) {
              exposures.push(createExposure(dataType, category, item, exposures.length + 1, fieldPath));
            }
          }
        } else if (item && typeof item === 'object') walk(item, fieldPath, depth + 1);
      }
    };
    walk(parsed);
  }
  return exposures;
}

function redactSensitiveText(
  value
) {
  return redact(String(value ?? ''));
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

function createSafeBodyPreview(body, exposures) {
  let preview = String(body || '');
  const offsets = (exposures || []).filter(item => item.location?.startsWith('response-body@'))
    .map(item => ({ offset: Number(item.location.slice('response-body@'.length)), length: item.valueLength }))
    .filter(item => Number.isInteger(item.offset) && item.offset >= 0 && item.length > 0)
    .sort((a, b) => b.offset - a.offset);
  for (const { offset, length } of offsets) {
    const raw = String(body || '').slice(offset, offset + length);
    if (raw && preview.slice(offset, offset + length) === raw) {
      preview = preview.slice(0, offset) + '[REDACTED]' + preview.slice(offset + length);
    }
  }
  try {
    const source = JSON.parse(preview);
    for (const item of exposures || []) {
      if (!item.fieldPath) continue;
      const path = item.fieldPath.replace(/^\$\.?/, '').replace(/\[(\d+)\]/g, '.$1').split('.').filter(Boolean);
      let parent = source;
      for (const key of path.slice(0, -1)) parent = parent?.[Array.isArray(parent) ? Number(key) : key];
      const leaf = path.at(-1);
      if (parent && leaf !== undefined) parent[Array.isArray(parent) ? Number(leaf) : leaf] = '[REDACTED]';
    }
    preview = JSON.stringify(source);
  } catch {
    // Offset-based matching below still masks text/plain response values.
  }
  return createBodyPreview(preview);
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

  if (!Object.hasOwn(response, 'body') && Object.hasOwn(response, 'bodyPreview')) {
    return redact(response);
  }

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
      createSafeBodyPreview(body, sensitiveData),
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

      return redact({
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
      });
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