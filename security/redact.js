'use strict';

const REDACTED = '[REDACTED]';
const SECRET_KEY = /(?:password|passwd|pwd|secret|token|api[-_]?key|authorization|cookie|private[-_]?key|credential|session[-_]?id)/i;
const ASSIGNMENT = /((?:["']?)[\w.-]*(?:password|passwd|pwd|secret|token|api[-_]?key|private[-_]?key|credential|session[-_]?id)[\w.-]*["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s&,;<>}"']+)/gi;

function redactString(value) {
  return value
    .replace(/-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY-----|$)/g, REDACTED)
    .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, REDACTED)
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, REDACTED)
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]+|sk-(?:proj-)?[A-Za-z0-9_-]{16,})\b/g, REDACTED)
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, `$1${REDACTED}@`)
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, `$1 ${REDACTED}`)
    .replace(/((?:["']?)(?:proxy-authorization|authorization|set-cookie|cookie)["']?\s*:\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n]+)/gi,
      (_match, prefix, value) => prefix + (value.startsWith('"') ? `"${REDACTED}"` : value.startsWith("'") ? `'${REDACTED}'` : REDACTED))
    .replace(ASSIGNMENT, (_match, prefix, value) =>
      prefix + (value.startsWith('"') ? `"${REDACTED}"` : value.startsWith("'") ? `'${REDACTED}'` : REDACTED));
}

// Produce a detached, JSON-safe copy. Never alter evidence used by evaluators.
function redact(value) {
  const ancestors = new WeakSet();
  function visit(item) {
    if (typeof item === 'string') return redactString(item);
    if (item === null || typeof item !== 'object') return item;
    if (ancestors.has(item)) return '[Circular]';
    if (Buffer.isBuffer(item)) return redactString(item.toString('utf8'));
    if (item instanceof Date) return item.toISOString();
    ancestors.add(item);
    const output = Array.isArray(item) ? item.map(visit) : Object.fromEntries(
      Object.entries(item).map(([key, entry]) => [key, SECRET_KEY.test(key) ? REDACTED : visit(entry)])
    );
    ancestors.delete(item);
    return output;
  }
  return visit(value);
}

module.exports = { redact };
