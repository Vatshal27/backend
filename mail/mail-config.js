'use strict';

function parseBoolean(
  value,
  fallback = false
) {
  if (
    value === undefined ||
    value === null ||
    value === ''
  ) {
    return fallback;
  }

  return String(
    value
  )
    .trim()
    .toLowerCase() ===
    'true';
}

function parseInteger(
  value,
  fallback
) {
  const parsed =
    Number.parseInt(
      value,
      10
    );

  return Number.isFinite(
    parsed
  )
    ? parsed
    : fallback;
}

function parseRecipients(
  value
) {
  if (
    !value
  ) {
    return [];
  }

  return String(
    value
  )
    .split(',')
    .map(
      email =>
        email.trim()
    )
    .filter(
      Boolean
    );
}

function getMailConfig() {
  return {
    enabled:
      parseBoolean(
        process.env.MAIL_ENABLED,
        false
      ),

    host:
      process.env.MAIL_HOST ||
      'smtp.gmail.com',

    port:
      parseInteger(
        process.env.MAIL_PORT,
        465
      ),

    secure:
      parseBoolean(
        process.env.MAIL_SECURE,
        true
      ),

    user:
      process.env.MAIL_USER ||
      '',

    password:
      process.env.MAIL_PASS ||
      '',

    fromName:
      process.env.MAIL_FROM_NAME ||
      'SentinelAI Security Reports',

    to:
      parseRecipients(
        process.env.MAIL_TO
      ),

    cc:
      parseRecipients(
        process.env.MAIL_CC
      ),

    bcc:
      parseRecipients(
        process.env.MAIL_BCC
      ),
  };
}

module.exports = {
  getMailConfig,
  parseRecipients,
};