'use strict';

const {
  getMailConfig,
} = require('./mail-config');

function buildFromAddress(
  config
) {
  if (
    !config.user
  ) {
    return '';
  }

  return `${config.fromName} <${config.user}>`;
}

function validateMailConfig(
  config
) {
  const errors = [];

  if (
    !config.host
  ) {
    errors.push(
      'MAIL_HOST is required.'
    );
  }

  if (
    !config.port
  ) {
    errors.push(
      'MAIL_PORT is required.'
    );
  }

  if (
    !config.user
  ) {
    errors.push(
      'MAIL_USER is required.'
    );
  }

  if (
    !config.password
  ) {
    errors.push(
      'MAIL_PASS is required.'
    );
  }

  if (
    config.to.length ===
    0
  ) {
    errors.push(
      'At least one MAIL_TO recipient is required.'
    );
  }

  return errors;
}

function getMailStatus() {
  const config =
    getMailConfig();

  if (
    !config.enabled
  ) {
    return {
      enabled:
        false,

      ready:
        false,

      reason:
        'Mail delivery is disabled by MAIL_ENABLED=false.',
    };
  }

  const errors =
    validateMailConfig(
      config
    );

  return {
    enabled:
      true,

    ready:
      errors.length ===
      0,

    errors,

    sender:
      config.user || null,

    recipients: {
      to:
        config.to,

      cc:
        config.cc,

      bcc:
        config.bcc,
    },
  };
}

async function sendMail(
  message = {}
) {
  const config =
    getMailConfig();

  if (
    !config.enabled
  ) {
    return {
      sent:
        false,

      skipped:
        true,

      reason:
        'Mail delivery is disabled.',
    };
  }

  const errors =
    validateMailConfig(
      config
    );

  if (
    errors.length >
    0
  ) {
    return {
      sent:
        false,

      skipped:
        false,

      errors,
    };
  }

  return {
    sent:
      false,

    skipped:
      true,

    reason:
      'SMTP transport is not enabled yet.',

    preview: {
      from:
        buildFromAddress(
          config
        ),

      to:
        config.to,

      cc:
        config.cc,

      bcc:
        config.bcc,

      subject:
        message.subject ||
        'SentinelAI Report',
    },
  };
}

module.exports = {
  getMailStatus,
  sendMail,
  validateMailConfig,
};