'use strict';

const nodemailer =
  require('nodemailer');

const {
  getMailConfig,
} = require('./mail-config');

function buildFromAddress(
  config
) {
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

function createTransporter(
  config
) {
  return nodemailer.createTransport({
    host:
      config.host,

    port:
      config.port,

    secure:
      config.secure,

    auth: {
      user:
        config.user,

      pass:
        config.password,
    },
  });
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

async function verifyMailConnection() {
  const config =
    getMailConfig();

  if (
    !config.enabled
  ) {
    return {
      connected:
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
      connected:
        false,

      skipped:
        false,

      errors,
    };
  }

  const transporter =
    createTransporter(
      config
    );

  try {
    await transporter.verify();

    return {
      connected:
        true,

      skipped:
        false,

      sender:
        config.user,
    };
  } catch (
    error
  ) {
    return {
      connected:
        false,

      skipped:
        false,

      error:
        error instanceof Error
          ? error.message
          : String(
              error
            ),
    };
  }
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

  const transporter =
    createTransporter(
      config
    );

  const mailOptions = {
    from:
      buildFromAddress(
        config
      ),

    to:
      config.to.join(
        ', '
      ),

    subject:
      message.subject ||
      'SentinelAI Security Report',

    text:
      message.text ||
      '',

    html:
      message.html ||
      undefined,

    attachments:
      Array.isArray(
        message.attachments
      )
        ? message.attachments
        : [],
  };

  if (
    config.cc.length >
    0
  ) {
    mailOptions.cc =
      config.cc.join(
        ', '
      );
  }

  if (
    config.bcc.length >
    0
  ) {
    mailOptions.bcc =
      config.bcc.join(
        ', '
      );
  }

  try {
    const info =
      await transporter.sendMail(
        mailOptions
      );

    return {
      sent:
        true,

      skipped:
        false,

      messageId:
        info.messageId,

      accepted:
        info.accepted || [],

      rejected:
        info.rejected || [],

      response:
        info.response || null,
    };
  } catch (
    error
  ) {
    return {
      sent:
        false,

      skipped:
        false,

      error:
        error instanceof Error
          ? error.message
          : String(
              error
            ),
    };
  }
}

module.exports = {
  getMailStatus,
  verifyMailConnection,
  sendMail,
  validateMailConfig,
};