'use strict';

const express =
  require('express');

const {
  getMailStatus,
  sendMail,
} = require('./mailer');

const router =
  express.Router();

router.get(
  '/status',
  (
    req,
    res
  ) => {
    try {
      const status =
        getMailStatus();

      return res.json({
        success:
          true,

        mail:
          status,
      });
    } catch (
      error
    ) {
      console.error(
        '[mail] Failed to read mail status:',
        error instanceof Error
          ? error.message
          : String(
              error
            )
      );

      return res
        .status(500)
        .json({
          success:
            false,

          error:
            'Unable to determine SentinelAI mail status.',
        });
    }
  }
);

router.post(
  '/test',
  async (
    req,
    res
  ) => {
    try {
      const result =
        await sendMail({
          subject:
            'SentinelAI Email Integration Test',

          text:
            'This is a SentinelAI email integration test.',
        });

      if (
        result.sent
      ) {
        return res.json({
          success:
            true,

          message:
            'SentinelAI test email was sent successfully.',

          mail:
            result,
        });
      }

      if (
        result.skipped
      ) {
        return res.json({
          success:
            true,

          message:
            result.reason ||
            'Email delivery was skipped.',

          mail:
            result,
        });
      }

      return res
        .status(400)
        .json({
          success:
            false,

          message:
            'SentinelAI test email could not be sent.',

          mail:
            result,
        });
    } catch (
      error
    ) {
      console.error(
        '[mail] Test email failed:',
        error instanceof Error
          ? error.message
          : String(
              error
            )
      );

      return res
        .status(500)
        .json({
          success:
            false,

          error:
            'SentinelAI test email failed.',
        });
    }
  }
);

module.exports =
  router;