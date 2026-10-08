'use strict';

const REPORT_RETENTION_MS =
  24 *
  60 *
  60 *
  1000;

function getReportTimeZone() {
  const override =
    String(
      process.env.SENTINEL_TIME_ZONE ||
      ''
    ).trim();

  if (
    override
  ) {
    try {
      new Intl.DateTimeFormat(
        'en-GB',
        {
          timeZone:
            override,
        }
      );
return normalizeTimeZone(
  override
);
    } catch {
      // Fall through to system timezone.
    }
  }

  try {
return normalizeTimeZone(
  Intl
    .DateTimeFormat()
    .resolvedOptions()
    .timeZone
);
  } catch {
    return 'UTC';
  }
}
function normalizeTimeZone(
  value
) {
  if (
    value ===
    'Asia/Calcutta'
  ) {
    return 'Asia/Kolkata';
  }

  return value ||
    'UTC';
}
function formatReportDateTime(
  value,
  timeZone
) {
  const date =
    value
      ? new Date(
          value
        )
      : new Date();

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return String(
      value || ''
    );
  }

  const parts =
    new Intl.DateTimeFormat(
      'en-GB',
      {
        timeZone,
        day:
          '2-digit',
        month:
          'long',
        year:
          'numeric',
        hour:
          '2-digit',
        minute:
          '2-digit',
        second:
          '2-digit',
        hour12:
          false,
      }
    ).formatToParts(
      date
    );

  const get =
    type =>
      parts.find(
        part =>
          part.type ===
          type
      )?.value ||
      '';

  return (
    `${get('day')} ` +
    `${get('month')} ` +
    `${get('year')} at ` +
    `${get('hour')}:` +
    `${get('minute')}:` +
    `${get('second')}`
  );
}

function getReportTimes(
  report = {}
) {
  const rawGeneratedAt =
    report.finishedAt ||
    report.generatedAt ||
    new Date().toISOString();

  let generatedDate =
    new Date(
      rawGeneratedAt
    );

  if (
    Number.isNaN(
      generatedDate.getTime()
    )
  ) {
    generatedDate =
      new Date();
  }

  const expiresDate =
    new Date(
      generatedDate.getTime() +
      REPORT_RETENTION_MS
    );

  const timeZone =
    report.timeZone ||
    getReportTimeZone();

  return {
    generatedAt:
      generatedDate.toISOString(),
    expiresAt:
      expiresDate.toISOString(),
    generatedLocal:
      formatReportDateTime(
        generatedDate,
        timeZone
      ),
    expiresLocal:
      formatReportDateTime(
        expiresDate,
        timeZone
      ),
    timeZone,
  };
}

function filenameTimestamp(
  value,
  timeZone
) {
  const date =
    new Date(
      value
    );

  const parts =
    new Intl.DateTimeFormat(
      'en-CA',
      {
        timeZone,
        year:
          'numeric',
        month:
          '2-digit',
        day:
          '2-digit',
        hour:
          '2-digit',
        minute:
          '2-digit',
        second:
          '2-digit',
        hour12:
          false,
      }
    ).formatToParts(
      date
    );

  const get =
    type =>
      parts.find(
        part =>
          part.type ===
          type
      )?.value ||
      '00';

  return (
    `${get('year')}-` +
    `${get('month')}-` +
    `${get('day')}_` +
    `${get('hour')}-` +
    `${get('minute')}-` +
    `${get('second')}`
  );
}

module.exports = {
  REPORT_RETENTION_MS,
  normalizeTimeZone,
  getReportTimeZone,
  formatReportDateTime,
  getReportTimes,
  filenameTimestamp,
};