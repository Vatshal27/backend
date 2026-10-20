'use strict';

const fs =
  require(
    'node:fs/promises'
  );

const path =
  require(
    'node:path'
  );

const {
  REPORT_RETENTION_MS,
} = require(
  './time'
);
const { getManagedReportFiles } = require('./writer');

async function cleanupExpiredReports(
  reportsDir
) {
  let entries;

  try {
    entries =
      await fs.readdir(
        reportsDir,
        {
          withFileTypes:
            true,
        }
      );
  } catch {
    return {
      deleted:
        0,
    };
  }

  const now = Date.now();
  const managedReports = getManagedReportFiles();

  let deleted =
    0;

  for (
    const entry of entries
  ) {
    if (
      !entry.isFile()
    ) {
      continue;
    }

    if (!managedReports.has(entry.name)) {
      continue;
    }

    const filePath =
      path.join(
        reportsDir,
        entry.name
      );

    try {
      const stats =
        await fs.stat(
          filePath
        );

      if (
        now -
          stats.mtimeMs >=
        REPORT_RETENTION_MS
      ) {
        await fs.unlink(
          filePath
        );

        deleted +=
          1;
      }
    } catch {
      // File may already be gone.
    }
  }

  return {
    deleted,
  };
}

module.exports = {
  cleanupExpiredReports,
};  