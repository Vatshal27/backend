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
  createMachineReport,
} = require(
  './machine-report'
);

const {
  renderMarkdownReport,
} = require(
  './markdown-report'
);

const REPORT_MARKDOWN =
  'SentinelAI_Security_Report.md';

const REPORT_JSON =
  'SentinelAI_Security_Data.json';

async function removeLegacyReports(
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
  } catch (
    error
  ) {
    if (
      error?.code ===
      'ENOENT'
    ) {
      return;
    }

    throw error;
  }

  const keep =
    new Set([
      REPORT_MARKDOWN,
      REPORT_JSON,
    ]);

  const removals =
    entries
      .filter(
        entry =>
          entry.isFile()
      )
      .filter(
        entry =>
          !keep.has(
            entry.name
          )
      )
      .filter(
        entry =>
          entry.name.includes(
            'SentinelAI'
          )
      )
      .map(
        entry =>
          fs.rm(
            path.join(
              reportsDir,
              entry.name
            ),
            {
              force:
                true,
            }
          )
      );

  await Promise.allSettled(
    removals
  );
}

async function writeReportFiles(
  report
) {
  const reportsDir =
    path.join(
      __dirname,
      '..',
      '..',
      'reports'
    );

  await fs.mkdir(
    reportsDir,
    {
      recursive:
        true,
    }
  );

  await removeLegacyReports(
    reportsDir
  );

  const markdownPath =
    path.join(
      reportsDir,
      REPORT_MARKDOWN
    );

  const jsonPath =
    path.join(
      reportsDir,
      REPORT_JSON
    );

  const machineReport =
    createMachineReport(
      report
    );

  const markdown =
    renderMarkdownReport(
      report
    );

  const json =
    JSON.stringify(
      machineReport,
      null,
      2
    );

  await Promise.all([
    fs.writeFile(
      markdownPath,
      markdown,
      'utf8'
    ),
    fs.writeFile(
      jsonPath,
      json,
      'utf8'
    ),
  ]);

  return {
    markdown:
      markdownPath,
    json:
      jsonPath,
    generatedAt:
      machineReport
        .generatedAt,
    expiresAt:
      machineReport
        .expiresAt,
    timeZone:
      machineReport
        .timeZone,
  };
}

module.exports = {
  writeReportFiles,
};