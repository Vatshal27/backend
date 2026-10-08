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
  getReportTimes,
  filenameTimestamp,
} = require(
  './time'
);

const {
  safeName,
} = require(
  './formatter'
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

const {
  cleanupExpiredReports,
} = require(
  './retention'
);

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

  await cleanupExpiredReports(
    reportsDir
  );

  const {
    generatedAt,
    timeZone,
  } =
    getReportTimes(
      report
    );

  const timestamp =
    filenameTimestamp(
      generatedAt,
      timeZone
    );

  const projectName =
    safeName(
      report.project?.name
    );

  const prefix =
    projectName
      ? `${timestamp}_SentinelAI_${projectName}`
      : `${timestamp}_SentinelAI`;

  const markdownPath =
    path.join(
      reportsDir,
      `${prefix}_Security_Report.md`
    );

  const jsonPath =
    path.join(
      reportsDir,
      `${prefix}_Security_Data.json`
    );

  const machineReport =
    createMachineReport(
      report
    );

  await Promise.all([
    fs.writeFile(
      markdownPath,
      renderMarkdownReport(
        report
      ),
      'utf8'
    ),
    fs.writeFile(
      jsonPath,
      JSON.stringify(
        machineReport,
        null,
        2
      ),
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