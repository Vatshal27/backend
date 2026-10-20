'use strict';

const {
  renderMarkdownReport,
} = require(
  './reporting/markdown-report'
);

const {
  createMachineReport,
} = require(
  './reporting/machine-report'
);

const {
  writeReportFiles,
  getManagedReportFiles,
} = require(
  './reporting/writer'
);

const {
  cleanupExpiredReports,
} = require(
  './reporting/retention'
);

module.exports = {
  renderMarkdownReport,
  createMachineReport,
  writeReportFiles,
  getManagedReportFiles,
  cleanupExpiredReports,
};