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
  cleanupExpiredReports,
};