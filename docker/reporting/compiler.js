'use strict';

function emptySummary() {
  return {
    findings: 0,
    tested: 0,
    confirmed: 0,
    observedExposures: 0,
    inconclusive: 0,
    notReproduced: 0,
    runtimeTests: 0,
    runtimeFailed: 0,
    durationMs: null,
  };
}

function normalizeSummary(summary) {
  return {
    ...emptySummary(),
    ...(summary || {}),
  };
}

function createSelfTest(report) {
  if (!report) {
    return {
      executed: false,
      reportId: null,
      startedAt: null,
      finishedAt: null,
      summary: emptySummary(),
      controlledFixtures: 0,
      detected: 0,
      coverage: {
        detected: 0,
        total: 0,
      },
      target: null,
      runtime: {
        attacks: [],
        validations: [],
      },
      events: [],
    };
  }

  const summary =
    normalizeSummary(
      report.summary
    );

  const total =
    summary.runtimeTests || 0;

  const detected =
    summary.confirmed || 0;

  return {
    executed: true,
    reportId:
      report.sandboxId || null,
    startedAt:
      report.startedAt || null,
    finishedAt:
      report.finishedAt || null,
    summary,
    controlledFixtures:
      total,
    detected,
    coverage: {
      detected,
      total,
    },
    target:
      report.target || null,
    runtime: {
      attacks:
        report.runtime?.attacks || [],
      validations:
        report.runtime?.validations || [],
    },
    events:
      report.events || [],
  };
}

function createProjectValidation(report) {
  if (!report) {
    return {
      executed: false,
      reportId: null,
      startedAt: null,
      finishedAt: null,
      summary: emptySummary(),
      target: null,
      runtime: {
        attacks: [],
        validations: [],
      },
      exposures: [],
      events: [],
    };
  }

  return {
    executed: true,
    reportId:
      report.sandboxId || null,
    startedAt:
      report.startedAt || null,
    finishedAt:
      report.finishedAt || null,
    summary:
      normalizeSummary(
        report.summary
      ),
    target:
      report.target || null,
    runtime: {
      attacks:
        report.runtime?.attacks || [],
      validations:
        report.runtime?.validations || [],
    },
    exposures:
      Array.isArray(
        report.exposures
      )
        ? report.exposures
        : [],
    events:
      Array.isArray(
        report.events
      )
        ? report.events
        : [],
  };
}

function getFinishedAt(
  simulationReport,
  projectReport
) {
  const timestamps = [
    simulationReport?.finishedAt,
    projectReport?.finishedAt,
  ]
    .filter(Boolean)
    .map(
      value =>
        new Date(
          value
        ).getTime()
    )
    .filter(
      Number.isFinite
    );

  if (!timestamps.length) {
    return new Date()
      .toISOString();
  }

  return new Date(
    Math.max(
      ...timestamps
    )
  ).toISOString();
}

function compileReports({
  simulationReport = null,
  projectReport = null,
  findings = [],
  project = null,
} = {}) {
  const selfTest =
    createSelfTest(
      simulationReport
    );

  const projectValidation =
    createProjectValidation(
      projectReport
    );

  const allFindings =
    Array.isArray(findings) &&
    findings.length
      ? findings
      : (
          Array.isArray(
            projectReport?.findings
          )
            ? projectReport.findings
            : []
        );

const staticFindings =
  Array.isArray(
    projectReport
      ?.staticFindings
  )
    ? projectReport
        .staticFindings
    : [];

const aiFindings =
  Array.isArray(
    projectReport
      ?.aiFindings
  )
    ? projectReport
        .aiFindings
    : [];
  return {
    schemaVersion: '1.1',
    reportType:
      'SentinelAI Security Report',
    mode:
      'compiled',
    finishedAt:
      getFinishedAt(
        simulationReport,
        projectReport
      ),
    generatedFrom: {
      safeSimulation:
        Boolean(
          simulationReport
        ),
      projectValidation:
        Boolean(
          projectReport
        ),
    },
    project:
      project ||
      projectReport?.project ||
      null,
    target:
      projectReport?.target ||
      null,
    summary:
      projectValidation.summary,
    findings: {
      all:
        allFindings,
      static:
        staticFindings,
      ai:
        aiFindings,
      correlated: [],
    },
    selfTest,
    projectValidation,
    exposures:
      projectValidation.exposures,
  };
}

module.exports = {
  compileReports,
};