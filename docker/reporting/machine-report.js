'use strict';

const {
  getReportTimes,
} = require(
  './time'
);

function createMachineAttack(
  attack
) {
  return {
    id:
      attack.id ||
      null,
    findingId:
      attack.findingId ||
      null,
    tool:
      attack.tool ||
      null,
    attackType:
      attack.attackType ||
      null,
    target:
      attack.target ||
      null,
    status:
      attack.status ||
      null,
    payload:
      attack.payload ||
      null,
    request:
      attack.request ||
      null,
    response:
      attack.response
        ? {
            statusCode:
              attack.response
                .statusCode ??
              null,
            contentType:
              attack.response
                .contentType ||
              null,
            bodyLength:
              attack.response
                .bodyLength ??
              0,
            bodyPreview:
              attack.response
                .bodyPreview ||
              '',
            evidenceSnippet:
              attack.response
                .evidenceSnippet ||
              null,
          }
        : null,
    sensitiveData:
      Array.isArray(
        attack.sensitiveData
      )
        ? attack.sensitiveData
        : [],
    startedAt:
      attack.startedAt ||
      null,
    finishedAt:
      attack.finishedAt ||
      null,
    evidence:
      Array.isArray(
        attack.evidence
      )
        ? attack.evidence.filter(
            item =>
              item?.type !==
              'response'
          )
        : [],
  };
}

function createRuntime(
  runtime
) {
  return {
    attacks:
      Array.isArray(
        runtime?.attacks
      )
        ? runtime.attacks.map(
            createMachineAttack
          )
        : [],
    validations:
      Array.isArray(
        runtime?.validations
      )
        ? runtime.validations
        : [],
  };
}

function createMachineReport(
  report
) {
  const {
    generatedAt,
    expiresAt,
    timeZone,
    generatedLocal,
    expiresLocal,
  } =
    getReportTimes(
      report
    );

  return {
    schemaVersion:
      report.schemaVersion ||
      '1.1',
    reportType:
      'SentinelAI Security Data',
    generatedAt,
    expiresAt,
    timeZone,
    displayTime: {
      generated:
        generatedLocal,
      expires:
        expiresLocal,
    },
    retentionHours:
      24,
    project:
      report.project ||
      null,
    target:
      report.target ||
      null,
    summary:
      report.summary ||
      {},
    findings:
      report.findings ||
      {
        all:
          [],
        static:
          [],
        ai:
          [],
        correlated:
          [],
      },
    selfTest: {
      ...report.selfTest,
      runtime:
        createRuntime(
          report.selfTest
            ?.runtime
        ),
    },
    projectValidation: {
      ...report
        .projectValidation,
      runtime:
        createRuntime(
          report
            .projectValidation
            ?.runtime
        ),
    },
    exposures:
      Array.isArray(
        report.exposures
      )
        ? report.exposures
        : [],
  };
}

module.exports = {
  createMachineReport,
};