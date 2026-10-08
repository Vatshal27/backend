'use strict';

const fs =
  require(
    'node:fs/promises'
  );

const path =
  require(
    'node:path'
  );

const REPORT_RETENTION_MS =
  24 *
  60 *
  60 *
  1000;

function clean(
  value
) {
  return String(
    value ?? ''
  )
    .replace(
      /\r?\n/g,
      ' '
    )
    .trim();
}

function formatLocalDateTime(
  value
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
    return clean(
      value
    );
  }

  return date.toLocaleString(
    'en-GB',
    {
      year:
        'numeric',
      month:
        'long',
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
  );
}

function filenameTimestamp(
  value
) {
  const date =
    value
      ? new Date(
          value
        )
      : new Date();

  const pad =
    number =>
      String(
        number
      ).padStart(
        2,
        '0'
      );

  return (
    date.getFullYear() +
    '-' +
    pad(
      date.getMonth() +
      1
    ) +
    '-' +
    pad(
      date.getDate()
    ) +
    '_' +
    pad(
      date.getHours()
    ) +
    '-' +
    pad(
      date.getMinutes()
    ) +
    '-' +
    pad(
      date.getSeconds()
    )
  );
}

function safeName(
  value
) {
  return String(
    value || ''
  )
    .trim()
    .replace(
      /[^a-z0-9_-]+/gi,
      '_'
    )
    .replace(
      /^_+|_+$/g,
      ''
    );
}

function getReportTimes(
  report
) {
  const generatedAt =
    report.finishedAt ||
    new Date().toISOString();

  const generatedDate =
    new Date(
      generatedAt
    );

  const expiresAt =
    new Date(
      generatedDate.getTime() +
      REPORT_RETENTION_MS
    ).toISOString();

  return {
    generatedAt:
      generatedDate.toISOString(),
    expiresAt,
  };
}

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
              attack.response.statusCode ??
              null,
            contentType:
              attack.response.contentType ||
              null,
            bodyLength:
              attack.response.bodyLength ??
              0,
            bodyPreview:
              attack.response.bodyPreview ||
              '',
            evidenceSnippet:
              attack.response.evidenceSnippet ||
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
        ? attack.evidence
        : [],
  };
}

function createMachineReport(
  report
) {
  const {
    generatedAt,
    expiresAt,
  } =
    getReportTimes(
      report
    );

  const attacks =
    Array.isArray(
      report.runtime?.attacks
    )
      ? report.runtime.attacks
      : (
          Array.isArray(
            report.attacks
          )
            ? report.attacks
            : []
        );

  const validations =
    Array.isArray(
      report.runtime?.validations
    )
      ? report.runtime.validations
      : (
          Array.isArray(
            report.validations
          )
            ? report.validations
            : []
        );

  return {
    schemaVersion:
      report.schemaVersion ||
      '1.0',
    reportType:
      'SentinelAI Security Data',
    reportId:
      report.sandboxId ||
      null,
    generatedAt,
    expiresAt,
    retentionHours:
      24,
    mode:
      report.mode ||
      null,
    project:
      report.project ||
      null,
    target:
      report.target ||
      null,
    summary:
      report.summary ||
      {},
    findings: {
      all:
        Array.isArray(
          report.findings
        )
          ? report.findings
          : [],
      static:
        Array.isArray(
          report.staticFindings
        )
          ? report.staticFindings
          : [],
      ai:
        Array.isArray(
          report.aiFindings
        )
          ? report.aiFindings
          : [],
    },
    runtime: {
      attacks:
        attacks.map(
          createMachineAttack
        ),
      validations,
    },
    exposures:
      Array.isArray(
        report.exposures
      )
        ? report.exposures
        : [],
    execution: {
      events:
        Array.isArray(
          report.events
        )
          ? report.events
          : [],
    },
  };
}

function renderSummaryTable(
  lines,
  summary
) {
  lines.push(
    '| Result | Count |'
  );

  lines.push(
    '|---|---:|'
  );

  lines.push(
    `| Confirmed vulnerabilities | ${summary.confirmed ?? 0} |`
  );

  lines.push(
    `| Observed exposures | ${summary.observedExposures ?? 0} |`
  );

  lines.push(
    `| Inconclusive | ${summary.inconclusive ?? 0} |`
  );

  lines.push(
    `| Not reproduced | ${summary.notReproduced ?? 0} |`
  );

  lines.push(
    `| Runtime tests | ${summary.runtimeTests ?? 0} |`
  );

  lines.push(
    `| Failed tests | ${summary.runtimeFailed ?? 0} |`
  );

  lines.push(
    `| Duration | ${summary.durationMs ?? 0} ms |`
  );
}

function renderSourceFindings(
  lines,
  title,
  findings
) {
  lines.push(
    `## ${title}`
  );

  lines.push('');

  if (
    !findings.length
  ) {
    lines.push(
      `No ${title.toLowerCase()} were reported.`
    );

    lines.push('');

    return;
  }

  findings.forEach(
    (
      finding,
      index
    ) => {
      lines.push(
        `### ${index + 1}. ${clean(
          finding.type ||
          finding.title ||
          'Security Finding'
        )}`
      );

      lines.push('');

      if (
        finding.id
      ) {
        lines.push(
          `- **ID:** ${clean(
            finding.id
          )}`
        );
      }

      if (
        finding.severity
      ) {
        lines.push(
          `- **Severity:** ${clean(
            finding.severity
          )}`
        );
      }

      if (
        finding.file
      ) {
        const location =
          finding.line
            ? `${finding.file}:${finding.line}`
            : finding.file;

        lines.push(
          `- **Location:** \`${clean(
            location
          )}\``
        );
      }

      if (
        finding.explanation
      ) {
        lines.push('');

        lines.push(
          '**Explanation**'
        );

        lines.push('');

        lines.push(
          clean(
            finding.explanation
          )
        );
      }

      if (
        finding.fix
      ) {
        lines.push('');

        lines.push(
          '**Recommended Fix**'
        );

        lines.push('');

        lines.push(
          clean(
            finding.fix
          )
        );
      }

      lines.push('');
    }
  );
}

function renderExposures(
  lines,
  exposures
) {
  lines.push(
    '## Sensitive Data Exposure'
  );

  lines.push('');

  if (
    !exposures.length
  ) {
    lines.push(
      'No sensitive-data exposure was detected in the runtime responses checked during this scan.'
    );

    lines.push('');

    return;
  }

  exposures.forEach(
    (
      exposure,
      index
    ) => {
      lines.push(
        `### ${index + 1}. ${clean(
          exposure.dataType ||
          'Sensitive Data'
        )}`
      );

      lines.push('');

      lines.push(
        '- **Verdict:** Observed Exposure'
      );

      lines.push(
        `- **Category:** ${clean(
          exposure.category
        )}`
      );

      if (
        exposure.endpoint
      ) {
        lines.push(
          `- **Endpoint:** \`${clean(
            exposure.endpoint
          )}\``
        );
      }

      lines.push(
        `- **Redacted Evidence:** \`${clean(
          exposure.maskedValue ||
          '[REDACTED]'
        )}\``
      );

      lines.push('');

      lines.push(
        'The complete sensitive value is intentionally not stored in this report.'
      );

      lines.push('');
    }
  );
}

function renderRuntimeValidation(
  lines,
  attacks,
  validations
) {
  lines.push(
    '## Runtime Validation'
  );

  lines.push('');

  if (
    !attacks.length
  ) {
    lines.push(
      'No runtime security probes were executed.'
    );

    lines.push('');

    return;
  }

  lines.push(
    '| Check | Verdict | Target | HTTP |'
  );

  lines.push(
    '|---|---|---|---:|'
  );

  attacks.forEach(
    attack => {
      const validation =
        validations.find(
          item =>
            item.attackId ===
            attack.id &&
            item.result !==
              'observed_exposure'
        );

      lines.push(
        `| ${clean(
          attack.attackType
        )} | ${clean(
          validation?.result ||
          attack.status ||
          'unknown'
        )} | ${clean(
          attack.target
        )} | ${clean(
          attack.response
            ?.statusCode ??
          ''
        )} |`
      );
    }
  );

  lines.push('');

  attacks.forEach(
    (
      attack,
      index
    ) => {
      const validation =
        validations.find(
          item =>
            item.attackId ===
            attack.id &&
            item.result !==
              'observed_exposure'
        );

      lines.push(
        `### Probe ${index + 1}: ${clean(
          attack.attackType ||
          'Runtime Check'
        )}`
      );

      lines.push('');

      lines.push(
        `- **Verdict:** ${clean(
          validation?.result ||
          attack.status ||
          'unknown'
        )}`
      );

      lines.push(
        `- **Target:** \`${clean(
          attack.target
        )}\``
      );

      if (
        attack.request
      ) {
        lines.push(
          `- **Request:** \`${clean(
            attack.request.method
          )} ${clean(
            attack.request.url
          )}\``
        );
      }

      if (
        attack.response
      ) {
        lines.push(
          `- **HTTP Status:** ${clean(
            attack.response.statusCode
          )}`
        );

        lines.push(
          `- **Content Type:** ${clean(
            attack.response.contentType
          )}`
        );

        lines.push(
          `- **Response Size:** ${clean(
            attack.response.bodyLength
          )} bytes`
        );
      }

      if (
        validation?.rationale
      ) {
        lines.push('');

        lines.push(
          '**Assessment**'
        );

        lines.push('');

        lines.push(
          clean(
            validation.rationale
          )
        );
      }

      if (
        attack.response
          ?.evidenceSnippet
      ) {
        lines.push('');

        lines.push(
          '**Security Evidence**'
        );

        lines.push('');

        lines.push(
          `\`${clean(
            attack.response
              .evidenceSnippet
          )}\``
        );
      }

      if (
        attack.response
          ?.bodyPreview
      ) {
        lines.push('');

        lines.push(
          '<details>'
        );

        lines.push(
          '<summary>Redacted response preview</summary>'
        );

        lines.push('');

        lines.push(
          '```text'
        );

        lines.push(
          String(
            attack.response
              .bodyPreview
          )
        );

        lines.push(
          '```'
        );

        lines.push('');

        lines.push(
          '</details>'
        );
      }

      lines.push('');
    }
  );
}

function renderMarkdownReport(
  report
) {
  const {
    generatedAt,
    expiresAt,
  } =
    getReportTimes(
      report
    );

  const summary =
    report.summary ||
    {};

  const target =
    report.target ||
    {};

  const staticFindings =
    Array.isArray(
      report.staticFindings
    )
      ? report.staticFindings
      : [];

  const aiFindings =
    Array.isArray(
      report.aiFindings
    )
      ? report.aiFindings
      : [];

  const attacks =
    Array.isArray(
      report.runtime?.attacks
    )
      ? report.runtime.attacks
      : (
          Array.isArray(
            report.attacks
          )
            ? report.attacks
            : []
        );

  const validations =
    Array.isArray(
      report.runtime?.validations
    )
      ? report.runtime.validations
      : (
          Array.isArray(
            report.validations
          )
            ? report.validations
            : []
        );

  const exposures =
    Array.isArray(
      report.exposures
    )
      ? report.exposures
      : [];

  const lines = [];

  lines.push(
    '# SentinelAI Security Report'
  );

  lines.push('');

  lines.push(
    `**Generated:** ${formatLocalDateTime(
      generatedAt
    )}`
  );

  lines.push(
    `**Expires:** ${formatLocalDateTime(
      expiresAt
    )}`
  );

  if (
    report.project?.name
  ) {
    lines.push(
      `**Project:** ${clean(
        report.project.name
      )}`
    );
  }

  lines.push(
    `**Target:** ${clean(
      target.url ||
      ''
    )}`
  );

  lines.push(
    `**Mode:** ${clean(
      report.mode ||
      ''
    )}`
  );

  lines.push('');

  lines.push(
    '> Local SentinelAI report files are retained for 24 hours and are then automatically removed.'
  );

  lines.push('');

  lines.push(
    '---'
  );

  lines.push('');

  lines.push(
    '## Executive Summary'
  );

  lines.push('');

  const securityRelevant =
    (
      summary.confirmed ||
      0
    ) +
    (
      summary.observedExposures ||
      0
    );

  if (
    securityRelevant > 0
  ) {
    lines.push(
      `SentinelAI identified ${securityRelevant} security-relevant result(s) requiring review.`
    );
  } else {
    lines.push(
      'SentinelAI did not confirm a vulnerability or sensitive-data exposure in the checks performed.'
    );
  }

  lines.push('');

  renderSummaryTable(
    lines,
    summary
  );

  lines.push('');

  renderSourceFindings(
    lines,
    'Static Analysis Findings',
    staticFindings
  );

  renderSourceFindings(
    lines,
    'AI Analysis Findings',
    aiFindings
  );

  renderExposures(
    lines,
    exposures
  );

  renderRuntimeValidation(
    lines,
    attacks,
    validations
  );

  lines.push(
    '## Validation Execution'
  );

  lines.push('');

  const events =
    Array.isArray(
      report.events
    )
      ? report.events
      : [];

  if (
    !events.length
  ) {
    lines.push(
      'No execution events were recorded.'
    );
  } else {
    events.forEach(
      event => {
        lines.push(
          `- **Step ${clean(
            event.step
          )}:** ${clean(
            event.description
          )} — ${clean(
            event.status
          )}`
        );
      }
    );
  }

  lines.push('');

  lines.push(
    '---'
  );

  lines.push('');

  lines.push(
    '*Generated automatically by SentinelAI.*'
  );

  lines.push('');

  return lines.join(
    '\n'
  );
}

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

  const now =
    Date.now();

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

    if (
      !entry.name.endsWith(
        '.md'
      ) &&
      !entry.name.endsWith(
        '.json'
      )
    ) {
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
      // File may have already been removed.
    }
  }

  return {
    deleted,
  };
}

async function writeReportFiles(
  report
) {
  const reportsDir =
    path.join(
      __dirname,
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
  } =
    getReportTimes(
      report
    );

  const timestamp =
    filenameTimestamp(
      generatedAt
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
      machineReport.generatedAt,
    expiresAt:
      machineReport.expiresAt,
  };
}

module.exports = {
  renderMarkdownReport,
  createMachineReport,
  writeReportFiles,
  cleanupExpiredReports,
};