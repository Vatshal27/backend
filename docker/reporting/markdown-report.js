'use strict';

const { getReportTimes } = require('./time');
const {
  clean,
  formatAttackType,
  formatVerdict,
} = require('./formatter');

function escapeTable(value) {
  return clean(value).replace(/\|/g, '\\|');
}

function inlineCode(value) {
  return String(value ?? '')
    .replace(/`/g, "'")
    .replace(/\r?\n/g, ' ')
    .trim();
}

function getValidation(validations, attack) {
  return (
    validations.find(
      item =>
        item?.attackId === attack?.id &&
        item?.result !== 'observed_exposure'
    ) || null
  );
}

function renderProjectSummary(lines, summary, executed) {
  lines.push('## Executive Summary');
  lines.push('');
  if (!executed) {
    lines.push('Project runtime validation has not been executed for this compiled report.');
    lines.push('');
    return;
  }
  const confirmed = summary.confirmed ?? 0;
  const exposures = summary.observedExposures ?? 0;
  if (confirmed > 0 || exposures > 0) {
    lines.push(
      `SentinelAI identified ${confirmed} confirmed vulnerability result(s) and ${exposures} observed sensitive-data exposure(s) requiring review.`
    );
  } else {
    lines.push(
      'SentinelAI did not confirm a vulnerability or sensitive-data exposure in the checks performed.'
    );
  }
  lines.push('');
  lines.push('### Project Security Results');
  lines.push('');
  lines.push('| Result | Count |');
  lines.push('|---|---:|');
  lines.push(`| Confirmed vulnerabilities | ${confirmed} |`);
  lines.push(`| Observed exposures | ${exposures} |`);
  lines.push(`| Inconclusive | ${summary.inconclusive ?? 0} |`);
  lines.push(`| Not reproduced | ${summary.notReproduced ?? 0} |`);
  lines.push(`| Runtime tests | ${summary.runtimeTests ?? 0} |`);
  lines.push(`| Failed tests | ${summary.runtimeFailed ?? 0} |`);
  if (
    summary.durationMs !== null &&
    summary.durationMs !== undefined
  ) {
    lines.push(`| Runtime duration | ${summary.durationMs} ms |`);
  }
  lines.push('');
}

function renderSelfTestSummary(lines, selfTest) {
  lines.push('### SentinelAI Runtime Engine Self-Test');
  lines.push('');
  if (!selfTest?.executed) {
    lines.push('Safe Simulation was not run before this report was compiled.');
    lines.push('');
    return;
  }
  const total =
    selfTest.coverage?.total ??
    selfTest.controlledFixtures ??
    0;
  const detected =
    selfTest.coverage?.detected ??
    selfTest.detected ??
    0;
  lines.push('| Result | Count |');
  lines.push('|---|---:|');
  lines.push(`| Controlled fixtures | ${total} |`);
  lines.push(`| Successfully detected | ${detected} |`);
  lines.push(`| Inconclusive | ${selfTest.summary?.inconclusive ?? 0} |`);
  lines.push(`| Failed tests | ${selfTest.summary?.runtimeFailed ?? 0} |`);
  lines.push(`| Detection coverage | ${detected} / ${total} |`);
  lines.push('');
  lines.push(
    '> Safe Simulation validates SentinelAI against controlled synthetic vulnerability fixtures. These detections are scanner self-test results and are not project vulnerabilities.'
  );
  lines.push('');
}

function renderFindings(lines, title, findings, emptyMessage) {
  lines.push(`## ${title}`);
  lines.push('');
  if (!Array.isArray(findings) || !findings.length) {
    lines.push(emptyMessage);
    lines.push('');
    return;
  }
  findings.forEach((finding, index) => {
    const name =
      finding?.title ||
      finding?.type ||
      'Security Finding';
    lines.push(`### ${index + 1}. ${clean(name)}`);
    lines.push('');
    if (finding?.id) {
      lines.push(`- **ID:** ${clean(finding.id)}`);
    }
    if (finding?.severity) {
      lines.push(`- **Severity:** ${clean(finding.severity)}`);
    }
    if (finding?.file) {
      const location =
        finding.line
          ? `${finding.file}:${finding.line}`
          : finding.file;
      lines.push(`- **Location:** \`${inlineCode(location)}\``);
    }
    if (finding?.explanation) {
      lines.push('');
      lines.push('**Explanation**');
      lines.push('');
      lines.push(clean(finding.explanation));
    }
    if (finding?.fix) {
      lines.push('');
      lines.push('**Recommended Fix**');
      lines.push('');
      lines.push(clean(finding.fix));
    }
    lines.push('');
  });
}

function renderExposures(lines, exposures) {
  lines.push('## Sensitive Data Exposure');
  lines.push('');
  if (!Array.isArray(exposures) || !exposures.length) {
    lines.push(
      'No sensitive-data exposure was detected in the runtime responses checked during this scan.'
    );
    lines.push('');
    return;
  }
  exposures.forEach((exposure, index) => {
    lines.push(
      `### ${index + 1}. ${clean(
        exposure?.dataType || 'Sensitive Data'
      )}`
    );
    lines.push('');
    lines.push('- **Verdict:** Observed Exposure');
    lines.push(
      `- **Category:** ${clean(
        exposure?.category || 'sensitive_data'
      )}`
    );
    if (exposure?.endpoint) {
      lines.push(
        `- **Endpoint:** \`${inlineCode(
          exposure.endpoint
        )}\``
      );
    }
    lines.push(
      `- **Redacted Evidence:** \`${inlineCode(
        exposure?.maskedValue || '[REDACTED]'
      )}\``
    );
    lines.push('');
    lines.push(
      'The complete sensitive value is intentionally not stored in this report.'
    );
    lines.push('');
  });
}

function renderRuntimeValidation(lines, projectValidation) {
  lines.push('## Project Runtime Validation');
  lines.push('');
  if (!projectValidation?.executed) {
    lines.push(
      'Project runtime validation was not executed for this compiled report.'
    );
    lines.push('');
    return;
  }
  const attacks =
    Array.isArray(projectValidation.runtime?.attacks)
      ? projectValidation.runtime.attacks
      : [];
  const validations =
    Array.isArray(projectValidation.runtime?.validations)
      ? projectValidation.runtime.validations
      : [];
  if (!attacks.length) {
    lines.push('No runtime security probes were executed.');
    lines.push('');
    return;
  }
  lines.push('| Check | Verdict | Target | HTTP |');
  lines.push('|---|---|---|---:|');
  attacks.forEach(attack => {
    const validation =
      getValidation(validations, attack);
    lines.push(
      `| ${escapeTable(
        formatAttackType(attack?.attackType)
      )} | ${escapeTable(
        formatVerdict(
          validation?.result ||
          attack?.status ||
          'unknown'
        )
      )} | ${escapeTable(
        attack?.target || ''
      )} | ${escapeTable(
        attack?.response?.statusCode ?? ''
      )} |`
    );
  });
  lines.push('');
  attacks.forEach((attack, index) => {
    const validation =
      getValidation(validations, attack);
    const verdict =
      validation?.result ||
      attack?.status ||
      'unknown';
    lines.push(
      `### Probe ${index + 1}: ${formatAttackType(
        attack?.attackType
      )}`
    );
    lines.push('');
    lines.push(
      `- **Verdict:** ${formatVerdict(verdict)}`
    );
    if (attack?.target) {
      lines.push(
        `- **Target:** \`${inlineCode(
          attack.target
        )}\``
      );
    }
    if (attack?.request) {
      lines.push(
        `- **Request:** \`${inlineCode(
          `${attack.request.method || 'GET'} ${attack.request.url || ''}`
        )}\``
      );
    }
    if (attack?.response) {
      lines.push(
        `- **HTTP Status:** ${clean(
          attack.response.statusCode ?? ''
        )}`
      );
      lines.push(
        `- **Content Type:** ${clean(
          attack.response.contentType || 'unknown'
        )}`
      );
      lines.push(
        `- **Response Size:** ${clean(
          attack.response.bodyLength ?? 0
        )} bytes`
      );
    }
    if (validation?.rationale) {
      lines.push('');
      lines.push('**Assessment**');
      lines.push('');
      lines.push(clean(validation.rationale));
    }
    if (attack?.response?.evidenceSnippet) {
      lines.push('');
      lines.push('**Security Evidence**');
      lines.push('');
      lines.push(
        `\`${inlineCode(
          attack.response.evidenceSnippet
        )}\``
      );
    }

    // Do not repeat normal HTML for every inconclusive probe.
    if (
      verdict === 'confirmed' &&
      attack?.response?.bodyPreview
    ) {
      lines.push('');
      lines.push('<details>');
      lines.push(
        '<summary>Redacted response preview</summary>'
      );
      lines.push('');
      lines.push('```text');
      lines.push(
        String(
          attack.response.bodyPreview
        ).replace(/```/g, "'''")
      );
      lines.push('```');
      lines.push('');
      lines.push('</details>');
    }
    lines.push('');
  });
}

function renderSelfTestDetails(lines, selfTest) {
  lines.push('## Scanner Self-Test Details');
  lines.push('');
  if (!selfTest?.executed) {
    lines.push(
      'No Safe Simulation result is included in this report.'
    );
    lines.push('');
    return;
  }
  const attacks =
    Array.isArray(selfTest.runtime?.attacks)
      ? selfTest.runtime.attacks
      : [];
  const validations =
    Array.isArray(selfTest.runtime?.validations)
      ? selfTest.runtime.validations
      : [];
  if (!attacks.length) {
    lines.push(
      'Safe Simulation completed without recorded runtime probes.'
    );
    lines.push('');
    return;
  }
  lines.push(
    '| Controlled Check | Result | HTTP |'
  );
  lines.push('|---|---|---:|');
  attacks.forEach(attack => {
    const validation =
      getValidation(validations, attack);
    lines.push(
      `| ${escapeTable(
        formatAttackType(attack?.attackType)
      )} | ${escapeTable(
        formatVerdict(
          validation?.result ||
          attack?.status ||
          'unknown',
          true
        )
      )} | ${escapeTable(
        attack?.response?.statusCode ?? ''
      )} |`
    );
  });
  lines.push('');
  lines.push(
    'These controlled results verify that the runtime scanner can detect its known synthetic fixtures. They do not represent vulnerabilities in the project target.'
  );
  lines.push('');
}

function renderExecution(lines, title, events) {
  lines.push(`## ${title}`);
  lines.push('');
  if (!Array.isArray(events) || !events.length) {
    lines.push(
      'No execution events were recorded.'
    );
    lines.push('');
    return;
  }
  events.forEach(event => {
    lines.push(
      `- **Step ${clean(
        event?.step ?? ''
      )}:** ${clean(
        event?.description || ''
      )} — ${clean(
        event?.status || ''
      )}`
    );
  });
  lines.push('');
}

function renderMarkdownReport(report) {
  const {
    generatedLocal,
    expiresLocal,
    timeZone,
  } = getReportTimes(report);
  const lines = [];

  lines.push('# SentinelAI Security Report');
  lines.push('');
  lines.push(`**Generated:** ${generatedLocal}`);
  lines.push(`**Expires:** ${expiresLocal}`);
  lines.push(`**Time Zone:** ${clean(timeZone)}`);

  if (report?.project?.name) {
    lines.push(
      `**Project:** ${clean(
        report.project.name
      )}`
    );
  }

  if (report?.target?.url) {
    lines.push(
      `**Target:** ${clean(
        report.target.url
      )}`
    );
  }

  lines.push(
    '**Report Type:** Compiled Security Report'
  );
  lines.push('');
  lines.push(
    '> Local SentinelAI report files are retained for 24 hours and are then automatically removed.'
  );
  lines.push('');
  lines.push('---');
  lines.push('');

  renderProjectSummary(
    lines,
    report?.summary || {},
    Boolean(
      report?.projectValidation?.executed
    )
  );

  renderSelfTestSummary(
    lines,
    report?.selfTest
  );

  renderFindings(
    lines,
    'Static Analysis Findings',
    report?.findings?.static || [],
    'No static analysis findings were reported.'
  );

  renderFindings(
    lines,
    'AI Analysis Findings',
    report?.findings?.ai || [],
    'No AI analysis findings were reported.'
  );

  renderExposures(
    lines,
    report?.exposures || []
  );

  renderRuntimeValidation(
    lines,
    report?.projectValidation
  );

  renderSelfTestDetails(
    lines,
    report?.selfTest
  );

  renderExecution(
    lines,
    'Project Validation Execution',
    report?.projectValidation?.events || []
  );

  renderExecution(
    lines,
    'Safe Simulation Execution',
    report?.selfTest?.events || []
  );

  lines.push('---');
  lines.push('');
  lines.push(
    '*Generated automatically by SentinelAI.*'
  );
  lines.push('');

  return lines.join('\n');
}

module.exports = {
  renderMarkdownReport,
};