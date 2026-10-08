'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

function clean(value) {
    return String(value ?? '')
        .replace(/\r?\n/g, ' ')
        .trim();
}

function renderMarkdownReport(report) {

    const summary =
        report.summary || {};

    const target =
        report.target || {};

    const findings =
        Array.isArray(report.findings)
            ? report.findings
            : [];

    const attacks =
        Array.isArray(report.attacks)
            ? report.attacks
            : [];

    const validations =
        Array.isArray(report.validations)
            ? report.validations
            : [];

    const events =
        Array.isArray(report.events)
            ? report.events
            : [];

    const lines = [];

    lines.push(
        '# SentinelAI Runtime Validation Report'
    );

    lines.push('');

    lines.push(
        `- **Sandbox ID:** ${clean(report.sandboxId)}`
    );

    lines.push(
        `- **Mode:** ${clean(report.mode)}`
    );

    lines.push(
        `- **Target:** ${clean(target.url)}`
    );

    lines.push(
        `- **Runtime:** ${clean(target.name)}`
    );

    lines.push(
        `- **Started:** ${clean(report.startedAt)}`
    );

    lines.push(
        `- **Finished:** ${clean(report.finishedAt)}`
    );

    lines.push('');

    lines.push(
        '## Validation Summary'
    );

    lines.push('');

    lines.push('| Metric | Value |');
    lines.push('|---|---:|');

    lines.push(
        `| Findings | ${summary.findings ?? 0} |`
    );

    lines.push(
        `| Tested | ${summary.tested ?? 0} |`
    );

    lines.push(
        `| Confirmed | ${summary.confirmed ?? 0} |`
    );

    lines.push(
        `| Inconclusive | ${summary.inconclusive ?? 0} |`
    );

    lines.push(
        `| Not Reproduced | ${summary.notReproduced ?? 0} |`
    );

    lines.push(
        `| Runtime Tests | ${summary.runtimeTests ?? 0} |`
    );

    lines.push(
        `| Successful Runtime Tests | ${summary.runtimeSuccessful ?? 0} |`
    );

    lines.push(
        `| Failed Runtime Tests | ${summary.runtimeFailed ?? 0} |`
    );

    lines.push(
        `| Duration (ms) | ${summary.durationMs ?? 0} |`
    );

    lines.push('');

    lines.push(
        '## Findings'
    );

    lines.push('');

    if (!findings.length) {

        lines.push(
            'No findings were supplied.'
        );

    } else {

        findings.forEach(
            (finding, index) => {

                lines.push(
                    `### ${index + 1}. ${clean(
                        finding.type ||
                        'Security Finding'
                    )}`
                );

                lines.push('');

                lines.push(
                    `- **ID:** ${clean(finding.id)}`
                );

                lines.push(
                    `- **Severity:** ${clean(
                        finding.severity
                    )}`
                );

                lines.push(
                    `- **File:** ${clean(
                        finding.file
                    )}`
                );

                if (finding.line) {

                    lines.push(
                        `- **Line:** ${clean(
                            finding.line
                        )}`
                    );

                }

                if (finding.explanation) {

                    lines.push(
                        `- **Explanation:** ${clean(
                            finding.explanation
                        )}`
                    );

                }

                if (finding.fix) {

                    lines.push(
                        `- **Fix:** ${clean(
                            finding.fix
                        )}`
                    );

                }

                lines.push('');
            }
        );
    }

    lines.push(
        '## Runtime Attack Evidence'
    );

    lines.push('');

    if (!attacks.length) {

        lines.push(
            'No runtime attacks were executed.'
        );

    } else {

        attacks.forEach(
            (attack, index) => {

                lines.push(
                    `### Attack ${index + 1}: ${clean(
                        attack.tool ||
                        'runtime-generic'
                    )}`
                );

                lines.push('');

                lines.push(
                    `- **Finding:** ${clean(
                        attack.findingId
                    )}`
                );

                lines.push(
                    `- **Attack Type:** ${clean(
                        attack.attackType
                    )}`
                );

                lines.push(
                    `- **Status:** ${clean(
                        attack.status
                    )}`
                );

                lines.push(
                    `- **Target:** ${clean(
                        attack.target
                    )}`
                );

                lines.push(
                    `- **Payload:** ${clean(
                        attack.payload
                    )}`
                );

                if (attack.request) {

                    lines.push(
                        `- **Request:** ${clean(
                            JSON.stringify(
                                attack.request
                            )
                        )}`
                    );

                }

                if (attack.response) {

                    lines.push(
                        `- **Response:** ${clean(
                            JSON.stringify(
                                attack.response
                            )
                        )}`
                    );

                }

                if (
                    Array.isArray(
                        attack.evidence
                    )
                ) {

                    lines.push('');

                    lines.push(
                        '**Evidence**'
                    );

                    lines.push('');

                    attack.evidence.forEach(
                        evidence => {

                            lines.push(
                                `- **${clean(
                                    evidence.type ||
                                    'evidence'
                                )}:** ${clean(
                                    evidence.content
                                )}`
                            );

                        }
                    );

                }

                lines.push('');
            }
        );
    }

    lines.push(
        '## Validation Verdicts'
    );

    lines.push('');

    if (!validations.length) {

        lines.push(
            'No validation verdicts were generated.'
        );

    } else {

        validations.forEach(
            (validation, index) => {

                lines.push(
                    `${index + 1}. **${clean(
                        validation.result
                    )}** — ${clean(
                        validation.findingId
                    )} — Confidence: ${clean(
                        validation.confidence
                    )}% — ${clean(
                        validation.rationale
                    )}`
                );

            }
        );
    }

    lines.push('');

    lines.push(
        '## Validation Execution'
    );

    lines.push('');

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

    lines.push('');

    lines.push(
        '---'
    );

    lines.push('');

    lines.push(
        '*Generated automatically by SentinelAI.*'
    );

    lines.push('');

    return lines.join('\n');
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
            recursive: true,
        }
    );

    const safeMode =
        String(
            report.mode ||
            'sandbox'
        ).replace(
            /[^a-z0-9_-]/gi,
            '-'
        );

    const safeId =
        String(
            report.sandboxId ||
            Date.now()
        ).replace(
            /[^a-z0-9_-]/gi,
            '-'
        );

    const baseName =
        `sentinelai-${safeMode}-${safeId}`;

    const markdownPath =
        path.join(
            reportsDir,
            `${baseName}.md`
        );

    const jsonPath =
        path.join(
            reportsDir,
            `${baseName}.json`
        );

    await fs.writeFile(
        markdownPath,
        renderMarkdownReport(
            report
        ),
        'utf8'
    );

    await fs.writeFile(
        jsonPath,
        JSON.stringify(
            report,
            null,
            2
        ),
        'utf8'
    );

    return {
        markdown:
            markdownPath,

        json:
            jsonPath,
    };
}

module.exports = {
    renderMarkdownReport,
    writeReportFiles,
};