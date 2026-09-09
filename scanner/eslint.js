'use strict';

const { execFile } = require('child_process');
const path = require('path');

function runESLint(projectPath) {
    return new Promise((resolve, reject) => {
        const absolutePath = path.resolve(projectPath);

        execFile(
            'npx',
            [
                'eslint',
                absolutePath,
                '--config', 'eslint.config.mjs',
                '--format', 'json',
            ],
            { maxBuffer: 1024 * 1024 * 20 },
            (error, stdout, stderr) => {
                if (stderr && !stdout) {
                    console.log('[ESLint warning]', stderr);
                }

                const output = stdout.trim();

                if (!output) {
                    return resolve([]);
                }

                try {
                    const result = JSON.parse(output);
                    const findings = normalizeFindings(result);
                    resolve(findings);
                } catch (parseError) {
                    reject(
                        new Error('Failed parsing ESLint JSON output')
                    );
                }
            }
        );
    });
}

function normalizeFindings(files) {
    const findings = [];

    for (const file of files) {
        for (const message of file.messages) {
            findings.push({
                tool: 'ESLint',
                id: message.ruleId || 'eslint-rule',
                type: convertType(message.ruleId, message.message),
                severity: getSeverity(message.ruleId, message.severity),
                file: file.filePath,
                line: message.line || 0,
                message: message.message,
                cwe: getCWE(message.ruleId),
                source: 'Static Analysis',
            });
        }
    }

    return findings;
}

function getSeverity(ruleId, severity) {
    const highSeverityRules = ['no-eval'];

    if (highSeverityRules.includes(ruleId)) {
        return 'High';
    }

    if (severity === 2) {
        return 'Medium';
    }

    return 'Low';
}

function getCWE(ruleId) {
    const cweMap = {
        'no-eval': 'CWE-95',
    };

    return cweMap[ruleId] || '';
}

function convertType(ruleId, message) {
    const lower = message.toLowerCase();

    if (ruleId === 'no-eval' || lower.includes('eval')) {
        return 'Code Injection';
    }

    if (lower.includes('security')) {
        return 'Security Issue';
    }

    return 'Code Quality/Security Issue';
}

module.exports = {
    runESLint,
};