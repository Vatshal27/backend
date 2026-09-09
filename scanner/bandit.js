'use strict';

const { execFile } = require('child_process');
const path = require('path');

function runBandit(projectPath) {
    return new Promise((resolve, reject) => {
        const absolutePath = path.resolve(projectPath);

        execFile(
            'bandit',
            ['-r', absolutePath, '-f', 'json'],
            { maxBuffer: 1024 * 1024 * 20 },
            (error, stdout, stderr) => {
                if (stderr) {
                    console.log('[Bandit warning]', stderr);
                }

                if (!stdout) {
                    return reject(
                        new Error('Bandit returned no output')
                    );
                }

                try {
                    const result = JSON.parse(stdout);

                    const findings = normalizeFindings(
                        result.results || []
                    );

                    resolve(findings);
                } catch (error) {
                    reject(
                        new Error('Failed parsing Bandit JSON output')
                    );
                }
            }
        );
    });
}

function normalizeFindings(results) {
    return results.map(finding => ({
        tool: 'Bandit',
        id: finding.test_id,
        type: convertType(finding.test_id),
        severity: convertSeverity(finding.issue_severity),
        file: finding.filename,
        line: finding.line_number || 0,
        message: finding.issue_text || 'Security issue detected',
        cwe: finding.issue_cwe?.id
            ? `CWE-${finding.issue_cwe.id}`
            : '',
        source: 'Static Analysis',
    }));
}

function convertType(testId) {
    const map = {
        B602: 'Command Injection',
        B603: 'Subprocess Execution',
        B605: 'Shell Injection',
        B607: 'Partial Command Injection',
        B307: 'Dangerous Eval',
        B105: 'Hardcoded Password',
        B106: 'Hardcoded Password',
    };

    return map[testId] || 'Python Security Issue';
}

function convertSeverity(level) {
    switch (level) {
        case 'HIGH': return 'High';
        case 'MEDIUM': return 'Medium';
        default: return 'Low';
    }
}

module.exports = {
    runBandit,
};