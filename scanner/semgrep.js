'use strict';

const { execFile } = require('child_process');
const path = require('path');

function runSemgrep(projectPath) {
    return new Promise((resolve, reject) => {
        const absolutePath = path.resolve(projectPath);

        execFile(
            'semgrep',
            [
                '--config', 'scanner/rules/javascript.yml',
                absolutePath,
                '--json',
            ],
            { maxBuffer: 1024 * 1024 * 20 },
            (error, stdout, stderr) => {
                if (stderr) {
                    console.log('[Semgrep warning]', stderr);
                }

                if (!stdout) {
                    return reject(
                        new Error('Semgrep returned no output')
                    );
                }

                try {
                    const result = JSON.parse(stdout);

                    console.log(
                        '[Semgrep raw findings]',
                        result.results?.length
                    );

                    const findings = normalizeFindings(
                        result.results || []
                    );

                    resolve(findings);
                } catch (parseError) {
                    reject(
                        new Error('Failed parsing Semgrep JSON output')
                    );
                }
            }
        );
    });
}

function normalizeFindings(results) {
    return results.map(finding => ({
        tool: 'Semgrep',
        id: finding.check_id,
        type: convertType(finding.check_id),
        severity: convertSeverity(finding.extra?.severity),
        file: finding.path,
        line: finding.start?.line || 0,
        message: finding.extra?.message || 'Security issue detected',
        cwe: finding.extra?.metadata?.cwe || '',
        source: 'Static Analysis',
    }));
}

function convertType(checkId) {
    if (checkId.includes('sql')) return 'SQL Injection';
    if (checkId.includes('command')) return 'Command Injection';
    if (checkId.includes('xss')) return 'Cross Site Scripting';
    if (checkId.includes('eval')) return 'Code Injection';
    return 'Security Issue';
}

function convertSeverity(level) {
    switch (level) {
        case 'ERROR': return 'High';
        case 'WARNING': return 'Medium';
        default: return 'Low';
    }
}

module.exports = {
    runSemgrep,
};