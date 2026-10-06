'use strict';

const Docker = require('dockerode');
const fs = require('fs');
const os = require('os');
const path = require('path');

const docker = new Docker();

const SCANNER_IMAGE = 'sentinelai-scanner:latest';
const CONTAINER_TIMEOUT = 180000;

const SOURCE_EXTENSIONS = new Set([
    '.js',
    '.jsx',
    '.ts',
    '.tsx',
    '.py',
    '.java',
    '.c',
    '.h',
    '.cpp',
    '.cc',
    '.cxx',
    '.cs',
    '.go',
    '.rs',
    '.php',
    '.rb',
    '.swift',
    '.kt',
    '.kts',
    '.sql',
    '.html',
    '.htm',
    '.vue',
    '.svelte',
    '.json',
    '.yaml',
    '.yml',
    '.xml',
    '.sh',
    '.bash'
]);

const IGNORED_PARTS = [
    'node_modules',
    '.git',
    '.svn',
    '.hg',
    'dist',
    'build',
    'coverage',
    '.next',
    '.nuxt',
    '.venv',
    'venv',
    '__pycache__',
    '.pytest_cache',
    '.idea',
    '.vscode'
];

async function checkDocker() {
    try {
        const info =
            await docker.info();

        return {
            ok: true,
            version:
                info.ServerVersion
        };
    } catch (error) {
        return {
            ok: false,
            reason:
                String(
                    error.message ||
                    error
                )
        };
    }
}

async function imageExists(
    imageName
) {
    try {
        await docker
            .getImage(imageName)
            .inspect();

        return true;
    } catch {
        return false;
    }
}

async function pullImage(
    imageName
) {
    if (
        await imageExists(
            imageName
        )
    ) {
        return;
    }

    console.log(
        `[docker-scanner] Pulling ${imageName}...`
    );

    const stream =
        await docker.pull(
            imageName
        );

    await new Promise(
        (
            resolve,
            reject
        ) => {
            docker.modem.followProgress(
                stream,
                error => {
                    if (error) {
                        reject(error);
                        return;
                    }

                    resolve();
                }
            );
        }
    );

    console.log(
        `[docker-scanner] Pulled ${imageName}`
    );
}

function filterSourceFiles(
    files
) {
    if (
        !Array.isArray(files)
    ) {
        return [];
    }

    const filtered =
        files.filter(file => {
            if (
                !file ||
                typeof file !== 'object'
            ) {
                return false;
            }

            const filePath =
                String(
                    file.path ||
                    ''
                ).replace(
                    /\\/g,
                    '/'
                );

            if (
                !filePath
            ) {
                return false;
            }

            const lowerPath =
                filePath.toLowerCase();

            if (
                IGNORED_PARTS.some(
                    part =>
                        lowerPath
                            .split('/')
                            .includes(part)
                )
            ) {
                return false;
            }

            const extension =
                path
                    .extname(
                        filePath
                    )
                    .toLowerCase();

            return SOURCE_EXTENSIONS.has(
                extension
            );
        });

    console.log(
        `[docker-scanner] File filter: ${files.length} -> ${filtered.length}`
    );

    return filtered;
}

function writeScanFiles(
    files,
    scanDirectory
) {
    for (
        const file of files
    ) {
        const relativePath =
            String(
                file.path ||
                'file.txt'
            )
                .replace(
                    /\\/g,
                    '/'
                )
                .replace(
                    /^\/+/,
                    ''
                );

        const destination =
            path.join(
                scanDirectory,
                relativePath
            );

        const normalizedRoot =
            path.resolve(
                scanDirectory
            );

        const normalizedDestination =
            path.resolve(
                destination
            );

        if (
            normalizedDestination !==
                normalizedRoot &&
            !normalizedDestination.startsWith(
                normalizedRoot +
                path.sep
            )
        ) {
            continue;
        }

        fs.mkdirSync(
            path.dirname(
                destination
            ),
            {
                recursive: true
            }
        );

        fs.writeFileSync(
            destination,
            String(
                file.code ||
                ''
            ),
            'utf8'
        );
    }
}

function makeScanFilesReadable(
    scanDirectory
) {
    const stack = [
        scanDirectory
    ];

    while (
        stack.length > 0
    ) {
        const current =
            stack.pop();

        let entries;

        try {
            entries =
                fs.readdirSync(
                    current,
                    {
                        withFileTypes:
                            true
                    }
                );
        } catch {
            continue;
        }

        for (
            const entry of entries
        ) {
            const entryPath =
                path.join(
                    current,
                    entry.name
                );

            if (
                entry.isDirectory()
            ) {
                stack.push(
                    entryPath
                );
                continue;
            }

            try {
                fs.chmodSync(
                    entryPath,
                    0o644
                );
            } catch {
                // Ignore permission failures.
            }
        }
    }
}

function buildScannerCommand(
    fileCount
) {
    return [
        'set -u',

        'echo "[scan] Running Semgrep..." >&2',

        'rm -f /tmp/semgrep.json',

        'semgrep --config auto /workspace --json --no-git-ignore > /tmp/semgrep.json 2>/tmp/semgrep-error.log || true',

        'if [ ! -s /tmp/semgrep.json ]; then',
        '  printf \'{"results":[]}\' > /tmp/semgrep.json',
        'fi',

        'echo "[scan] Running Bandit..." >&2',

        'rm -f /tmp/bandit.json',

        'bandit -r /workspace -f json -o /tmp/bandit.json 2>/tmp/bandit-error.log || true',

        'if [ ! -s /tmp/bandit.json ]; then',
        '  printf \'{"results":[]}\' > /tmp/bandit.json',
        'fi',

        'printf "__SENTINEL_RESULT_START__\\n"',

        'python3 -c \'import json; s=json.load(open("/tmp/semgrep.json")); b=json.load(open("/tmp/bandit.json")); print(json.dumps({"semgrep": s.get("results", []), "bandit": b.get("results", []), "filesScanned": ' +
            String(
                fileCount
            ) +
            '}))\'',

        'printf "\\n__SENTINEL_RESULT_END__\\n"'
    ].join('\n');
}

function extractScannerResult(
    logs
) {
    const startMarker =
        '__SENTINEL_RESULT_START__';

    const endMarker =
        '__SENTINEL_RESULT_END__';

    const text =
        Buffer.isBuffer(logs)
            ? logs.toString(
                'utf8'
            )
            : String(
                logs ||
                ''
            );

    const startIndex =
        text.indexOf(
            startMarker
        );

    if (
        startIndex === -1
    ) {
        console.error(
            '[docker-scanner] Result start marker not found.'
        );

        return null;
    }

    const jsonStart =
        startIndex +
        startMarker.length;

    const endIndex =
        text.indexOf(
            endMarker,
            jsonStart
        );

    if (
        endIndex === -1
    ) {
        console.error(
            '[docker-scanner] Result end marker not found.'
        );

        return null;
    }

    let jsonText =
        text
            .slice(
                jsonStart,
                endIndex
            )
            .trim();

    jsonText =
        jsonText
            .replace(
                /^[\u0000-\u001F]+/,
                ''
            )
            .replace(
                /[\u0000-\u001F]+$/,
                ''
            )
            .trim();

    try {
        const result =
            JSON.parse(
                jsonText
            );

        if (
            !result ||
            !Array.isArray(
                result.semgrep
            ) ||
            !Array.isArray(
                result.bandit
            )
        ) {
            throw new Error(
                'Scanner result has an invalid structure.'
            );
        }

        return result;
    } catch (error) {
        console.error(
            '[docker-scanner] Result JSON parse failed:',
            error.message
        );

        console.error(
            '[docker-scanner] JSON length:',
            jsonText.length
        );

        console.error(
            '[docker-scanner] JSON start:',
            JSON.stringify(
                jsonText.slice(
                    0,
                    200
                )
            )
        );

        return null;
    }
}

async function runScannersInContainer(
    files
) {
    if (
        !await imageExists(
            SCANNER_IMAGE
        )
    ) {
        throw new Error(
            `Docker image ${SCANNER_IMAGE} is missing. Build it first.`
        );
    }

    const scanDirectory =
        fs.mkdtempSync(
            path.join(
                os.tmpdir(),
                'sentinelai-scan-'
            )
        );

    writeScanFiles(
        files,
        scanDirectory
    );

    makeScanFilesReadable(
        scanDirectory
    );

    let container;

    try {
        container =
            await docker.createContainer({
                Image:
                    SCANNER_IMAGE,

                User:
                    '0:0',

                Entrypoint:
                    [],

                Cmd: [
                    'sh',
                    '-c',
                    buildScannerCommand(
                        files.length
                    )
                ],

                WorkingDir:
                    '/workspace',

                HostConfig: {
                    Binds: [
                        `${scanDirectory}:/workspace:ro`
                    ],

                    Memory:
                        512 *
                        1024 *
                        1024,

                    NanoCpus:
                        1_000_000_000,

                    PidsLimit:
                        256,

                    CapDrop: [
                        'ALL'
                    ],

                    SecurityOpt: [
                        'no-new-privileges:true'
                    ],

                    AutoRemove:
                        false
                }
            });

        await container.start();

        const waitResult =
            await Promise.race([
                container.wait(),

                new Promise(
                    (_, reject) =>
                        setTimeout(
                            () =>
                                reject(
                                    new Error(
                                        'Scanner container timed out.'
                                    )
                                ),
                            CONTAINER_TIMEOUT
                        )
                )
            ]);

        const rawLogs =
            await container.logs({
                stdout: true,
                stderr: true
            });

        console.log(
            `[docker-scanner] Container exited with code ${waitResult.StatusCode}`
        );

        const result =
            extractScannerResult(
                rawLogs
            );

        if (
            result
        ) {
            return result;
        }

        const output =
            rawLogs
                .toString(
                    'utf8'
                );

        console.error(
            '[docker-scanner] Scanner returned no valid result.'
        );

        console.error(
            output.slice(
                0,
                3000
            )
        );

        return {
            semgrep: [],
            bandit: [],
            filesScanned:
                files.length
        };
    } finally {
        if (
            container
        ) {
            try {
                await container.remove({
                    force: true
                });
            } catch {
                // Ignore cleanup failures.
            }
        }

        fs.rmSync(
            scanDirectory,
            {
                recursive:
                    true,
                force:
                    true
            }
        );
    }
}

function convertSemgrepSeverity(
    severity
) {
    const value =
        String(
            severity ||
            ''
        ).toUpperCase();

    if (
        value === 'ERROR'
    ) {
        return 'HIGH';
    }

    if (
        value === 'WARNING'
    ) {
        return 'MEDIUM';
    }

    if (
        value === 'INFO'
    ) {
        return 'LOW';
    }

    return 'MEDIUM';
}

function convertBanditSeverity(
    severity
) {
    const value =
        String(
            severity ||
            ''
        ).toUpperCase();

    if (
        value === 'HIGH'
    ) {
        return 'HIGH';
    }

    if (
        value === 'MEDIUM'
    ) {
        return 'MEDIUM';
    }

    return 'LOW';
}

function convertSemgrepType(
    checkId,
    message
) {
    const text =
        `${checkId || ''} ${message || ''}`
            .toLowerCase();

    if (
        text.includes('sql')
    ) {
        return 'SQL Injection';
    }

    if (
        text.includes('xss') ||
        text.includes('cross-site')
    ) {
        return 'Cross-Site Scripting';
    }

    if (
        text.includes('command') ||
        text.includes('shell')
    ) {
        return 'Command Injection';
    }

    if (
        text.includes('path') ||
        text.includes('traversal')
    ) {
        return 'Path Traversal';
    }

    if (
        text.includes('deserial')
    ) {
        return 'Insecure Deserialization';
    }

    if (
        text.includes('secret') ||
        text.includes('credential')
    ) {
        return 'Hardcoded Secret';
    }

    if (
        text.includes('ssrf')
    ) {
        return 'SSRF';
    }

    return (
        checkId ||
        'Security Issue'
    );
}

function convertBanditType(
    testId
) {
    const id =
        String(
            testId ||
            ''
        ).toUpperCase();

    const mapping = {
        B101:
            'Insecure Debug / Assert',
        B102:
            'Exec Used',
        B103:
            'Insecure File Permissions',
        B104:
            'Binding To All Interfaces',
        B105:
            'Hardcoded Password',
        B106:
            'Hardcoded Password',
        B107:
            'Hardcoded Password',
        B108:
            'Insecure Temporary File',
        B110:
            'Try Except Pass',
        B301:
            'Insecure Pickle',
        B302:
            'Insecure Marshal',
        B303:
            'Weak Cryptography',
        B304:
            'Weak Cryptography',
        B305:
            'Weak Cryptography',
        B306:
            'Insecure Temporary File',
        B307:
            'Use Of Eval',
        B308:
            'Insecure Markup',
        B310:
            'URL Open',
        B311:
            'Weak Randomness',
        B324:
            'Weak Hash',
        B501:
            'Request Without Certificate Validation',
        B506:
            'Insecure YAML Load',
        B602:
            'Subprocess With Shell',
        B603:
            'Subprocess Without Shell',
        B604:
            'Function With Shell'
    };

    return (
        mapping[id] ||
        `Bandit ${id}`
    );
}

function normalizeSemgrepFindings(
    results
) {
    if (
        !Array.isArray(results)
    ) {
        return [];
    }

    return results.map(
        finding => {
            const extra =
                finding.extra ||
                {};

            const message =
                extra.message ||
                'Security issue detected';

            const metadata =
                extra.metadata ||
                {};

            const cwe =
                metadata.cwe;

            return {
                tool:
                    'Semgrep',

                id:
                    finding.check_id ||
                    '',

                type:
                    convertSemgrepType(
                        finding.check_id,
                        message
                    ),

                severity:
                    convertSemgrepSeverity(
                        finding.severity
                    ),

                file:
                    finding.path ||
                    'Unknown',

                line:
                    finding.start?.line ||
                    0,

                column:
                    finding.start?.col ||
                    0,

                message,

                cwe:
                    Array.isArray(cwe)
                        ? cwe.join(
                            ', '
                        )
                        : String(
                            cwe ||
                            ''
                        ),

                source:
                    'Static Analysis (Docker)',

                metadata
            };
        }
    );
}

function normalizeBanditFindings(
    results
) {
    if (
        !Array.isArray(results)
    ) {
        return [];
    }

    return results.map(
        finding => ({
            tool:
                'Bandit',

            id:
                finding.test_id ||
                '',

            type:
                convertBanditType(
                    finding.test_id
                ),

            severity:
                convertBanditSeverity(
                    finding.issue_severity
                ),

            file:
                finding.filename ||
                'Unknown',

            line:
                finding.line_number ||
                0,

            message:
                finding.issue_text ||
                'Security issue detected',

            cwe:
                finding.issue_cwe?.id
                    ? `CWE-${finding.issue_cwe.id}`
                    : '',

            source:
                'Static Analysis (Docker)',

            confidence:
                finding.issue_confidence ||
                ''
        })
    );
}

function attachCodeContext(
    findings,
    files
) {
    if (
        !Array.isArray(files) ||
        files.length === 0
    ) {
        return findings;
    }

    const fileMap =
        new Map();

    for (
        const file of files
    ) {
        if (
            !file ||
            !file.path
        ) {
            continue;
        }

        const normalizedPath =
            String(
                file.path
            )
                .replace(
                    /\\/g,
                    '/'
                )
                .toLowerCase();

        const code =
            String(
                file.code ||
                ''
            );

        fileMap.set(
            normalizedPath,
            code
        );

        fileMap.set(
            path.basename(
                normalizedPath
            ),
            code
        );
    }

    return findings.map(
        finding => {
            const rawPath =
                String(
                    finding.file ||
                    ''
                ).replace(
                    /\\/g,
                    '/'
                );

            const cleanedPath =
                rawPath
                    .replace(
                        /^\/tmp\/code\//i,
                        ''
                    )
                    .replace(
                        /^tmp\/code\//i,
                        ''
                    );

            const lookupPath =
                cleanedPath.toLowerCase();

            const code =
                fileMap.get(
                    lookupPath
                ) ||
                fileMap.get(
                    path.basename(
                        lookupPath
                    )
                );

            const updated = {
                ...finding,

                file:
                    cleanedPath ||
                    finding.file
            };

            if (
                code
            ) {
                const lines =
                    code.split(
                        '\n'
                    );

                const lineNo =
                    parseInt(
                        finding.line,
                        10
                    );

                if (
                    !Number.isNaN(
                        lineNo
                    ) &&
                    lineNo > 0
                ) {
                    const start =
                        Math.max(
                            0,
                            lineNo - 5
                        );

                    const end =
                        Math.min(
                            lines.length,
                            lineNo + 5
                        );

                    updated.codeContext =
                        lines
                            .slice(
                                start,
                                end
                            )
                            .map(
                                (
                                    line,
                                    index
                                ) =>
                                    `${start + index + 1}: ${line}`
                            )
                            .join(
                                '\n'
                            );
                }
            }

            return updated;
        }
    );
}

function deduplicateFindings(
    findings
) {
    const seen =
        new Set();

    return findings.filter(
        finding => {
            const key =
                [
                    finding.tool,
                    finding.id,
                    finding.file,
                    finding.line,
                    finding.message
                ].join('|');

            if (
                seen.has(key)
            ) {
                return false;
            }

            seen.add(
                key
            );

            return true;
        }
    );
}

async function runStaticAnalysis(
    filesOrPath
) {
    if (
        !Array.isArray(
            filesOrPath
        )
    ) {
        return [];
    }

    console.log(
        `[docker-scanner] Received ${filesOrPath.length} workspace files`
    );

    const filteredFiles =
        filterSourceFiles(
            filesOrPath
        );

    if (
        filteredFiles.length === 0
    ) {
        console.log(
            '[docker-scanner] No relevant source files to scan'
        );

        return [];
    }

    const raw =
        await runScannersInContainer(
            filteredFiles
        );

    const semgrepFindings =
        normalizeSemgrepFindings(
            raw.semgrep ||
            []
        );

    const banditFindings =
        normalizeBanditFindings(
            raw.bandit ||
            []
        );

    const allFindings =
        deduplicateFindings([
            ...semgrepFindings,
            ...banditFindings
        ]);

    const enrichedFindings =
        attachCodeContext(
            allFindings,
            filteredFiles
        );

    console.log(
        `[docker-scanner] Total: ${enrichedFindings.length} ` +
        `(Semgrep ${semgrepFindings.length}, ` +
        `Bandit ${banditFindings.length})`
    );

    return enrichedFindings;
}

module.exports = {
    checkDocker,
    runStaticAnalysis,
    filterSourceFiles
};