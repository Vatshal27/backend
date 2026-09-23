'use strict';

const Docker = require('dockerode');
const fs = require('fs');
const os = require('os');
const path = require('path');

const docker = new Docker();

const SCANNER_IMAGE =
    'sentinelai-scanner:latest';


const IGNORED_PATH_PATTERNS = [
    /(^|[\\/])\.git([\\/]|$)/i,
    /(^|[\\/])\.github([\\/]|$)/i,
    /(^|[\\/])\.gitlab([\\/]|$)/i,
    /(^|[\\/])node_modules([\\/]|$)/i,
    /(^|[\\/])__pycache__([\\/]|$)/i,
    /(^|[\\/])\.venv([\\/]|$)/i,
    /(^|[\\/])venv([\\/]|$)/i,
    /(^|[\\/])dist([\\/]|$)/i,
    /(^|[\\/])build([\\/]|$)/i,
    /(^|[\\/])coverage([\\/]|$)/i,
    /(^|[\\/])\.next([\\/]|$)/i,
    /(^|[\\/])\.nuxt([\\/]|$)/i,
    /(^|[\\/])target([\\/]|$)/i,
    /(^|[\\/])vendor([\\/]|$)/i,
    /(^|[\\/])out([\\/]|$)/i,
    /(^|[\\/])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i,
    /(^|[\\/])composer\.lock$/i,
    /(^|[\\/])README(?:\.[^\\/]+)?$/i,
    /(^|[\\/])LICENSE(?:\.[^\\/]+)?$/i,
];

const SOURCE_EXTENSIONS = new Set([
    '.js',
    '.jsx',
    '.ts',
    '.tsx',
    '.mjs',
    '.cjs',
    '.py',
    '.java',
    '.c',
    '.cpp',
    '.cc',
    '.h',
    '.hpp',
    '.cs',
    '.go',
    '.rs',
    '.php',
    '.rb',
    '.kt',
    '.kts',
    '.swift',
    '.scala',
    '.dart',
    '.sql',
    '.sh',
    '.bash',
    '.zsh',
    '.ps1',
    '.html',
    '.htm',
    '.vue',
    '.svelte',
]);

const SECURITY_CONFIG_NAMES = new Set([
    'dockerfile',
    'nginx.conf',
    'application.yml',
    'application.yaml',
]);

const SECURITY_CONFIG_EXTENSIONS = new Set([
    '.env',
]);

function checkDocker() {
    return docker
        .info()
        .then(info => ({
            ok: true,
            version: info.ServerVersion,
        }))
        .catch(error => ({
            ok: false,
            reason: String(
                error.message || error
            ),
        }));
}

async function imageExists(imageName) {
    try {
        await docker
            .getImage(imageName)
            .inspect();

        return true;
    } catch {
        return false;
    }
}

function normalizeFilePath(filePath) {
    return String(filePath || '')
        .replace(/\\/g, '/')
        .replace(/^file:\/\//i, '')
        .trim();
}

function isRelevantFile(file) {
    if (
        !file ||
        typeof file.path !== 'string'
    ) {
        return false;
    }

    const filePath =
        normalizeFilePath(
            file.path
        );

    if (!filePath) {
        return false;
    }

    if (
        IGNORED_PATH_PATTERNS.some(
            pattern =>
                pattern.test(filePath)
        )
    ) {
        return false;
    }

    const fileName =
        path.basename(
            filePath
        ).toLowerCase();

    if (
        fileName.startsWith('readme.') ||
        fileName === 'readme' ||
        fileName.startsWith('license.') ||
        fileName === 'license'
    ) {
        return false;
    }

    if (
        fileName.endsWith('.txt')
    ) {
        return false;
    }

    if (
        SECURITY_CONFIG_NAMES.has(
            fileName
        )
    ) {
        return true;
    }

    const extension =
        path.extname(
            fileName
        );

    if (
        SECURITY_CONFIG_EXTENSIONS.has(
            extension
        )
    ) {
        return true;
    }

    return SOURCE_EXTENSIONS.has(
        extension
    );
}

function filterSourceFiles(files) {
    if (!Array.isArray(files)) {
        return [];
    }

    const filtered =
        files.filter(
            isRelevantFile
        );

    console.log(
        `[docker-scanner] File filter: ${files.length} -> ${filtered.length}`
    );

    return filtered;
}

function safeRelativePath(filePath) {
    const normalized =
        normalizeFilePath(
            filePath
        ).replace(
            /^\/+/,
            ''
        );

    const relative =
        path.posix.normalize(
            normalized
        );

    if (
        relative === '..' ||
        relative.startsWith('../') ||
        path.posix.isAbsolute(
            relative
        )
    ) {
        return null;
    }

    return relative;
}

function writeScanFiles(
    files,
    root
) {
    for (const file of files) {
        const relativePath =
            safeRelativePath(
                file.path
            );

        if (!relativePath) {
            console.warn(
                `[docker-scanner] Skipping unsafe path: ${file.path}`
            );

            continue;
        }

        const destination =
            path.join(
                root,
                relativePath
            );

        const parent =
            path.dirname(
                destination
            );

        fs.mkdirSync(
            parent,
            {
                recursive: true,
                mode: 0o755,
            }
        );

        fs.writeFileSync(
            destination,
            String(
                file.code || ''
            ),
            {
                encoding: 'utf8',
                mode: 0o644,
            }
        );
    }
}

function makeScanFilesReadable(
    root
) {
    fs.chmodSync(
        root,
        0o755
    );

    const entries =
        fs.readdirSync(
            root,
            {
                withFileTypes: true,
            }
        );

    for (const entry of entries) {
        const target =
            path.join(
                root,
                entry.name
            );

        if (
            entry.isDirectory()
        ) {
            makeScanFilesReadable(
                target
            );
        } else {
            fs.chmodSync(
                target,
                0o644
            );
        }
    }
}

function convertSemgrepType(
    checkId
) {
    const id =
        String(checkId || '')
            .toLowerCase();

    if (id.includes('sql')) {
        return 'SQL Injection';
    }

    if (
        id.includes('command') ||
        id.includes('shell')
    ) {
        return 'Command Injection';
    }

    if (
        id.includes('xss') ||
        id.includes('cross-site')
    ) {
        return 'Cross Site Scripting';
    }

    if (
        id.includes('eval') ||
        id.includes('code-injection')
    ) {
        return 'Code Injection';
    }

    if (
        id.includes('path') ||
        id.includes('traversal')
    ) {
        return 'Path Traversal';
    }

    if (
        id.includes('secret') ||
        id.includes('password') ||
        id.includes('credential')
    ) {
        return 'Hardcoded Secret';
    }

    return 'Security Issue';
}

function convertSemgrepSeverity(
    level
) {
    switch (
        String(level || '')
            .toUpperCase()
    ) {
        case 'ERROR':
            return 'High';

        case 'WARNING':
            return 'Medium';

        default:
            return 'Low';
    }
}

function convertBanditType(
    testId
) {
    const map = {
        B602: 'Command Injection',
        B603: 'Subprocess Execution',
        B605: 'Shell Injection',
        B607: 'Partial Command Injection',
        B307: 'Dangerous Eval',
        B105: 'Hardcoded Password',
        B106: 'Hardcoded Password',
        B108: 'Insecure Temporary File',
        B301: 'Insecure Deserialization',
        B506: 'Unsafe YAML Load',
    };

    return (
        map[testId] ||
        'Python Security Issue'
    );
}

function convertBanditSeverity(
    level
) {
    switch (
        String(level || '')
            .toUpperCase()
    ) {
        case 'HIGH':
            return 'High';

        case 'MEDIUM':
            return 'Medium';

        default:
            return 'Low';
    }
}

function normalizeSemgrepFindings(
    results
) {
    return results.map(
        finding => ({
            tool: 'Semgrep',

            id:
                finding.check_id ||
                '',

            type:
                convertSemgrepType(
                    finding.check_id
                ),

            severity:
                convertSemgrepSeverity(
                    finding.extra?.severity
                ),

            file:
                finding.path ||
                'Unknown',

            line:
                finding.start?.line ||
                0,

            message:
                finding.extra?.message ||
                'Security issue detected',

            cwe:
                finding.extra?.metadata?.cwe ||
                '',

            source:
                'Static Analysis (Docker)',
        })
    );
}

function normalizeBanditFindings(
    results
) {
    return results.map(
        finding => ({
            tool: 'Bandit',

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
        })
    );
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
                String(fileCount) +
                '}))\'',

            'printf "\\n__SENTINEL_RESULT_END__\\n"',
    ].join('\n');
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

                User: '0:0',

                Entrypoint: [],

                Cmd: [
                    'sh',
                    '-c',
                    buildScannerCommand(
                        files.length
                    ),
                ],

                WorkingDir:
                    '/workspace',

                HostConfig: {
                    Binds: [
                        `${scanDirectory}:/workspace:ro`,
                    ],

                    Memory:
                        512 * 1024 * 1024,

                    NanoCpus:
                        1_000_000_000,

                    PidsLimit: 256,

                    CapDrop: [
                        'ALL',
                    ],

                    SecurityOpt: [
                        'no-new-privileges:true',
                    ],

                    AutoRemove: false,
                },
            });

        await container.start();
const waitResult =
    await container.wait();

        const rawLogs =
            await container.logs({
                stdout: true,
                stderr: false,
            });

        const output =
    rawLogs.toString('utf8').trim();

console.log(
    `[docker-scanner] Container exited with code ${waitResult.StatusCode}`
);

try {
    const result =
        JSON.parse(output);

    if (
        result &&
        Array.isArray(result.semgrep) &&
        Array.isArray(result.bandit)
    ) {
        return result;
    }
} catch (error) {
    console.error(
        '[docker-scanner] Scanner JSON parse failed:',
        error.message
    );
}

        console.log(
            `[docker-scanner] Container exited with code ${waitResult.StatusCode}`
        );

        const result =
            extractScannerResult(
                output
            );

        if (result) {
            return result;
        }

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
                files.length,
        };
    } finally {
        if (container) {
            try {
                await container.remove({
                    force: true,
                });
            } catch {
                // Ignore cleanup failures.
            }
        }

        fs.rmSync(
            scanDirectory,
            {
                recursive: true,
                force: true,
            }
        );
    }
}

function extractScannerResult(logs) {
    const startMarker =
        '__SENTINEL_RESULT_START__';

    const endMarker =
        '__SENTINEL_RESULT_END__';

    const startIndex =
        logs.indexOf(startMarker);

    if (startIndex === -1) {
        console.error(
            '[docker-scanner] Result start marker not found.'
        );
        return null;
    }

    const jsonStart =
        startIndex + startMarker.length;

    const endIndex =
        logs.indexOf(
            endMarker,
            jsonStart
        );

    if (endIndex === -1) {
        console.error(
            '[docker-scanner] Result end marker not found.'
        );
        return null;
    }

    let jsonText =
        logs
            .slice(
                jsonStart,
                endIndex
            )
            .trim();

    jsonText =
        jsonText.replace(
            /^@/,
            ''
        ).trim();

    try {
        return JSON.parse(
            jsonText
        );
    } catch (error) {
        console.error(
            '[docker-scanner] Result JSON parse failed:',
            error.message
        );

        console.error(
            '[docker-scanner] Raw result:',
            jsonText.slice(0, 1000)
        );

        return null;
    }
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

    for (const file of files) {
        if (
            !file.path ||
            typeof file.code !== 'string'
        ) {
            continue;
        }

        const normalizedPath =
            normalizeFilePath(
                file.path
            ).toLowerCase();

        fileMap.set(
            normalizedPath,
            file.code
        );

        fileMap.set(
            path.basename(
                normalizedPath
            ),
            file.code
        );
    }

    return findings.map(
        finding => {
            const rawPath =
                String(
                    finding.file || ''
                )
                    .replace(
                        /\\/g,
                        '/'
                    );

            const cleanedPath =
                rawPath
                    .replace(
                        /^\/workspace\//i,
                        ''
                    )
                    .replace(
                        /^workspace\//i,
                        ''
                    )
                    .replace(
                        /^\/tmp\/code\//i,
                        ''
                    );

            const lookupPath =
                cleanedPath
                    .toLowerCase();

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
                    finding.file,
            };

            if (code) {
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
                                    `${
                                        start +
                                        index +
                                        1
                                    }: ${line}`
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
            raw.semgrep || []
        );

    const banditFindings =
        normalizeBanditFindings(
            raw.bandit || []
        );

    const allFindings = [
        ...semgrepFindings,
        ...banditFindings,
    ];

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
    filterSourceFiles,
};