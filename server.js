'use strict';

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('node:path');
const { createLocalOnlyMiddleware } = require('./http/local-only');

const {
    checkDocker,
    runSandbox,
    stopSandbox,
} = require('./docker/sandbox');

const {
    discoverRuntimes,
    checkRuntime,
} = require('./runtime');

const {
    runStaticAnalysis,
} = require('./docker-scanner');
const { createJobManager } = require('./jobs/manager');
const { createSecurityRouter } = require('./jobs/routes');
const { getScanProfiles, runSupplementaryChecks } = require('./security/profiles');
const {
    analyzeFindings,
} = require('./llm/analyzer');

const {
    cleanupExpiredReports,
} = require('./docker/report-writer');

const mailRoutes =
    require('./mail/mail-routes');

const {
    MODEL,
} = require('./llm/ollama');

const app =
    express();

const corsOptions = {
    origin(origin, callback) {
        if (!origin) return callback(null, true);
        try {
            const hostname = new URL(origin).hostname.toLowerCase();
            return callback(null, ['localhost', '127.0.0.1', '[::1]', '::1'].includes(hostname));
        } catch {
            return callback(null, false);
        }
    },
};

app.use(createLocalOnlyMiddleware());

app.use(cors(corsOptions));

app.use(
    express.json({
        limit: '5mb',
    })
);

app.use(
    '/api/mail',
    mailRoutes
);

const securityJobManager = createJobManager();
app.use('/security', createSecurityRouter({
    manager: securityJobManager,
    capabilities: () => ({
        profiles: getScanProfiles().map(profile => ({
            id: profile.id, name: profile.name, supported: true,
            checks: profile.checks,
        })),
        limitations: [
            'Safe Simulation uses synthetic fixtures and never confirms a project vulnerability.',
            'Authentication, API specification and real-browser checks are unsupported.',
        ],
    }),
    execute: async (request, { signal, emit, checkpoint }) => {
        emit({ stage: 'source-analysis', status: 'running', description: 'Running existing static source analysis.' });
        const staticFindings = await runStaticAnalysis(
            request.files.map(file => ({ path: file.path, code: file.content })),
            { signal, onEvent: emit }
        );
        if (signal.aborted) throw signal.reason;
        emit({ stage: 'profile-checks', status: 'running', description: `Running ${request.profile} profile checks.` });
        const supplementary = await runSupplementaryChecks({
            files: request.files, profile: request.profile, signal,
            onEvent: event => emit({ stage: event.check || 'profile-checks', status: event.status, description: `${event.check || 'Check'}: ${event.status}.` }),
            options: request.options,
        });
        const findings = [...staticFindings, ...supplementary.findings];
        const checkpointBase = {
            kind: 'scan', profile: request.profile, filesScanned: request.files.length,
            findings, staticFindings,
            coverage: [...(staticFindings.coverage ? [{ check: 'source', status: staticFindings.coverage.status,
                filesScanned: staticFindings.coverage.filesScanned, reason: staticFindings.coverage.reason,
                tools: staticFindings.coverage.tools }] : []), ...supplementary.coverage],
            llmUsed: false, llmEnabled: false,
            provenance: { mode: 'workspace-source-analysis', synthetic: false, project: true },
        };
        checkpoint(checkpointBase);
        const sourceFileCount = request.files.filter(file => /\.(?:js|mjs|cjs|ts|py|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/i.test(file.path)).length;
        const configuredLlmEnabled = String(process.env.LLM_ENABLED || 'false').toLowerCase() === 'true';
        const llmEnabled = configuredLlmEnabled && request.profile !== 'dependencies' && request.profile !== 'infrastructure';
        let analyzedFindings = findings;
        let llmUsed = false;
        let llmReason = !configuredLlmEnabled ? 'LLM analysis was disabled.'
            : !llmEnabled ? 'LLM source review was skipped for this non-source profile.'
                : 'LLM analysis was not executed.';
        if (llmEnabled && sourceFileCount > 0) {
            checkpoint({ ...checkpointBase, llmEnabled: true, llmReason: 'Local LLM analysis is running.' });
            emit({ stage: 'llm-analysis', status: 'running', description: 'Running optional local LLM analysis.' });
            try {
                analyzedFindings = await analyzeFindings(findings, request.files.map(file => ({ path: file.path, code: file.content })));
                llmUsed = true;
                llmReason = 'Local LLM analysis completed.';
            } catch (error) {
                if (signal.aborted) throw signal.reason;
                llmReason = 'Local LLM analysis failed; static/profile findings are preserved.';
                checkpoint({ ...checkpointBase, llmEnabled: true, llmUsed: false, llmReason });
                emit({ stage: 'llm-analysis', status: 'failed', description: llmReason });
            }
        } else if (llmEnabled) {
            llmReason = 'LLM analysis was enabled but skipped because no supported source files were supplied.';
        }
        const staticCoverage = staticFindings.coverage;
        const coverage = [
            { check: 'source', status: sourceFileCount === 0 ? 'skipped' : (staticCoverage?.status === 'complete' ? 'tested' : 'inconclusive'),
                filesSubmitted: sourceFileCount,
                filesScanned: staticCoverage?.filesScanned ?? 0,
                reason: sourceFileCount === 0 ? 'No supported source files were submitted to the static scanner.'
                    : (staticCoverage?.status === 'complete' ? 'Configured static scanners returned a result.' : (staticCoverage?.reason || 'Static scanner did not report complete per-tool coverage.')),
                tools: staticCoverage?.tools || null },
            ...supplementary.coverage.filter(item => item.check !== 'source'),
        ];
        const completedResult = {
            kind: 'scan', profile: request.profile, filesScanned: request.files.length,
            findings: analyzedFindings, staticFindings,
            llmFindings: llmUsed ? analyzedFindings.filter(finding => finding.source === 'ai') : [],
            coverage, llmUsed, llmEnabled, llmReason,
            provenance: { mode: 'workspace-source-analysis', synthetic: false, project: true },
        };
        checkpoint(completedResult);
        return completedResult;
    },
}));

const PORT =
    Number(process.env.PORT || 3000);

const REPORT_CLEANUP_INTERVAL_MS =
    60 * 60 * 1000;

const REPORTS_DIR =
    path.join(
        __dirname,
        'reports'
    );

const OLLAMA_TAGS_URL =
    'http://localhost:11434/api/tags';

function validateSandboxTarget(
    targetUrl
) {
    if (
        !targetUrl
    ) {
        throw new Error(
            'Project validation requires a targetUrl.'
        );
    }

    let parsed;

    try {
        parsed =
            new URL(
                targetUrl
            );
    } catch {
        throw new Error(
            'Invalid targetUrl.'
        );
    }

    if (
        parsed.protocol !==
            'http:' &&
        parsed.protocol !==
            'https:'
    ) {
        throw new Error(
            'Project validation only supports HTTP or HTTPS.'
        );
    }

    const allowedHosts = [
        'localhost',
        '127.0.0.1',
        '::1',
    ];

    if (
        !allowedHosts.includes(
            parsed.hostname.toLowerCase()
        )
    ) {
        throw new Error(
            'Project validation only allows local targets.'
        );
    }

    return parsed.toString();
}

function getErrorMessage(
    error
) {
    if (
        error.response &&
        error.response.data
    ) {
        return (
            error.response.data.detail ||
            error.response.data.error ||
            error.message
        );
    }

    return (
        error.message ||
        String(
            error
        )
    );
}

async function cleanupLocalReports() {
    try {
        const result =
            await cleanupExpiredReports(
                REPORTS_DIR
            );

        if (
            result.deleted >
            0
        ) {
            console.log(
                `[reports] Deleted ${result.deleted} expired report file(s).`
            );
        }
    } catch (
        error
    ) {
        console.error(
            '[reports] Cleanup failed:',
            getErrorMessage(
                error
            )
        );
    }
}

app.get(
    '/runtime/discover',
    async (
        _req,
        res
    ) => {
        try {
            const runtimes =
                await discoverRuntimes();

            return res.json({
                ok: true,
                runtimes,
            });
        } catch (
            error
        ) {
            return res
                .status(500)
                .json({
                    ok: false,

                    error:
                        error instanceof Error
                            ? error.message
                            : String(
                                  error
                              ),
                });
        }
    }
);

app.post(
    '/runtime/check',
    async (
        req,
        res
    ) => {
        try {
            const targetUrl =
                req.body?.targetUrl;

            if (
                !targetUrl
            ) {
                return res
                    .status(400)
                    .json({
                        ok: false,

                        error:
                            'targetUrl is required.',
                    });
            }

            const validatedTargetUrl = validateSandboxTarget(targetUrl);
            const result = await checkRuntime(validatedTargetUrl);

            return res.json({
                ok: true,
                ...result,
            });
        } catch (
            error
        ) {
            return res
                .status(400)
                .json({
                    ok: false,

                    error:
                        error instanceof Error
                            ? error.message
                            : String(
                                  error
                              ),
                });
        }
    }
);

app.get(
    '/health',
    async (
        _req,
        res
    ) => {
        const llmEnabled =
            String(
                process.env
                    .LLM_ENABLED ||
                    'false'
            ).toLowerCase() ===
            'true';

        if (
            !llmEnabled
        ) {
            return res.json({
                status:
                    'ok',

                model:
                    MODEL,

                ollama:
                    'disabled',
            });
        }

        try {
            await axios.get(
                OLLAMA_TAGS_URL,
                {
                    timeout:
                        5000,
                }
            );

            return res.json({
                status:
                    'ok',

                model:
                    MODEL,

                ollama:
                    'connected',
            });
        } catch {
            return res
                .status(503)
                .json({
                    status:
                        'error',

                    model:
                        MODEL,

                    ollama:
                        'disconnected',
                });
        }
    }
);

app.post(
    '/analyze-project',
    async (
        req,
        res
    ) => {
        console.log(
            '[server] Starting security scan...'
        );

        try {
            const files =
                Array.isArray(
                    req.body?.files
                )
                    ? req.body.files
                    : [];

            console.log(
                `[server] Received ${files.length} files from VS Code`
            );

            const staticFindings =
                await runStaticAnalysis(
                    files
                );

            console.log(
                `[server] Static findings: ${staticFindings.length}`
            );

            const findings =
                await analyzeFindings(
                    staticFindings,
                    files
                );

            return res.json({
                findings,
                staticFindings,

                filesScanned:
                    files.length,

                scannerCoverage: staticFindings.coverage || { status: 'unknown', reason: 'Static scanner coverage was not reported.' },

                model:
                    MODEL,
            });
        } catch (
            error
        ) {
            console.error(
                '[server] Analysis failed:',
                error
            );

            return res
                .status(500)
                .json({
                    error:
                        'Analysis failed',

                    detail:
                        error.message,
                });
        }
    }
);

app.post(
    '/sandbox/run',
    async (
        req,
        res
    ) => {
        const findings =
            req.body?.findings;

        if (
            !Array.isArray(
                findings
            )
        ) {
            return res
                .status(400)
                .json({
                    error:
                        'Findings must be an array.',
                });
        }

        const mode =
            req.body?.mode ===
            'project-validation'
                ? 'project-validation'
                : 'simulation';

        const targetUrl =
            req.body?.targetUrl;

        try {
            let validatedTargetUrl;

            if (
                mode ===
                'project-validation'
            ) {
                validatedTargetUrl =
                    validateSandboxTarget(
                        targetUrl
                    );

                console.log(
                    `[sandbox] Project validation target: ${validatedTargetUrl}`
                );
            }

            const report =
                await runSandbox({
                    findings,
                    mode,

                    targetUrl:
                        validatedTargetUrl,
                });

            return res.json(
                report
            );
        } catch (
            error
        ) {
            console.error(
                '[sandbox] Error:',
                getErrorMessage(
                    error
                )
                
            );

            return res
                .status(400)
                .json({
                    error:
                        getErrorMessage(
                            error
                        ),
                });
        }
    }
);

app.post(
    '/sandbox/stop',
    async (
        req,
        res
    ) => {
        try {
            const sandboxId =
                req.body?.sandboxId;

            if (
                !sandboxId
            ) {
                return res
                    .status(400)
                    .json({
                        error:
                            'sandboxId is required.',
                    });
            }

            const result =
                await stopSandbox(
                    sandboxId
                );

            return res.json(
                result
            );
        } catch (
            error
        ) {
            return res
                .status(500)
                .json({
                    error:
                        getErrorMessage(
                            error
                        ),
                });
        }
    }
);

app.get(
    '/sandbox/check',
    async (
        _req,
        res
    ) => {
        try {
            const result =
                await checkDocker();

            return res.json(
                result
            );
        } catch (
            error
        ) {
            return res
                .status(503)
                .json({
                    error:
                        getErrorMessage(
                            error
                        ),
                });
        }
    }
);

if (require.main === module) app.listen(
    PORT,
    '127.0.0.1',
    () => {
        console.log(
            `[server] Running on http://localhost:${PORT}`
        );

        console.log(
            `[server] Model: ${MODEL}`
        );

        console.log(
            `[server] LLM: ${
                String(
                    process.env
                        .LLM_ENABLED ||
                        'false'
                ).toLowerCase() ===
                'true'
                    ? 'enabled'
                    : 'disabled'
            }`
        );

        cleanupLocalReports();

        const cleanupTimer =
            setInterval(
                cleanupLocalReports,
                REPORT_CLEANUP_INTERVAL_MS
            );

        cleanupTimer.unref();

        console.log(
            '[reports] 24-hour local report retention enabled.'
        );
    }
);

module.exports = { app, validateSandboxTarget };