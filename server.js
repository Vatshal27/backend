'use strict';

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('node:path');

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

const {
    analyzeFindings,
} = require('./llm/analyzer');

const {
    cleanupExpiredReports,
} = require('./docker/report-writer');

const { MODEL } = require('./llm/ollama');

const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const PORT = 3000;

const REPORT_CLEANUP_INTERVAL_MS =
    60 * 60 * 1000;

const REPORTS_DIR =
    path.join(
        __dirname,
        'reports'
    );

const OLLAMA_TAGS_URL =
    'http://localhost:11434/api/tags';

function validateSandboxTarget(targetUrl) {
    if (!targetUrl) {
        throw new Error(
            'Project validation requires a targetUrl.'
        );
    }

    let parsed;

    try {
        parsed = new URL(targetUrl);
    } catch {
        throw new Error(
            'Invalid targetUrl.'
        );
    }

    if (
        parsed.protocol !== 'http:' &&
        parsed.protocol !== 'https:'
    ) {
        throw new Error(
            'Project validation only supports HTTP or HTTPS.'
        );
    }

    const allowedHosts = [
        'localhost',
        '127.0.0.1',
        '::1'
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

function getErrorMessage(error) {
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

    return error.message || String(error);
}

async function cleanupLocalReports() {
    try {
        const result =
            await cleanupExpiredReports(
                REPORTS_DIR
            );

        if (
            result.deleted > 0
        ) {
            console.log(
                `[reports] Deleted ${result.deleted} expired report file(s).`
            );
        }
    } catch (error) {
        console.error(
            '[reports] Cleanup failed:',
            getErrorMessage(error)
        );
    }
}

app.get(
    '/runtime/discover',
    async (_req, res) => {
        try {
            const runtimes =
                await discoverRuntimes();

            res.json({
                ok: true,
                runtimes,
            });
        } catch (error) {
            res.status(500).json({
                ok: false,
                error:
                    error instanceof Error
                        ? error.message
                        : String(error),
            });
        }
    }
);

app.post(
    '/runtime/check',
    async (req, res) => {
        try {
            const targetUrl =
                req.body?.targetUrl;

            if (!targetUrl) {
                return res.status(400).json({
                    ok: false,
                    error:
                        'targetUrl is required.',
                });
            }

            const result =
                await checkRuntime(
                    targetUrl
                );

            return res.json({
                ok: true,
                ...result,
            });
        } catch (error) {
            return res.status(400).json({
                ok: false,
                error:
                    error instanceof Error
                        ? error.message
                        : String(error),
            });
        }
    }
);

app.get(
    '/health',
    async (_req, res) => {
        const llmEnabled =
            String(
                process.env.LLM_ENABLED || 'false'
            ).toLowerCase() === 'true';

        if (!llmEnabled) {
            return res.json({
                status: 'ok',
                model: MODEL,
                ollama: 'disabled',
            });
        }

        try {
            await axios.get(
                OLLAMA_TAGS_URL,
                { timeout: 5000 }
            );

            return res.json({
                status: 'ok',
                model: MODEL,
                ollama: 'connected',
            });
        } catch {
            return res.status(503).json({
                status: 'error',
                model: MODEL,
                ollama: 'disconnected',
            });
        }
    }
);

app.post(
    '/analyze-project',
    async (req, res) => {
        console.log(
            '[server] Starting security scan...'
        );

        try {
            const files =
                Array.isArray(req.body?.files)
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
                filesScanned: files.length,
                model: MODEL,
            });
        } catch (error) {
            console.error(
                '[server] Analysis failed:',
                error
            );

            return res.status(500).json({
                error: 'Analysis failed',
                detail: error.message,
            });
        }
    }
);

app.post(
    '/sandbox/run',
    async (req, res) => {
        const findings =
            req.body?.findings;

        if (
            !Array.isArray(findings)
        ) {
            return res.status(400).json({
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
        } catch (error) {
            console.error(
                '[sandbox] Error:',
                getErrorMessage(error)
            );

            return res.status(400).json({
                error:
                    getErrorMessage(error),
            });
        }
    }
);

app.post(
    '/sandbox/stop',
    async (req, res) => {
        try {
            const sandboxId =
                req.body?.sandboxId;

            if (!sandboxId) {
                return res.status(400).json({
                    error:
                        'sandboxId is required.',
                });
            }

            const result =
                await stopSandbox(
                    sandboxId
                );

            return res.json(result);
        } catch (error) {
            return res.status(500).json({
                error:
                    getErrorMessage(error),
            });
        }
    }
);

app.get(
    '/sandbox/check',
    async (_req, res) => {
        try {
            const result =
                await checkDocker();

            return res.json(result);
        } catch (error) {
            return res.status(503).json({
                error:
                    getErrorMessage(error),
            });
        }
    }
);

app.listen(
    PORT,
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
                    process.env.LLM_ENABLED || 'false'
                ).toLowerCase() === 'true'
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