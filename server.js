'use strict';

const express = require('express');
const cors = require('cors');
const axios = require('axios');

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

const { MODEL } = require('./llm/ollama');

const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const PORT = 3000;

const OLLAMA_TAGS_URL =
    'http://localhost:11434/api/tags';

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

/* Analysis route is always available. */
app.post(
    '/analyze-project',
    async (req, res) => {
        console.log(
            '[server] Starting security scan...'
        );

        try {
            let staticFindings = [];

            if (
                Array.isArray(
                    req.body?.files
                )
            ) {
                staticFindings =
                    await runStaticAnalysis(
                        req.body.files
                    );
            } else {
                staticFindings =
                    await runStaticAnalysis(
                        req.body?.projectPath || '.'
                    );
            }

            console.log(
                `[server] Static findings: ${staticFindings.length}`
            );

            const findings =
                await analyzeFindings(
                    staticFindings,
                    req.body?.files
                );

            return res.json({
                findings,
                staticFindings,
                filesScanned:
                    Array.isArray(
                        req.body?.files
                    )
                        ? req.body.files.length
                        : 0,
                model: MODEL,
            });
        } catch (error) {
            console.error(
                '[server] Error:',
                getErrorMessage(error)
            );

            return res.status(500).json({
                error: 'Analysis failed',
                detail: getErrorMessage(error),
            });
        }
    }
);

app.post(
    '/sandbox/run',
    async (req, res) => {
        try {
            const findings =
                Array.isArray(
                    req.body?.findings
                )
                    ? req.body.findings
                    : [];

            const mode =
                req.body?.mode ===
                'project-validation'
                    ? 'project-validation'
                    : 'simulation';

            const targetUrl =
                req.body?.targetUrl;

            if (!findings.length) {
                return res.status(400).json({
                    error:
                        'At least one finding is required to run the sandbox.',
                });
            }

            if (
                mode === 'project-validation' &&
                !targetUrl
            ) {
                return res.status(400).json({
                    error:
                        'targetUrl is required for project validation.',
                });
            }

            const report =
                await runSandbox({
                    findings,
                    mode,
                    targetUrl,
                });

            return res.json(report);
        } catch (error) {
            console.error(
                '[sandbox]',
                error
            );

            return res.status(500).json({
                error:
                    error instanceof Error
                        ? error.message
                        : String(error),
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
    }
);