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
  async (req, res) => {
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
      const {
        targetUrl,
      } = req.body || {};

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

      res.json({
        ok: true,
        ...result,
      });
    } catch (error) {
      res.status(400).json({
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
        try {
            await axios.get(
                OLLAMA_TAGS_URL,
                { timeout: 5000 }
            );

            res.json({
                status: 'ok',
                model: MODEL,
                ollama: 'connected',
            });
        } catch {
            res.status(503).json({
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
            let staticFindings = [];

            // Accept either an array of files or a projectPath.
            if (Array.isArray(req.body.files)) {
                staticFindings = await runStaticAnalysis(
                    req.body.files
                );
            } else {
                staticFindings = await runStaticAnalysis(
                    req.body.projectPath || '.'
                );
            }

            console.log(
                `[server] Static findings: ${staticFindings.length}`
            );

            // Run LLM analysis through the centralized analyzer.
            // Pass source files so AI audit runs even if SAST found 0 issues.
            const findings = await analyzeFindings(staticFindings, req.body.files);

            res.json({
                findings,
                staticFindings,
                filesScanned: Array.isArray(req.body.files)
                    ? req.body.files.length
                    : 0,
                model: MODEL,
            });
        } catch (error) {
            console.error(
                '[server] Error:',
                getErrorMessage(error)
            );

            res.status(500).json({
                error: 'Analysis failed',
                detail: getErrorMessage(error),
            });
        }
    }
);


app.post('/sandbox/run', async (req, res) => {
  try {
    const findings =
      req.body &&
      Array.isArray(req.body.findings)
        ? req.body.findings
        : [];

    const mode =
      req.body?.mode ===
      'project-validation'
        ? 'project-validation'
        : 'simulation';

    if (!findings.length) {
      return res.status(400).json({
        error:
          'At least one finding is required to run the sandbox.',
      });
    }

    const report =
      await runSandbox(
        findings,
        { mode }
      );

    return res.json(
      report
    );
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
});




app.post(
    '/sandbox/stop',
    async (_req, res) => {
        try {
            const result = await stopSandbox();
            res.json(result);
        } catch (error) {
            res.status(500).json({
                error: getErrorMessage(error),
            });
        }
    }
);



app.get(
    '/sandbox/check',
    async (_req, res) => {
        try {
            const result = await checkDocker();
            res.json(result);
        } catch (error) {
            res.status(503).json({
                error: getErrorMessage(error),
            });
        }
    }
);



app.listen(PORT, () => {
    console.log(
        `[server] Running on http://localhost:${PORT}`
    );

    console.log(
        `[server] Model: ${MODEL}`
    );

    console.log(
        '[server] Ollama must be running: ollama serve'
    );
});