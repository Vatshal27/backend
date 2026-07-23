'use strict';

const express = require('express');
const cors = require('cors');
const axios = require('axios');

const {
    checkDocker,
    runSandbox,
    stopSandbox
} = require('./docker-sandbox');

const {
    runStaticAnalysis
} = require('./scanner/scanner');

const {
    buildSecurityPrompt
} = require('./scanner/prompt-builder');


const app = express();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

const PORT = 3000;

const OLLAMA_URL =
    'http://localhost:11434/api/generate';

const OLLAMA_TAGS_URL =
    'http://localhost:11434/api/tags';

const MODEL =
    'codellama:13b';



async function analyseWithOllama(prompt) {

    console.log(
        `[server] Prompt length: ${prompt.length}`
    );

    console.log(
        `[server] Sending request to ${MODEL}`
    );


    const response =
        await axios.post(
            OLLAMA_URL,
            {
                model: MODEL,
                prompt,
                stream: false,
                format: 'json',

                options: {
                    temperature: 0.1,
                    num_predict: 1200,
                    num_ctx: 4096
                }
            },
            {
                timeout: 600000
            }
        );


    if (response.data.error) {

        throw new Error(
            response.data.error
        );

    }


    if (
        !response.data ||
        typeof response.data.response !== 'string'
    ) {

        throw new Error(
            'Invalid Ollama response'
        );

    }


    return response.data.response;

}



function normaliseFinding(
    finding,
    index
) {

    return {

        id:
            String(
                finding.id ||
                `finding-${index + 1}`
            ),

        type:
            String(
                finding.type ||
                'Security Issue'
            ),

        severity:
            finding.severity || 'Medium',

        file:
            String(
                finding.file ||
                'Unknown'
            ),

        line:
            String(
                finding.line ||
                ''
            ),

        explanation:
            String(
                finding.explanation ||
                ''
            ),

        attackStory:
            Array.isArray(
                finding.attackStory
            )
                ? finding.attackStory
                : [],

        fix:
            String(
                finding.fix ||
                ''
            )
    };

}



function parseFindings(raw) {

    const cleaned =
        String(raw)
        .replace(/```json/gi, '')
        .replace(/```/g, '')
        .trim();


    const parsed =
        JSON.parse(cleaned);


    let findings;


    if (Array.isArray(parsed)) {

        findings = parsed;

    } else if (
        parsed &&
        Array.isArray(parsed.findings)
    ) {

        findings = parsed.findings;

    } else {

        throw new Error(
            'No findings returned'
        );

    }


    return findings
        .map(normaliseFinding)
        .filter(Boolean);

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




app.get(
    '/health',
    async (_req,res)=>{

        try {

            await axios.get(
                OLLAMA_TAGS_URL,
                {
                    timeout:5000
                }
            );


            res.json({

                status:'ok',
                model:MODEL,
                ollama:'connected'

            });


        } catch(error) {

            res.status(503).json({

                status:'error',
                model:MODEL,
                ollama:'disconnected'

            });

        }

    }
);



app.post(
    '/analyze-project',
    async(req,res)=>{

        console.log(
            '[server] Starting security scan...'
        );


        try {

            const staticFindings =
                await runStaticAnalysis(
                    req.body.projectPath || '.'
                );


            console.log(
                `[server] Static findings: ${staticFindings.length}`
            );


            const prompt =
                buildSecurityPrompt(
                    staticFindings
                );


            const raw =
                await analyseWithOllama(
                    prompt
                );


            const findings =
                parseFindings(
                    raw
                );


            res.json({

                findings,

                staticFindings,

                model:MODEL

            });


        } catch(error) {

            console.error(
                '[server] Error:',
                getErrorMessage(error)
            );


            res.status(500).json({

                error:'Analysis failed',

                detail:
                    getErrorMessage(error)

            });

        }

    }
);



app.post(
    '/sandbox/run',
    async(req,res)=>{

        const findings =
            req.body.findings || [];


        if(findings.length===0){

            return res.status(400).json({

                error:
                'No findings provided'

            });

        }


        try {

            const report =
                await runSandbox(
                    findings
                );


            res.json(report);


        } catch(error){

            res.status(500).json({

                error:
                getErrorMessage(error)

            });

        }

    }
);



app.post(
    '/sandbox/stop',
    async(_req,res)=>{

        try {

            const result =
                await stopSandbox();


            res.json(result);


        } catch(error){

            res.status(500).json({

                error:
                getErrorMessage(error)

            });

        }

    }
);



app.get(
    '/sandbox/check',
    async(_req,res)=>{

        try {

            const result =
                await checkDocker();


            res.json(result);


        } catch(error){

            res.status(503).json({

                error:
                getErrorMessage(error)

            });

        }

    }
);



app.listen(
    PORT,
    ()=>{

        console.log(
            `[server] Running on http://localhost:${PORT}`
        );

        console.log(
            `[server] Model: ${MODEL}`
        );

        console.log(
            '[server] Ollama must be running: ollama serve'
        );

    }
);