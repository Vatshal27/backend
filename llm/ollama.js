'use strict';

const axios = require('axios');

const OLLAMA_URL =
    process.env.OLLAMA_URL ||
    'http://localhost:11434/api/generate';

const MODEL =
    process.env.MODEL ||
    'qwen2.5:3b';

const OLLAMA_OPTIONS = {
    temperature: 0.1,
    num_predict: 700,
    num_ctx: 4096,
    top_p: 0.9,
    top_k: 40,
    repeat_penalty: 1.1,
};

async function askOllama(prompt) {
    const timerLabel =
        `Ollama Response ${Date.now()}-${Math.random()
            .toString(36)
            .slice(2, 8)}`;

    console.log(
        `[LLM] Sending request to Ollama using ${MODEL}...`
    );

    console.time(timerLabel);

    try {
        const response = await axios.post(
            OLLAMA_URL,
            {
                model: MODEL,
                prompt,
                stream: false,
                format: 'json',
                keep_alive: '10m',
                options: OLLAMA_OPTIONS,
            },
            {
                timeout: 180000,
            }
        );

        console.timeEnd(timerLabel);

        if (response.data?.error) {
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

        console.log(
            '[LLM] Response received'
        );

        return response.data.response;
    } catch (error) {
        console.timeEnd(timerLabel);

        console.error(
            '[LLM] Error:',
            error.response?.data ||
            error.message
        );

        throw error;
    }
}

module.exports = {
    askOllama,
    MODEL,
};