'use strict';

const axios = require('axios');

const OLLAMA_URL = 'http://localhost:11434/api/generate';
const MODEL = 'phi3:mini';

const OLLAMA_OPTIONS = {
    temperature: 0.1,
    num_predict: 700,
    num_ctx: 4096,
    top_p: 0.9,
    top_k: 40,
    repeat_penalty: 1.1,
};

async function askOllama(prompt) {
    console.log('[LLM] Sending request to Ollama...');
    console.time('Ollama Response');

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
            }
        );
        console.timeEnd('Ollama Response');

        if (response.data?.error) {
            throw new Error(response.data.error);
        }

        if (
            !response.data ||
            typeof response.data.response !== 'string'
        ) {
            throw new Error('Invalid Ollama response');
        }

        console.log('[LLM] Response received');

        return response.data.response;
    } catch (error) {
        console.timeEnd('Ollama Response');

        console.error(
            '[LLM] Error:',
            error.response?.data || error.message
        );

        throw error;
    }
}

module.exports = {
    askOllama,
    MODEL,
};