const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const OLLAMA_URL = 'http://localhost:11434/api/generate';
const MODEL = 'phi3:mini';


const MAX_CHARS_PER_FILE = 800;  
const MAX_TOTAL_CHARS    = 6000; 
const MAX_FILES          = 10;    


function buildPrompt(files) {
  const fileList = Array.isArray(files)
    ? files
    : [{ path: 'file.js', code: files }];

  const filtered = fileList
    .filter(f => f.code && f.code.trim().length > 30)
    .slice(0, MAX_FILES);

  let totalChars = 0;
  const chunks = [];
  for (const f of filtered) {
    if (totalChars >= MAX_TOTAL_CHARS) break;
    const snippet = f.code.slice(0, MAX_CHARS_PER_FILE);
    chunks.push(`FILE: ${f.path}\n---\n${snippet}\n`);
    totalChars += snippet.length;
  }

  const projectSummary = chunks.join('\n');

  return `You are a senior application security engineer doing a full project audit.

Analyse the code below as a WHOLE PROJECT — not file by file. Trace data flow across files.
Look for vulnerabilities based on:
- What the code is TRYING to do (intent)
- HOW it is structured (patterns, architecture)
- What security controls are MISSING (not just what is wrong)
- Cross-file data flows (e.g. unsanitised input in fileA passed to DB query in fileB)

Examples of what to catch:
- Database connected but no prepared statements anywhere in project
- User input taken in route handler but never validated before use
- Passwords or secrets stored in plain text or hardcoded in code
- No authentication check before sensitive operations
- CORS set to wildcard, cookies with no httpOnly/secure flags
- eval(), exec(), child_process with user-controlled input
- File uploads with no type or size validation
- Missing rate limiting on login or sensitive endpoints
- API keys or tokens committed directly in source

For EACH vulnerability found, return a JSON object.
Return ONLY a raw JSON array — no markdown, no backticks, no explanation outside the JSON.

Format:
[
  {
    "id": "unique-short-id",
    "type": "Vulnerability type name",
    "severity": "High" or "Medium" or "Low",
    "file": "filename where the root cause is",
    "line": "approximate line number or function name",
    "explanation": "Plain English: why this is dangerous and exactly how it works in THIS code",
    "attackStory": [
      "Step 1: what attacker does first",
      "Step 2: what happens next",
      "Step 3: what data or damage results"
    ],
    "fix": "Exact code change or pattern needed to fix this"
  }
]

If no vulnerabilities found, return [].

PROJECT CODE:
${projectSummary}`;
}


async function analyseWithOllama(prompt) {
  let fullResponse = '';

  const response = await axios.post(
    OLLAMA_URL,
    {
      model: MODEL,
      prompt,
      stream: true,
      options: {
        temperature: 0.1,  
        num_predict: 2048,
      },
    },
    { responseType: 'stream' }
  );

  return new Promise((resolve, reject) => {
    response.data.on('data', (chunk) => {
      try {
        const lines = chunk.toString().split('\n').filter(Boolean);
        for (const line of lines) {
          const parsed = JSON.parse(line);
          if (parsed.response) fullResponse += parsed.response;
          if (parsed.done) resolve(fullResponse);
        }
      } catch {
      }
    });
    response.data.on('error', reject);
  });
}


function parseFindings(raw) {
  try {
    const cleaned = raw
      .replace(/```json/gi, '')
      .replace(/```/g, '')
      .trim();

    const start = cleaned.indexOf('[');
    const end = cleaned.lastIndexOf(']');
    if (start === -1 || end === -1) return [];

    const parsed = JSON.parse(cleaned.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

app.post('/analyze-project', async (req, res) => {
  const { files } = req.body;

  if (!files || files.length === 0) {
    return res.status(400).json({ error: 'No files provided' });
  }

  console.log(`[server] Scanning ${files.length} file(s) with ${MODEL}...`);

  try {
    const prompt = buildPrompt(files);
    const raw = await analyseWithOllama(prompt);
    const findings = parseFindings(raw);

    console.log(`[server] Found ${findings.length} vulnerability/vulnerabilities`);
    return res.json({ findings, model: MODEL, filesScanned: files.length });
  } catch (err) {
    console.error('[server] Ollama error:', err.message);
    return res.status(500).json({ error: 'Analysis failed', detail: err.message });
  }
});


app.post('/analyze', async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'No code provided' });
  }

  console.log(`[server] Single-file scan with ${MODEL}...`);

  try {
    const prompt = buildPrompt(code);
    const raw = await analyseWithOllama(prompt);
    const vulnerabilities = parseFindings(raw);

    return res.json({ vulnerabilities });
  } catch (err) {
    console.error('[server] Ollama error:', err.message);
    return res.status(500).json({ error: 'Analysis failed', detail: err.message });
  }
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', model: MODEL });
});


app.listen(3000, () => {
  console.log('[server] Security analysis server → http://localhost:3000');
  console.log(`[server] Model: ${MODEL}`);
  console.log('[server] Make sure Ollama is running: ollama serve');
});