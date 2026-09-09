'use strict';

const { buildSecurityPrompt } = require('./prompt-builder');
const { askOllama } = require('./ollama');

const VALID_ATTACK_TYPES = [
    'sqli', 'xss', 'cmdi', 'path_traversal',
    'auth_bypass', 'code_injection', 'ssrf', 'crypto', 'other',
];

const BATCH_SIZE = 4;

/**
 * Normalize a single finding returned by the LLM into the
 * shape the VS Code extension and sandbox expect.
 */
function normaliseFinding(finding, index, staticFinding = {}) {
    let attackType = String(finding.attackType || staticFinding.attackType || 'other').toLowerCase();
    if (!VALID_ATTACK_TYPES.includes(attackType)) {
        attackType = 'other';
    }

    let attackPayloads = [];
    if (Array.isArray(finding.attackPayloads)) {
        attackPayloads = finding.attackPayloads
            .map(p => String(p))
            .filter(p => p.trim());
    }

    return {
        id: String(finding.id || staticFinding.id || `finding-${index + 1}`),

        type: String(
            finding.type ||
            finding.vulnerability ||
            staticFinding.type ||
            staticFinding.vulnerability ||
            'Security Issue'
        ),

        severity: finding.severity || staticFinding.severity || 'Medium',

        file: String(finding.file || staticFinding.file || 'Unknown'),

        line: String(finding.line || staticFinding.line || ''),

        explanation: String(
            finding.explanation ||
            finding.fixExplanation ||
            staticFinding.message ||
            'Security issue detected'
        ),

        attackStory: Array.isArray(finding.attackStory) && finding.attackStory.length > 0
            ? finding.attackStory
            : [
                `Step 1: Identify issue in ${finding.file || staticFinding.file || 'file'} at line ${finding.line || staticFinding.line || ''}`,
                `Step 2: Craft exploit payload for ${finding.type || staticFinding.type || 'vulnerability'}`
            ],

        fix: String(
            finding.fix ||
            finding.fixExplanation ||
            'Review code and sanitize input or update dependencies.'
        ),

        attackType,

        attackPayloads,

        attackScript: String(finding.attackScript || ''),

        vulnerableCode: String(finding.vulnerableCode || staticFinding.codeContext || ''),

        fixedCode: String(finding.fixedCode || ''),
    };
}

/**
 * Attempt to repair or extract valid JSON from a raw string that may be malformed or truncated.
 */
function repairAndParseJSON(raw) {
    let cleaned = String(raw)
        .replace(/```json/gi, '')
        .replace(/```/g, '')
        .trim();

    // 1. Try direct JSON.parse
    try {
        return JSON.parse(cleaned);
    } catch {
        // Direct parse failed, proceed to repair
    }

    // 2. Extract contents inside "findings": [ ... ] if present
    const findingsMatch = cleaned.match(/"findings"\s*:\s*\[([\s\S]*)/);
    let jsonContent = findingsMatch ? findingsMatch[1] : cleaned;

    // 3. Extract all completed JSON objects {...} inside the text
    const extractedObjects = [];
    let depth = 0;
    let inString = false;
    let escapeNext = false;
    let objectStart = -1;

    for (let i = 0; i < jsonContent.length; i++) {
        const char = jsonContent[i];

        if (escapeNext) {
            escapeNext = false;
            continue;
        }

        if (char === '\\' && inString) {
            escapeNext = true;
            continue;
        }

        if (char === '"') {
            inString = !inString;
            continue;
        }

        if (!inString) {
            if (char === '{') {
                if (depth === 0) {
                    objectStart = i;
                }
                depth++;
            } else if (char === '}') {
                depth--;
                if (depth === 0 && objectStart !== -1) {
                    const objStr = jsonContent.slice(objectStart, i + 1);
                    try {
                        extractedObjects.push(JSON.parse(objStr));
                    } catch {
                        // Skip malformed object
                    }
                    objectStart = -1;
                }
            }
        }
    }

    if (extractedObjects.length > 0) {
        return { findings: extractedObjects };
    }

    // 4. Try closing unclosed strings/brackets
    let repaired = cleaned;
    repaired = repaired.replace(/,\s*"[^"]*"\s*:\s*"[^"]*$/g, '');
    repaired = repaired.replace(/,\s*"[^"]*"\s*:\s*$/g, '');
    repaired = repaired.replace(/,\s*$/g, '');

    let openBraces = 0;
    let openBrackets = 0;
    inString = false;
    escapeNext = false;

    for (let i = 0; i < repaired.length; i++) {
        const char = repaired[i];
        if (escapeNext) { escapeNext = false; continue; }
        if (char === '\\' && inString) { escapeNext = true; continue; }
        if (char === '"') { inString = !inString; continue; }
        if (!inString) {
            if (char === '{') openBraces++;
            if (char === '}') openBraces--;
            if (char === '[') openBrackets++;
            if (char === ']') openBrackets--;
        }
    }

    if (inString) {
        repaired += '"';
    }

    while (openBraces > 0) {
        repaired += '}';
        openBraces--;
    }
    while (openBrackets > 0) {
        repaired += ']';
        openBrackets--;
    }

    try {
        return JSON.parse(repaired);
    } catch {
        return null;
    }
}

/**
 * Parse the raw LLM response string into a normalized array of findings.
 */
function parseFindings(raw, staticBatch = []) {
    const parsed = repairAndParseJSON(raw);

    let rawFindings = [];
    if (Array.isArray(parsed)) {
        rawFindings = parsed;
    } else if (parsed && Array.isArray(parsed.findings)) {
        rawFindings = parsed.findings;
    }

    const normalized = [];
    const maxLen = Math.max(rawFindings.length, staticBatch.length);

    for (let i = 0; i < maxLen; i++) {
        const rawFinding = rawFindings[i] || {};
        const staticFinding = staticBatch[i] || {};

        if (Object.keys(rawFinding).length > 0 || Object.keys(staticFinding).length > 0) {
            normalized.push(normaliseFinding(rawFinding, i, staticFinding));
        }
    }

    return normalized;
}

/**
 * Analyze a single batch of findings using Ollama.
 */
async function analyzeBatch(batch, batchIndex, totalBatches) {
    console.log(
        `[LLM] Processing batch ${batchIndex + 1}/${totalBatches} (${batch.length} findings)`
    );

    const prompt = buildSecurityPrompt(batch);

    try {
        const raw = await askOllama(prompt);
        return parseFindings(raw, batch);
    } catch (err) {
        console.error(
            `[LLM] Batch ${batchIndex + 1} failed: ${err.message}. Falling back to static findings normalization.`
        );
        return batch.map((sf, idx) => normaliseFinding({}, idx, sf));
    }
}

/**
 * Build synthetic "targets" from raw source files so the LLM
 * can perform a full AI security audit even when SAST returns 0 findings.
 */
function buildTargetsFromFiles(files) {
    if (!Array.isArray(files) || files.length === 0) {
        return [];
    }

    return files.map((f, i) => ({
        id: `ai-audit-${i + 1}`,
        type: 'AI Security Audit',
        severity: 'Medium',
        file: f.path || 'Unknown',
        line: '',
        message: 'Full AI-powered security audit of this file.',
        codeContext: (f.code || '').slice(0, 3000),
    }));
}

/**
 * Run the full LLM analysis pipeline with batching to avoid token truncation:
 *   static findings → batch prompts → Ollama → parsed & normalized findings
 *
 * If staticFindings is empty but sourceFiles are provided, builds synthetic
 * targets from the source files to perform an AI-only code audit.
 */
async function analyzeFindings(staticFindings, sourceFiles) {
    let targetFindings = staticFindings;

    // When SAST tools found nothing, run AI audit directly on source files
    if ((!Array.isArray(targetFindings) || targetFindings.length === 0) && Array.isArray(sourceFiles) && sourceFiles.length > 0) {
        console.log('[LLM] SAST found 0 issues — running AI-only security audit on source files');
        targetFindings = buildTargetsFromFiles(sourceFiles);
    }

    if (!Array.isArray(targetFindings) || targetFindings.length === 0) {
        return [];
    }

    console.log(
        `[LLM] Preparing ${targetFindings.length} targets for AI analysis`
    );

    const batches = [];
    for (let i = 0; i < targetFindings.length; i += BATCH_SIZE) {
        batches.push(targetFindings.slice(i, i + BATCH_SIZE));
    }

    const allFindings = [];

    for (let i = 0; i < batches.length; i++) {
        const batchResults = await analyzeBatch(batches[i], i, batches.length);
        allFindings.push(...batchResults);
    }

    console.log(
        `[LLM] Parsed total of ${allFindings.length} findings from LLM`
    );

    const withPayloads = allFindings.filter(f => f.attackPayloads.length > 0);
    console.log(
        `[LLM] ${withPayloads.length}/${allFindings.length} findings have attack payloads`
    );

    return allFindings;
}

module.exports = {
    analyzeFindings,
    buildTargetsFromFiles,
    parseFindings,
};