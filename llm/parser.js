'use strict';

const VALID_ATTACK_TYPES = [
    'sqli',
    'xss',
    'cmdi',
    'path_traversal',
    'auth_bypass',
    'code_injection',
    'ssrf',
    'crypto',
    'other',
];

function normaliseFinding(
    finding,
    index,
    staticFinding = {}
) {
    let attackType = String(
        finding.attackType ||
        staticFinding.attackType ||
        'other'
    ).toLowerCase();

    if (
        !VALID_ATTACK_TYPES.includes(
            attackType
        )
    ) {
        attackType = 'other';
    }

    let attackPayloads = [];

    if (
        Array.isArray(
            finding.attackPayloads
        )
    ) {
        attackPayloads =
            finding.attackPayloads
                .map(p => String(p))
                .filter(p =>
                    p.trim()
                );
    }

    return {
        id: String(
            finding.id ||
            staticFinding.id ||
            `finding-${index + 1}`
        ),

        type: String(
            finding.type ||
            finding.vulnerability ||
            staticFinding.type ||
            staticFinding.vulnerability ||
            'Security Issue'
        ),

        severity:
            finding.severity ||
            staticFinding.severity ||
            'Medium',

        file: String(
            finding.file ||
            staticFinding.file ||
            'Unknown'
        ),

        line: String(
            finding.line ||
            staticFinding.line ||
            ''
        ),

        explanation: String(
            finding.explanation ||
            finding.fixExplanation ||
            staticFinding.message ||
            'Security issue detected'
        ),

        attackStory:
            Array.isArray(
                finding.attackStory
            ) &&
            finding.attackStory.length > 0
                ? finding.attackStory
                : [
                    `Step 1: Identify issue in ${
                        finding.file ||
                        staticFinding.file ||
                        'file'
                    } at line ${
                        finding.line ||
                        staticFinding.line ||
                        ''
                    }`,
                    `Step 2: Craft exploit payload for ${
                        finding.type ||
                        staticFinding.type ||
                        'vulnerability'
                    }`,
                ],

        fix: String(
            finding.fix ||
            finding.fixExplanation ||
            'Review code and sanitize input or update dependencies.'
        ),

        attackType,

        attackPayloads,

        attackScript: String(
            finding.attackScript ||
            ''
        ),

        vulnerableCode: String(
            finding.vulnerableCode ||
            staticFinding.codeContext ||
            ''
        ),

        fixedCode: String(
            finding.fixedCode ||
            ''
        ),
    };
}

function repairAndParseJSON(raw) {
    let cleaned = String(raw)
        .replace(/```json/gi, '')
        .replace(/```/g, '')
        .trim();

    try {
        return JSON.parse(cleaned);
    } catch {
        // Continue with repair.
    }

    const findingsMatch =
        cleaned.match(
            /"findings"\s*:\s*\[([\s\S]*)/
        );

    let jsonContent =
        findingsMatch
            ? findingsMatch[1]
            : cleaned;

    const extractedObjects = [];

    let depth = 0;
    let inString = false;
    let escapeNext = false;
    let objectStart = -1;

    for (
        let i = 0;
        i < jsonContent.length;
        i++
    ) {
        const char =
            jsonContent[i];

        if (escapeNext) {
            escapeNext = false;
            continue;
        }

        if (
            char === '\\' &&
            inString
        ) {
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
            } else if (
                char === '}'
            ) {
                depth--;

                if (
                    depth === 0 &&
                    objectStart !== -1
                ) {
                    const objStr =
                        jsonContent.slice(
                            objectStart,
                            i + 1
                        );

                    try {
                        extractedObjects.push(
                            JSON.parse(
                                objStr
                            )
                        );
                    } catch {
                        // Skip malformed object.
                    }

                    objectStart = -1;
                }
            }
        }
    }

    if (
        extractedObjects.length > 0
    ) {
        return {
            findings:
                extractedObjects,
        };
    }

    let repaired = cleaned;

    repaired = repaired.replace(
        /,\s*"[^"]*"\s*:\s*"[^"]*$/g,
        ''
    );

    repaired = repaired.replace(
        /,\s*"[^"]*"\s*:\s*$/g,
        ''
    );

    repaired = repaired.replace(
        /,\s*$/g,
        ''
    );

    let openBraces = 0;
    let openBrackets = 0;

    inString = false;
    escapeNext = false;

    for (
        let i = 0;
        i < repaired.length;
        i++
    ) {
        const char =
            repaired[i];

        if (escapeNext) {
            escapeNext = false;
            continue;
        }

        if (
            char === '\\' &&
            inString
        ) {
            escapeNext = true;
            continue;
        }

        if (char === '"') {
            inString = !inString;
            continue;
        }

        if (!inString) {
            if (char === '{') {
                openBraces++;
            }

            if (char === '}') {
                openBraces--;
            }

            if (char === '[') {
                openBrackets++;
            }

            if (char === ']') {
                openBrackets--;
            }
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
        return JSON.parse(
            repaired
        );
    } catch {
        return null;
    }
}

function parseFindings(
    raw,
    staticBatch = []
) {
    const parsed =
        repairAndParseJSON(raw);

    let rawFindings = [];

    if (
        Array.isArray(parsed)
    ) {
        rawFindings = parsed;
    } else if (
        parsed &&
        Array.isArray(
            parsed.findings
        )
    ) {
        rawFindings =
            parsed.findings;
    }

    const normalized = [];

    const maxLen =
        Math.max(
            rawFindings.length,
            staticBatch.length
        );

    for (
        let i = 0;
        i < maxLen;
        i++
    ) {
        const rawFinding =
            rawFindings[i] || {};

        const staticFinding =
            staticBatch[i] || {};

        if (
            Object.keys(
                rawFinding
            ).length > 0 ||
            Object.keys(
                staticFinding
            ).length > 0
        ) {
            normalized.push(
                normaliseFinding(
                    rawFinding,
                    i,
                    staticFinding
                )
            );
        }
    }

    return normalized;
}

module.exports = {
    normaliseFinding,
    parseFindings,
};