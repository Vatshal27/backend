'use strict';

const crypto = require('node:crypto');

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

const VALID_SEVERITIES = new Set([
    'High',
    'Medium',
    'Low',
]);

function createAiFindingId(
    finding,
    index
) {
    const identity = [
        finding.file || '',
        finding.line || '',
        finding.type ||
            finding.vulnerability ||
            '',
        finding.vulnerableCode || '',
        index,
    ].join('|');

    const digest =
        crypto
            .createHash(
                'sha256'
            )
            .update(
                identity
            )
            .digest(
                'hex'
            )
            .slice(
                0,
                12
            );

    return `ai-${digest}`;
}

function normalizeSeverity(
    severity
) {
    const value =
        String(
            severity ||
            'Medium'
        );

    return VALID_SEVERITIES.has(
        value
    )
        ? value
        : 'Medium';
}

function normalizeConfidence(
    confidence
) {
    const value =
        Number(
            confidence
        );

    if (
        !Number.isFinite(
            value
        )
    ) {
        return null;
    }

    return Math.max(
        0,
        Math.min(
            100,
            Math.round(
                value
            )
        )
    );
}

function normaliseFinding(
    finding,
    index
) {
    let attackType =
        String(
            finding.attackType ||
            'other'
        ).toLowerCase();

    if (
        !VALID_ATTACK_TYPES.includes(
            attackType
        )
    ) {
        attackType =
            'other';
    }

    const attackPayloads =
        Array.isArray(
            finding.attackPayloads
        )
            ? finding.attackPayloads
                .map(
                    payload =>
                        String(
                            payload
                        ).trim()
                )
                .filter(
                    Boolean
                )
            : [];

    const attackStory =
        Array.isArray(
            finding.attackStory
        )
            ? finding.attackStory
                .map(
                    step =>
                        String(
                            step
                        ).trim()
                )
                .filter(
                    Boolean
                )
            : [];

    return {
        id:
            createAiFindingId(
                finding,
                index
            ),
        source:
            'ai',
        type:
            String(
                finding.type ||
                finding.vulnerability ||
                'Security Issue'
            ),
        severity:
            normalizeSeverity(
                finding.severity
            ),
        confidence:
            normalizeConfidence(
                finding.confidence
            ),
        verification:
            'unverified',
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
        attackStory,
        fix:
            String(
                finding.fix ||
                finding.fixExplanation ||
                ''
            ),
        attackType,
        attackPayloads,
        attackScript:
            String(
                finding.attackScript ||
                ''
            ),
        vulnerableCode:
            String(
                finding.vulnerableCode ||
                ''
            ),
        fixedCode:
            String(
                finding.fixedCode ||
                ''
            ),
        fixExplanation:
            String(
                finding.fixExplanation ||
                ''
            ),
    };
}

function extractCompleteObjects(
    value
) {
    const objects = [];

    let depth = 0;
    let inString = false;
    let escaped = false;
    let start = -1;

    for (
        let i = 0;
        i < value.length;
        i += 1
    ) {
        const char =
            value[i];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (
            char === '\\' &&
            inString
        ) {
            escaped = true;
            continue;
        }

        if (char === '"') {
            inString =
                !inString;
            continue;
        }

        if (inString) {
            continue;
        }

        if (char === '{') {
            if (depth === 0) {
                start = i;
            }

            depth += 1;
            continue;
        }

        if (char === '}') {
            if (depth > 0) {
                depth -= 1;
            }

            if (
                depth === 0 &&
                start !== -1
            ) {
                const objectText =
                    value.slice(
                        start,
                        i + 1
                    );

                try {
                    objects.push(
                        JSON.parse(
                            objectText
                        )
                    );
                } catch {
                    // Ignore malformed partial object.
                }

                start = -1;
            }
        }
    }

    return objects;
}

function repairAndParseJSON(
    raw
) {
    const cleaned =
        String(
            raw ||
            ''
        )
            .replace(
                /```json/gi,
                ''
            )
            .replace(
                /```/g,
                ''
            )
            .trim();

    if (!cleaned) {
        return null;
    }

    try {
        return JSON.parse(
            cleaned
        );
    } catch {
        // Continue with controlled recovery.
    }

    const findingsMatch =
        cleaned.match(
            /"findings"\s*:\s*\[([\s\S]*)/
        );

    if (findingsMatch) {
        const objects =
            extractCompleteObjects(
                findingsMatch[1]
            );

        if (
            objects.length >
            0
        ) {
            return {
                findings:
                    objects,
            };
        }
    }

    const objects =
        extractCompleteObjects(
            cleaned
        );

    if (
        objects.length >
        0
    ) {
        const wrapper =
            objects.find(
                item =>
                    Array.isArray(
                        item?.findings
                    )
            );

        if (wrapper) {
            return wrapper;
        }

        return {
            findings:
                objects,
        };
    }

    return null;
}

function parseFindings(
    raw
) {
    const parsed =
        repairAndParseJSON(
            raw
        );

    let rawFindings = [];

    if (
        Array.isArray(
            parsed
        )
    ) {
        rawFindings =
            parsed;
    } else if (
        parsed &&
        Array.isArray(
            parsed.findings
        )
    ) {
        rawFindings =
            parsed.findings;
    }

    if (
        rawFindings.length ===
        0
    ) {
        return [];
    }

    return rawFindings
        .filter(
            finding =>
                finding &&
                typeof finding ===
                    'object' &&
                !Array.isArray(
                    finding
                )
        )
        .map(
            (
                finding,
                index
            ) =>
                normaliseFinding(
                    finding,
                    index
                )
        );
}

module.exports = {
    normaliseFinding,
    parseFindings,
};