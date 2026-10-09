'use strict';

const IGNORED_PATH_PATTERNS = [
    /(^|[\\/])node_modules([\\/]|$)/i,
    /(^|[\\/])\.git([\\/]|$)/i,
    /(^|[\\/])(dist|build|coverage|out)([\\/]|$)/i,
    /(^|[\\/])\.next([\\/]|$)/i,
    /(^|[\\/])\.nuxt([\\/]|$)/i,
    /(^|[\\/])vendor([\\/]|$)/i,
    /(^|[\\/])target([\\/]|$)/i,
    /(^|[\\/])__pycache__([\\/]|$)/i,
    /(^|[\\/])\.venv([\\/]|$)/i,
    /(^|[\\/])venv([\\/]|$)/i,
    /(^|[\\/])(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i,
    /(^|[\\/])composer\.lock$/i,
];

const CODE_EXTENSIONS = new Set([
    '.js',
    '.jsx',
    '.ts',
    '.tsx',
    '.mjs',
    '.cjs',
    '.py',
    '.java',
    '.c',
    '.cpp',
    '.cc',
    '.h',
    '.hpp',
    '.cs',
    '.go',
    '.rs',
    '.php',
    '.rb',
    '.kt',
    '.kts',
    '.swift',
    '.scala',
    '.dart',
    '.sql',
    '.sh',
    '.bash',
    '.zsh',
    '.ps1',
    '.html',
    '.htm',
    '.vue',
    '.svelte',
]);

const NOISE_PATTERNS = [
    /unused import/i,
    /unused variable/i,
    /unused parameter/i,
    /unused function/i,
    /no-unused-vars/i,
    /no-unused-import/i,
    /missing semicolon/i,
    /semicolon/i,
    /indentation/i,
    /trailing whitespace/i,
    /line length/i,
    /naming convention/i,
    /formatting/i,
    /code style/i,
    /style issue/i,
    /documentation/i,
    /comment style/i,
    /spelling/i,
    /whitespace/i,
    /prettier/i,
    /eslint.*style/i,
];

const SECURITY_PATTERNS = [
    /sql injection/i,
    /sql query/i,
    /database injection/i,
    /cross.?site scripting/i,
    /\bxss\b/i,
    /command injection/i,
    /shell injection/i,
    /code injection/i,
    /path traversal/i,
    /directory traversal/i,
    /authentication/i,
    /authorization/i,
    /access control/i,
    /hard.?coded.*(password|secret|token|key|credential)/i,
    /secret/i,
    /credential/i,
    /ssrf/i,
    /server.?side request forgery/i,
    /deserializ/i,
    /pickle/i,
    /unsafe yaml/i,
    /eval\s*\(/i,
    /exec\s*\(/i,
    /subprocess/i,
    /child_process/i,
    /crypto/i,
    /encryption/i,
    /hashing/i,
    /weak hash/i,
    /weak crypto/i,
    /insecure file/i,
    /file inclusion/i,
    /open redirect/i,
    /prototype pollution/i,
    /jwt/i,
    /session/i,
    /cookie/i,
    /csrf/i,
    /cors/i,
    /xxe/i,
    /ldap injection/i,
    /template injection/i,
    /expression injection/i,
];

function isSecurityRelevant(
    finding
) {
    const text = [
        finding?.id,
        finding?.type,
        finding?.message,
        finding?.explanation,
        finding?.vulnerability,
        finding?.cwe,
        finding?.ruleId,
    ]
        .filter(
            Boolean
        )
        .join(
            ' '
        );

    const isObviousNoise =
        NOISE_PATTERNS.some(
            pattern =>
                pattern.test(
                    text
                )
        );

    if (!isObviousNoise) {
        return true;
    }

    return SECURITY_PATTERNS.some(
        pattern =>
            pattern.test(
                text
            )
    );
}

function filterSecurityFindings(
    findings
) {
    if (
        !Array.isArray(
            findings
        )
    ) {
        return [];
    }

    const before =
        findings.length;

    const filtered =
        findings.filter(
            isSecurityRelevant
        );

    console.log(
        `[LLM] Security filter: ${before} -> ${filtered.length} findings`
    );

    return filtered;
}

function deduplicateFindings(
    findings
) {
    if (
        !Array.isArray(
            findings
        )
    ) {
        return [];
    }

    const seen =
        new Set();

    const result =
        findings.filter(
            finding => {
                const key = [
                    finding?.source || '',
                    finding?.file || '',
                    finding?.line || '',
                    finding?.type || '',
                    finding?.vulnerableCode || '',
                ]
                    .join(
                        '|'
                    )
                    .toLowerCase();

                if (
                    seen.has(
                        key
                    )
                ) {
                    return false;
                }

                seen.add(
                    key
                );

                return true;
            }
        );

    if (
        result.length !==
        findings.length
    ) {
        console.log(
            `[LLM] Removed ${
                findings.length -
                result.length
            } duplicate findings`
        );
    }

    return result;
}

function getFindingText(
    finding
) {
    return [
        finding?.type,
        finding?.explanation,
        finding?.fix,
        finding?.fixExplanation,
        finding?.vulnerableCode,
    ]
        .filter(
            Boolean
        )
        .join(
            '\n'
        );
}

function isSecretClaim(
    finding
) {
    const text = [
        finding?.type,
        finding?.explanation,
    ]
        .filter(
            Boolean
        )
        .join(
            ' '
        );

    return /hard.?coded.*(credential|password|secret|api.?key|access.?token|auth.?token|private.?key)|credential|password|secret|api.?key|access.?token|auth.?token/i.test(
        text
    );
}

function containsSecretEvidence(
    value
) {
    const code =
        String(
            value ||
            ''
        );

    if (!code.trim()) {
        return false;
    }

    const patterns = [
        /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|credential)\b\s*[:=]\s*['"`][^'"`\n]{4,}['"`]/i,
        /\bAKIA[A-Z0-9]{16}\b/,
        /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{8,}\b/,
        /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/i,
        /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
        /:\/\/[^:\s/]+:[^@\s/]+@/,
    ];

    return patterns.some(
        pattern =>
            pattern.test(
                code
            )
    );
}

function isDependencyClaim(
    finding
) {
    const text = [
        finding?.type,
        finding?.explanation,
    ]
        .filter(
            Boolean
        )
        .join(
            ' '
        );

    return /dependency|package vulnerability|vulnerable package|vulnerable library|vulnerable module|supply.?chain|dependency confusion/i.test(
        text
    );
}

function hasDependencyAdvisoryEvidence(
    finding
) {
    const text =
        getFindingText(
            finding
        );

    const hasAdvisory =
        /\bCVE-\d{4}-\d{4,}\b/i.test(
            text
        ) ||
        /\bGHSA-[a-z0-9-]+\b/i.test(
            text
        );

    const hasVersion =
        /\b\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?\b/.test(
            text
        );

    return (
        hasAdvisory &&
        hasVersion
    );
}

function isImportOnlyEvidence(
    value
) {
    const code =
        String(
            value ||
            ''
        )
            .trim()
            .replace(
                /\r/g,
                ''
            );

    if (!code) {
        return false;
    }

    const meaningfulLines =
        code
            .split(
                '\n'
            )
            .map(
                line =>
                    line.trim()
            )
            .filter(
                line =>
                    line &&
                    !line.startsWith(
                        '//'
                    ) &&
                    !line.startsWith(
                        '/*'
                    ) &&
                    !line.startsWith(
                        '*'
                    )
            );

    if (
        meaningfulLines.length ===
        0
    ) {
        return false;
    }

    return meaningfulLines.every(
        line =>
            /^import\b/.test(
                line
            ) ||
            /^require\s*\(/.test(
                line
            )
    );
}

function validateAiFinding(
    finding
) {
    if (
        !finding ||
        finding.source !==
            'ai'
    ) {
        return {
            valid:
                false,
            reason:
                'finding does not have AI provenance',
        };
    }

    if (
        !String(
            finding.type ||
            ''
        ).trim()
    ) {
        return {
            valid:
                false,
            reason:
                'missing vulnerability type',
        };
    }

    if (
        !String(
            finding.file ||
            ''
        ).trim() ||
        finding.file ===
            'Unknown'
    ) {
        return {
            valid:
                false,
            reason:
                'missing source file',
        };
    }

    if (
        !String(
            finding.vulnerableCode ||
            ''
        ).trim()
    ) {
        return {
            valid:
                false,
            reason:
                'missing vulnerable-code evidence',
        };
    }

    if (
        !String(
            finding.explanation ||
            ''
        ).trim()
    ) {
        return {
            valid:
                false,
            reason:
                'missing explanation',
        };
    }

    if (
        isSecretClaim(
            finding
        ) &&
        !containsSecretEvidence(
            finding.vulnerableCode
        )
    ) {
        return {
            valid:
                false,
            reason:
                'secret or credential claim has no secret-like literal evidence',
        };
    }

    if (
        isDependencyClaim(
            finding
        ) &&
        !hasDependencyAdvisoryEvidence(
            finding
        )
    ) {
        return {
            valid:
                false,
            reason:
                'dependency vulnerability lacks version plus CVE/GHSA evidence',
        };
    }

    if (
        isImportOnlyEvidence(
            finding.vulnerableCode
        ) &&
        (
            isSecretClaim(
                finding
            ) ||
            isDependencyClaim(
                finding
            )
        )
    ) {
        return {
            valid:
                false,
            reason:
                'ordinary import statements do not prove the claimed vulnerability',
        };
    }

    return {
        valid:
            true,
        reason:
            null,
    };
}

function filterSupportedAiFindings(
    findings
) {
    if (
        !Array.isArray(
            findings
        )
    ) {
        return [];
    }

    const accepted = [];

    for (
        const finding of
            findings
    ) {
        const validation =
            validateAiFinding(
                finding
            );

        if (
            validation.valid
        ) {
            accepted.push(
                finding
            );
            continue;
        }

        console.warn(
            `[LLM] Rejected AI finding "${finding?.type || 'Unknown'}": ${validation.reason}`
        );
    }

    console.log(
        `[LLM] AI evidence validation: ${findings.length} -> ${accepted.length} findings`
    );

    return accepted;
}

function isRelevantSourceFile(
    file
) {
    const filePath =
        String(
            file?.path ||
            ''
        );

    if (!filePath) {
        return false;
    }

    if (
        IGNORED_PATH_PATTERNS.some(
            pattern =>
                pattern.test(
                    filePath
                )
        )
    ) {
        return false;
    }

    const lowerPath =
        filePath
            .toLowerCase();

    const lastDot =
        lowerPath
            .lastIndexOf(
                '.'
            );

    if (
        lastDot ===
        -1
    ) {
        return false;
    }

    const extension =
        lowerPath.slice(
            lastDot
        );

    return CODE_EXTENSIONS.has(
        extension
    );
}

function buildTargetsFromFiles(
    files
) {
    if (
        !Array.isArray(
            files
        ) ||
        files.length ===
            0
    ) {
        return [];
    }

    const relevantFiles =
        files.filter(
            isRelevantSourceFile
        );

    console.log(
        `[LLM] AI fallback selected ${relevantFiles.length}/${files.length} source files`
    );

    return relevantFiles.map(
        (
            file,
            index
        ) => ({
            id:
                `ai-audit-${index + 1}`,
            type:
                'AI Security Review',
            severity:
                'Medium',
            file:
                file.path ||
                'Unknown',
            line:
                '',
            message:
                'Review this source file for actual security vulnerabilities only.',
            codeContext:
                String(
                    file.code ||
                    ''
                ).slice(
                    0,
                    2500
                ),
        })
    );
}

module.exports = {
    filterSecurityFindings,
    filterSupportedAiFindings,
    deduplicateFindings,
    buildTargetsFromFiles,
};