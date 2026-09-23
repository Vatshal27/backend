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

function isSecurityRelevant(finding) {
    const text = [
        finding.id,
        finding.type,
        finding.message,
        finding.explanation,
        finding.vulnerability,
        finding.cwe,
        finding.ruleId,
    ]
        .filter(Boolean)
        .join(' ');

    const isObviousNoise =
        NOISE_PATTERNS.some(
            pattern => pattern.test(text)
        );

    if (!isObviousNoise) {
        return true;
    }

    return SECURITY_PATTERNS.some(
        pattern => pattern.test(text)
    );
}

function filterSecurityFindings(findings) {
    if (!Array.isArray(findings)) {
        return [];
    }

    const before = findings.length;

    const filtered =
        findings.filter(
            isSecurityRelevant
        );

    console.log(
        `[LLM] Security filter: ${
            before
        } -> ${
            filtered.length
        } findings`
    );

    return filtered;
}

function deduplicateFindings(findings) {
    const seen = new Set();

    const result =
        findings.filter(
            finding => {
                const key = [
                    finding.file || '',
                    finding.line || '',
                    finding.id || '',
                    finding.type || '',
                ]
                    .join('|')
                    .toLowerCase();

                if (seen.has(key)) {
                    return false;
                }

                seen.add(key);

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

function isRelevantSourceFile(file) {
    const filePath =
        String(file?.path || '');

    if (!filePath) {
        return false;
    }

    if (
        IGNORED_PATH_PATTERNS.some(
            pattern =>
                pattern.test(filePath)
        )
    ) {
        return false;
    }

    const lowerPath =
        filePath.toLowerCase();

    const lastDot =
        lowerPath.lastIndexOf('.');

    if (lastDot === -1) {
        return false;
    }

    const extension =
        lowerPath.slice(lastDot);

    return CODE_EXTENSIONS.has(
        extension
    );
}

function buildTargetsFromFiles(files) {
    if (
        !Array.isArray(files) ||
        files.length === 0
    ) {
        return [];
    }

    const relevantFiles =
        files.filter(
            isRelevantSourceFile
        );

    console.log(
        `[LLM] AI fallback selected ${
            relevantFiles.length
        }/${files.length} source files`
    );

    return relevantFiles.map(
        (file, index) => ({
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
                (file.code || '')
                    .slice(0, 2500),
        })
    );
}

module.exports = {
    filterSecurityFindings,
    deduplicateFindings,
    buildTargetsFromFiles,
};