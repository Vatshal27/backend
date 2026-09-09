'use strict';

/**
 * Code sanitizer to remove sensitive data before sending to Docker
 * Protects API keys, secrets, passwords, and other sensitive information
 */

// Patterns for sensitive data detection
const SENSITIVE_PATTERNS = [
    // API keys
    {
        pattern: /(['"`]?api[_-]?key['"`]?\s*[:=]\s*['"`])([a-zA-Z0-9_-]{20,})(['"`])/gi,
        placeholder: '$1REDACTED_API_KEY$3'
    },
    {
        pattern: /(['"`]?apikey['"`]?\s*[:=]\s*['"`])([a-zA-Z0-9_-]{20,})(['"`])/gi,
        placeholder: '$1REDACTED_API_KEY$3'
    },
    
    // Secret keys
    {
        pattern: /(['"`]?secret[_-]?key['"`]?\s*[:=]\s*['"`])([a-zA-Z0-9_-]{20,})(['"`])/gi,
        placeholder: '$1REDACTED_SECRET$3'
    },
    {
        pattern: /(['"`]?secret['"`]?\s*[:=]\s*['"`])([a-zA-Z0-9_-]{20,})(['"`])/gi,
        placeholder: '$1REDACTED_SECRET$3'
    },
    
    // Passwords
    {
        pattern: /(['"`]?password['"`]?\s*[:=]\s*['"`])([^'"`]{8,})(['"`])/gi,
        placeholder: '$1REDACTED_PASSWORD$3'
    },
    {
        pattern: /(['"`]?passwd['"`]?\s*[:=]\s*['"`])([^'"`]{8,})(['"`])/gi,
        placeholder: '$1REDACTED_PASSWORD$3'
    },
    
    // Database connection strings
    {
        pattern: /(mongodb:\/\/|postgresql:\/\/|mysql:\/\/)[^:\/]+:[^@]+@/gi,
        placeholder: '$1REDACTED_USER:REDACTED_PASSWORD@'
    },
    
    // JWT tokens
    {
        pattern: /(['"`]?token['"`]?\s*[:=]\s*['"`])(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)(['"`])/gi,
        placeholder: '$1REDACTED_JWT_TOKEN$3'
    },
    
    // AWS keys
    {
        pattern: /(['"`]?aws[_-]?access[_-]?key[_-]?id['"`]?\s*[:=]\s*['"`])([A-Z0-9]{20})(['"`])/gi,
        placeholder: '$1REDACTED_AWS_KEY$3'
    },
    {
        pattern: /(['"`]?aws[_-]?secret[_-]?access[_-]?key['"`]?\s*[:=]\s*['"`])([a-zA-Z0-9/+]{40})(['"`])/gi,
        placeholder: '$1REDACTED_AWS_SECRET$3'
    },
    
    // GitHub tokens
    {
        pattern: /(['"`]?github[_-]?token['"`]?\s*[:=]\s*['"`])(ghp_[a-zA-Z0-9]{36})(['"`])/gi,
        placeholder: '$1REDACTED_GITHUB_TOKEN$3'
    },
    
    // Generic base64 encoded strings (potential secrets)
    {
        pattern: /(['"`]?[a-z_]+['"`]?\s*[:=]\s*['"`])([A-Za-z0-9+/]{32,}={0,2})(['"`])/gi,
        placeholder: '$1REDACTED_BASE64$3'
    }
];

/**
 * Sanitize code by removing sensitive data
 * @param {string} code - The code to sanitize
 * @returns {object} - { sanitizedCode, redactedCount, redactedItems }
 */
function sanitizeCode(code) {
    if (!code || typeof code !== 'string') {
        return {
            sanitizedCode: code,
            redactedCount: 0,
            redactedItems: []
        };
    }

    let sanitizedCode = code;
    const redactedItems = [];
    let redactedCount = 0;

    for (const { pattern, placeholder } of SENSITIVE_PATTERNS) {
        const matches = sanitizedCode.match(pattern);
        if (matches) {
            redactedCount += matches.length;
            matches.forEach(match => {
                redactedItems.push({
                    original: match.substring(0, 50) + (match.length > 50 ? '...' : ''),
                    type: pattern.toString()
                });
            });
            sanitizedCode = sanitizedCode.replace(pattern, placeholder);
        }
    }

    return {
        sanitizedCode,
        redactedCount,
        redactedItems
    };
}

/**
 * Extract relevant code snippet around a vulnerability
 * @param {string} fullCode - The full file content
 * @param {number} lineNumber - The line number of the vulnerability
 * @param {number} contextLines - Number of lines before/after to include
 * @returns {string} - The extracted code snippet
 */
function extractCodeSnippet(fullCode, lineNumber, contextLines = 5) {
    if (!fullCode || !lineNumber) {
        return fullCode || '';
    }

    const lines = fullCode.split('\n');
    const lineIndex = lineNumber - 1; // Convert to 0-indexed
    
    const startLine = Math.max(0, lineIndex - contextLines);
    const endLine = Math.min(lines.length, lineIndex + contextLines + 1);
    
    return lines.slice(startLine, endLine).join('\n');
}

/**
 * Sanitize findings by extracting and sanitizing code snippets
 * @param {Array} findings - Array of findings with code context
 * @returns {object} - { sanitizedFindings, sanitizationReport }
 */
function sanitizeFindings(findings) {
    const sanitizedFindings = [];
    const sanitizationReport = {
        totalFindings: findings.length,
        totalRedactions: 0,
        redactedByType: {},
        filesProcessed: new Set()
    };

    for (const finding of findings) {
        let codeToSanitize = finding.vulnerableCode || finding.codeContext || '';
        
        // Extract snippet if we have line numbers
        if (finding.line && finding.file) {
            // In a real implementation, you'd read the file here
            // For now, use whatever code context is available
        }

        const { sanitizedCode, redactedCount, redactedItems } = sanitizeCode(codeToSanitize);
        
        sanitizationReport.totalRedactions += redactedCount;
        
        redactedItems.forEach(item => {
            const type = item.type.substring(0, 30);
            sanitizationReport.redactedByType[type] = 
                (sanitizationReport.redactedByType[type] || 0) + 1;
        });

        if (finding.file) {
            sanitizationReport.filesProcessed.add(finding.file);
        }

        sanitizedFindings.push({
            ...finding,
            vulnerableCode: sanitizedCode,
            originalCode: codeToSanitize, // Keep original for reference
            redactedCount,
            redactedItems
        });
    }

    sanitizationReport.filesProcessed = Array.from(sanitizationReport.filesProcessed);

    return {
        sanitizedFindings,
        sanitizationReport
    };
}

module.exports = {
    sanitizeCode,
    extractCodeSnippet,
    sanitizeFindings
};
