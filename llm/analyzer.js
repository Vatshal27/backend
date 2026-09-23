'use strict';

const { buildSecurityPrompt } = require('./prompt-builder');
const { askOllama } = require('./ollama');

const {
    normaliseFinding,
    parseFindings,
} = require('./parser');

const {
    filterSecurityFindings,
    deduplicateFindings,
} = require('./filters');

const {
    filterSourceFiles,
} = require('../docker-scanner');

const FILE_BATCH_SIZE = 3;
const CONCURRENCY = 1;
const LLM_ENABLED =
    String(process.env.LLM_ENABLED || 'false').toLowerCase() === 'true';

function normalizePath(filePath) {
    return String(filePath || '')
        .replace(/\\/g, '/')
        .replace(/^\/+/, '')
        .toLowerCase();
}

function getFileNames(filePath) {
    const normalized =
        normalizePath(filePath);

    return [
        normalized,
        normalized.split('/').pop(),
    ].filter(Boolean);
}

function findingBelongsToFiles(
    finding,
    files
) {
    if (!finding?.file) {
        return false;
    }

    const findingNames =
        getFileNames(finding.file);

    return files.some(file => {
        const fileNames =
            getFileNames(file.path);

        return findingNames.some(
            findingName =>
                fileNames.includes(
                    findingName
                )
        );
    });
}

function createFileBatches(files) {
    const batches = [];

    for (
        let i = 0;
        i < files.length;
        i += FILE_BATCH_SIZE
    ) {
        batches.push(
            files.slice(
                i,
                i + FILE_BATCH_SIZE
            )
        );
    }

    return batches;
}

function createAnalysisBatches(
    files,
    findings
) {
    const fileBatches =
        createFileBatches(files);

    return fileBatches.map(
        batchFiles => {
            const batchFindings =
                findings.filter(
                    finding =>
                        findingBelongsToFiles(
                            finding,
                            batchFiles
                        )
                );

            return {
                files: batchFiles,
                findings: batchFindings,
            };
        }
    );
}

async function analyzeBatch(
    batch,
    batchIndex,
    totalBatches
) {
    console.log(
        `[LLM] Processing batch ${
            batchIndex + 1
        }/${totalBatches} (` +
        `${batch.files.length} files, ` +
        `${batch.findings.length} static findings)`
    );

    const prompt =
        buildSecurityPrompt({
            findings: batch.findings,
            files: batch.files,
        });

    try {
        const raw =
            await askOllama(prompt);

        return parseFindings(
            raw,
            batch.findings
        );
    } catch (err) {
        console.error(
            `[LLM] Batch ${
                batchIndex + 1
            } failed: ${
                err.message
            }. Falling back to static findings normalization.`
        );

        return batch.findings.map(
            (finding, index) =>
                normaliseFinding(
                    {},
                    index,
                    finding
                )
        );
    }
}

async function analyzeFindings(
    staticFindings,
    sourceFiles
) {
if (!LLM_ENABLED) {
    console.log(
        '[LLM] Disabled. Using static findings only.'
    );

    return Array.isArray(staticFindings)
        ? deduplicateFindings(
            staticFindings
        )
        : [];
}
    let findings =
        Array.isArray(
            staticFindings
        )
            ? staticFindings
            : [];

    const files =
        filterSourceFiles(
            Array.isArray(sourceFiles)
                ? sourceFiles
                : []
        );

    console.log(
        `[LLM] Source files after filtering: ${files.length}`
    );

    if (findings.length > 0) {
        console.log(
            `[LLM] Static analysis returned ${
                findings.length
            } findings`
        );

        findings =
            filterSecurityFindings(
                findings
            );

        findings =
            deduplicateFindings(
                findings
            );

        console.log(
            `[LLM] Security findings after filtering: ${
                findings.length
            }`
        );

    } else {
        console.log(
            '[LLM] Static analysis returned no findings'
        );
    }

    if (files.length === 0) {
        if (findings.length === 0) {
            console.log(
                '[LLM] No source files or findings available for AI analysis'
            );

            return [];
        }

        console.log(
            '[LLM] No source files available; analyzing static findings only'
        );

        const result =
            await analyzeBatch(
                {
                    files: [],
                    findings,
                },
                0,
                1
            );

        return deduplicateFindings(
            result
        );
    }

    console.log(
        `[LLM] AI will analyze ${
            files.length
        } source files and ${
            findings.length
        } static findings`
    );

    const batches =
        createAnalysisBatches(
            files,
            findings
        );

    console.log(
        `[LLM] Created ${
            batches.length
        } AI source batches`
    );

    const allFindings = [];

    for (
        let i = 0;
        i < batches.length;
        i += CONCURRENCY
    ) {
        const currentBatches =
            batches.slice(
                i,
                i + CONCURRENCY
            );

        console.log(
            `[LLM] Running ${
                currentBatches.length
            } batch(es)`
        );

        const results =
            await Promise.all(
                currentBatches.map(
                    (
                        batch,
                        offset
                    ) =>
                        analyzeBatch(
                            batch,
                            i + offset,
                            batches.length
                        )
                )
            );

        for (
            const batchResults
            of results
        ) {
            allFindings.push(
                ...batchResults
            );
        }
    }

    const finalFindings =
        deduplicateFindings(
            allFindings
        );

    console.log(
        `[LLM] Parsed total of ${
            finalFindings.length
        } findings from AI analysis`
    );

    const withPayloads =
        finalFindings.filter(
            finding =>
                Array.isArray(
                    finding.attackPayloads
                ) &&
                finding.attackPayloads.length >
                    0
        );

    console.log(
        `[LLM] ${
            withPayloads.length
        }/${
            finalFindings.length
        } findings have attack payloads`
    );

    return finalFindings;
}

module.exports = {
    analyzeFindings,
};