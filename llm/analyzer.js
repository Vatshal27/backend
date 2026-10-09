'use strict';

const {
    buildSecurityPrompt,
} = require(
    './prompt-builder'
);

const {
    askOllama,
} = require(
    './ollama'
);

const {
    parseFindings,
} = require(
    './parser'
);

const {
    filterSecurityFindings,
    filterSupportedAiFindings,
    deduplicateFindings,
} = require(
    './filters'
);

const {
    filterSourceFiles,
} = require(
    '../docker-scanner'
);

const FILE_BATCH_SIZE =
    3;

const CONCURRENCY =
    1;

const LLM_ENABLED =
    String(
        process.env
            .LLM_ENABLED ||
        'false'
    ).toLowerCase() ===
    'true';

function normalizePath(
    filePath
) {
    return String(
        filePath ||
        ''
    )
        .replace(
            /\\/g,
            '/'
        )
        .replace(
            /^\/+/,
            ''
        )
        .toLowerCase();
}

function getFileNames(
    filePath
) {
    const normalized =
        normalizePath(
            filePath
        );

    return [
        normalized,
        normalized
            .split(
                '/'
            )
            .pop(),
    ].filter(
        Boolean
    );
}

function findingBelongsToFiles(
    finding,
    files
) {
    if (
        !finding?.file
    ) {
        return false;
    }

    const findingNames =
        getFileNames(
            finding.file
        );

    return files.some(
        file => {
            const fileNames =
                getFileNames(
                    file.path
                );

            return findingNames.some(
                findingName =>
                    fileNames.includes(
                        findingName
                    )
            );
        }
    );
}

function createFileBatches(
    files
) {
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
        createFileBatches(
            files
        );

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
                files:
                    batchFiles,
                findings:
                    batchFindings,
            };
        }
    );
}

function normalizeStaticFindings(
    staticFindings
) {
    if (
        !Array.isArray(
            staticFindings
        )
    ) {
        return [];
    }

    return staticFindings.map(
        (
            finding,
            index
        ) => ({
            ...finding,
            id:
                String(
                    finding?.id ||
                    `static-${index + 1}`
                ),
            source:
                'static',
        })
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
            findings:
                batch.findings,
            files:
                batch.files,
        });

    try {
        const raw =
            await askOllama(
                prompt
            );

        const parsed =
            parseFindings(
                raw
            );

        return filterSupportedAiFindings(
            parsed
        );
    } catch (
        err
    ) {
        console.error(
            `[LLM] Batch ${
                batchIndex + 1
            } failed: ${
                err.message
            }. AI findings for this batch will be omitted.`
        );

        return [];
    }
}

async function analyzeFindings(
    staticFindings,
    sourceFiles
) {
    let findings =
        normalizeStaticFindings(
            staticFindings
        );

    if (
        !LLM_ENABLED
    ) {
        console.log(
            '[LLM] Disabled. Using static findings only.'
        );

        return deduplicateFindings(
            findings
        );
    }

    const files =
        filterSourceFiles(
            Array.isArray(
                sourceFiles
            )
                ? sourceFiles
                : []
        );

    console.log(
        `[LLM] Source files after filtering: ${files.length}`
    );

    if (
        findings.length >
        0
    ) {
        console.log(
            `[LLM] Static analysis returned ${findings.length} findings`
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
            `[LLM] Security findings after filtering: ${findings.length}`
        );
    } else {
        console.log(
            '[LLM] Static analysis returned no findings'
        );
    }

    if (
        files.length ===
        0
    ) {
        console.log(
            '[LLM] No source files available for independent AI source review'
        );

        return findings;
    }

    console.log(
        `[LLM] AI will analyze ${files.length} source files and ${findings.length} static findings`
    );

    const batches =
        createAnalysisBatches(
            files,
            findings
        );

    console.log(
        `[LLM] Created ${batches.length} AI source batches`
    );

    const aiFindings = [];

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
            `[LLM] Running ${currentBatches.length} batch(es)`
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
            const batchResults of
                results
        ) {
            aiFindings.push(
                ...batchResults
            );
        }
    }

    const finalAiFindings =
        deduplicateFindings(
            aiFindings
        );

    console.log(
        `[LLM] Parsed total of ${finalAiFindings.length} supported findings from AI analysis`
    );

    const withPayloads =
        finalAiFindings.filter(
            finding =>
                Array.isArray(
                    finding
                        .attackPayloads
                ) &&
                finding
                    .attackPayloads
                    .length >
                    0
        );

    console.log(
        `[LLM] ${withPayloads.length}/${finalAiFindings.length} AI findings have attack payloads`
    );

    const combined =
        deduplicateFindings([
            ...findings,
            ...finalAiFindings,
        ]);

    console.log(
        `[LLM] Returning ${combined.length} combined static + AI findings`
    );

    return combined;
}

module.exports = {
    analyzeFindings,
};