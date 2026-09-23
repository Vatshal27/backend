'use strict';

const fs = require('fs');
const path = require('path');

const IGNORED_DIRECTORIES = new Set([
    '.git',
    '.github',
    '.gitlab',
    'node_modules',
    '__pycache__',
    '.venv',
    'venv',
    'dist',
    'build',
    'coverage',
    '.next',
    '.nuxt',
    'target',
    'vendor',
    'out',
]);

const IGNORED_FILES = new Set([
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'composer.lock',
    'readme',
    'license',
]);

const SOURCE_EXTENSIONS = new Set([
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

const SECURITY_CONFIG_NAMES = new Set([
    'dockerfile',
    'nginx.conf',
    'application.yml',
    'application.yaml',
]);

const SECURITY_CONFIG_EXTENSIONS = new Set([
    '.env',
]);

function normalizePath(filePath) {
    return String(filePath || '')
        .replace(/\\/g, '/')
        .replace(/^file:\/\//i, '')
        .trim();
}

function isIgnoredPath(filePath) {
    const normalized =
        normalizePath(filePath);

    const parts =
        normalized
            .split('/')
            .filter(Boolean)
            .map(part => part.toLowerCase());

    for (const part of parts) {
        if (
            IGNORED_DIRECTORIES.has(
                part
            )
        ) {
            return true;
        }
    }

    const fileName =
        path.basename(
            normalized
        ).toLowerCase();

    if (
        IGNORED_FILES.has(
            fileName
        )
    ) {
        return true;
    }

    if (
        fileName.startsWith('readme.') ||
        fileName.startsWith('license.')
    ) {
        return true;
    }

    if (
        fileName.endsWith('.txt')
    ) {
        return true;
    }

    return false;
}

function isRelevantFile(file) {
    if (
        !file ||
        typeof file.path !== 'string'
    ) {
        return false;
    }

    const filePath =
        normalizePath(file.path);

    if (!filePath) {
        return false;
    }

    if (
        isIgnoredPath(filePath)
    ) {
        return false;
    }

    const fileName =
        path.basename(
            filePath
        ).toLowerCase();

    if (
        SECURITY_CONFIG_NAMES.has(
            fileName
        )
    ) {
        return true;
    }

    const extension =
        path.extname(
            fileName
        );

    if (
        SECURITY_CONFIG_EXTENSIONS.has(
            extension
        )
    ) {
        return true;
    }

    return SOURCE_EXTENSIONS.has(
        extension
    );
}

function filterSourceFiles(files) {
    if (!Array.isArray(files)) {
        return [];
    }

    const filtered =
        files.filter(
            isRelevantFile
        );

    console.log(
        `[scanner-files] File filter: ${files.length} -> ${filtered.length}`
    );

    return filtered;
}

function safeRelativePath(filePath) {
    const normalized =
        normalizePath(filePath)
            .replace(/^\/+/, '');

    const relative =
        path.posix.normalize(
            normalized
        );

    if (
        relative === '..' ||
        relative.startsWith('../') ||
        path.posix.isAbsolute(
            relative
        )
    ) {
        return null;
    }

    return relative;
}

function writeScanFiles(
    files,
    root
) {
    for (const file of files) {
        const relativePath =
            safeRelativePath(
                file.path
            );

        if (!relativePath) {
            console.warn(
                `[scanner-files] Skipping unsafe path: ${file.path}`
            );

            continue;
        }

        const destination =
            path.join(
                root,
                relativePath
            );

        fs.mkdirSync(
            path.dirname(
                destination
            ),
            {
                recursive: true,
            }
        );

        fs.writeFileSync(
            destination,
            String(
                file.code || ''
            ),
            {
                encoding: 'utf8',
                mode: 0o644,
            }
        );
    }
}

function makeScanFilesReadable(
    root
) {
    fs.chmodSync(
        root,
        0o755
    );

    const entries =
        fs.readdirSync(
            root,
            {
                withFileTypes: true,
            }
        );

    for (const entry of entries) {
        const target =
            path.join(
                root,
                entry.name
            );

        if (
            entry.isDirectory()
        ) {
            makeScanFilesReadable(
                target
            );
        } else {
            fs.chmodSync(
                target,
                0o644
            );
        }
    }
}

module.exports = {
    normalizePath,
    isRelevantFile,
    filterSourceFiles,
    safeRelativePath,
    writeScanFiles,
    makeScanFilesReadable,
};