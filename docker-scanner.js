'use strict';

const Docker = require('dockerode');
const path = require('path');

const docker = new Docker();

const SEMGREP_IMAGE = 'returntocorp/semgrep:latest';
const CONTAINER_TIMEOUT = 180_000;

async function checkDocker() {
    try {
        const info = await docker.info();

        return {
            ok: true,
            version: info.ServerVersion,
        };
    } catch (error) {
        return {
            ok: false,
            reason: String(error.message || error),
        };
    }
}

async function imageExists(imageName) {
    try {
        await docker.getImage(imageName).inspect();
        return true;
    } catch {
        return false;
    }
}

async function pullImage(imageName) {
    if (await imageExists(imageName)) {
        return;
    }

    console.log(`[docker-scanner] Pulling ${imageName}...`);

    const stream = await docker.pull(imageName);

    await new Promise((resolve, reject) => {
        docker.modem.followProgress(
            stream,
            error => (error ? reject(error) : resolve())
        );
    });

    console.log(`[docker-scanner] Pulled ${imageName}`);
}

function sanitizeOutput(buffer) {
    return String(buffer)
        .replace(/\u0000/g, '')
        .replace(/[^\x09\x0A\x0D\x20-\x7E\u0080-\uFFFF]/g, '');
}

/* ------------------------------------------------------------------ */
/*  Python scan script — runs both Semgrep + Bandit inside container  */
/* ------------------------------------------------------------------ */

function buildScanScript() {
    return [
        'import json, os, subprocess, base64, sys, pathlib',
        '',
        'def main():',
        '    files_b64 = os.environ.get("FILES_B64", "")',
        '    if not files_b64:',
        '        print(json.dumps({"semgrep": [], "bandit": [], "filesScanned": 0}))',
        '        return',
        '',
        '    files = json.loads(base64.b64decode(files_b64).decode("utf-8"))',
        '',
        '    root = "/tmp/code"',
        '    pathlib.Path(root).mkdir(parents=True, exist_ok=True)',
        '    for f in files:',
        '        filepath = os.path.join(root, f.get("path", "file"))',
        '        os.makedirs(os.path.dirname(filepath), exist_ok=True)',
        '        with open(filepath, "w") as fp:',
        '            fp.write(f.get("code", ""))',
        '',
        '    sys.stderr.write("[scan] Wrote " + str(len(files)) + " files to /tmp/code\\n")',
        '',
        '    # --- Semgrep ---',
        '    semgrep_results = []',
        '    try:',
        '        result = subprocess.run(',
        '            ["semgrep", "--config", "auto", "/tmp/code", "--json", "--no-git-ignore"],',
        '            capture_output=True, text=True, timeout=120',
        '        )',
        '        if result.stdout.strip():',
        '            output = json.loads(result.stdout)',
        '            semgrep_results = output.get("results", [])',
        '            sys.stderr.write("[scan] Semgrep found " + str(len(semgrep_results)) + " issues\\n")',
        '    except Exception as e:',
        '        sys.stderr.write("[scan] Semgrep error: " + str(e) + "\\n")',
        '',
        '    # --- Bandit (only for Python files) ---',
        '    bandit_results = []',
        '    py_files = [f for f in files if f.get("path","").endswith(".py")]',
        '    if py_files:',
        '        try:',
        '            subprocess.run(',
        '                [sys.executable, "-m", "pip", "install", "-q", "bandit"],',
        '                capture_output=True, timeout=60',
        '            )',
        '            result = subprocess.run(',
        '                ["bandit", "-r", "/tmp/code", "-f", "json"],',
        '                capture_output=True, text=True, timeout=120',
        '            )',
        '            if result.stdout.strip():',
        '                output = json.loads(result.stdout)',
        '                bandit_results = output.get("results", [])',
        '                sys.stderr.write("[scan] Bandit found " + str(len(bandit_results)) + " issues\\n")',
        '        except Exception as e:',
        '            sys.stderr.write("[scan] Bandit error: " + str(e) + "\\n")',
        '',
        '    print(json.dumps({',
        '        "semgrep": semgrep_results,',
        '        "bandit": bandit_results,',
        '        "filesScanned": len(files)',
        '    }))',
        '',
        'main()',
    ].join('\n');
}

/* ------------------------------------------------------------------ */
/*  Normalisation helpers                                              */
/* ------------------------------------------------------------------ */

function convertSemgrepType(checkId) {
    if (checkId.includes('sql')) return 'SQL Injection';
    if (checkId.includes('command')) return 'Command Injection';
    if (checkId.includes('xss')) return 'Cross Site Scripting';
    if (checkId.includes('eval')) return 'Code Injection';
    return 'Security Issue';
}

function convertSemgrepSeverity(level) {
    switch (level) {
        case 'ERROR': return 'High';
        case 'WARNING': return 'Medium';
        default: return 'Low';
    }
}

function convertBanditType(testId) {
    const map = {
        B602: 'Command Injection',
        B603: 'Subprocess Execution',
        B605: 'Shell Injection',
        B607: 'Partial Command Injection',
        B307: 'Dangerous Eval',
        B105: 'Hardcoded Password',
        B106: 'Hardcoded Password',
    };

    return map[testId] || 'Python Security Issue';
}

function convertBanditSeverity(level) {
    switch (level) {
        case 'HIGH': return 'High';
        case 'MEDIUM': return 'Medium';
        default: return 'Low';
    }
}

function normalizeSemgrepFindings(results) {
    return results.map(finding => ({
        tool: 'Semgrep',
        id: finding.check_id || '',
        type: convertSemgrepType(finding.check_id || ''),
        severity: convertSemgrepSeverity(finding.extra?.severity),
        file: finding.path || 'Unknown',
        line: finding.start?.line || 0,
        message: finding.extra?.message || 'Security issue detected',
        cwe: finding.extra?.metadata?.cwe || '',
        source: 'Static Analysis (Docker)',
    }));
}

function normalizeBanditFindings(results) {
    return results.map(finding => ({
        tool: 'Bandit',
        id: finding.test_id || '',
        type: convertBanditType(finding.test_id || ''),
        severity: convertBanditSeverity(finding.issue_severity),
        file: finding.filename || 'Unknown',
        line: finding.line_number || 0,
        message: finding.issue_text || 'Security issue detected',
        cwe: finding.issue_cwe?.id ? `CWE-${finding.issue_cwe.id}` : '',
        source: 'Static Analysis (Docker)',
    }));
}

/* ------------------------------------------------------------------ */
/*  Docker container execution                                         */
/* ------------------------------------------------------------------ */

async function runScannersInContainer(files) {
    await pullImage(SEMGREP_IMAGE);

    const payload = Buffer.from(
        JSON.stringify(files || [])
    ).toString('base64');

    const scanScript = buildScanScript();

    const container = await docker.createContainer({
        Image: SEMGREP_IMAGE,
        Entrypoint: [],
        Cmd: ['python3', '-c', scanScript],
        Env: [`FILES_B64=${payload}`],
        HostConfig: {
            Memory: 512 * 1024 * 1024,
            NanoCpus: 1_000_000_000,
            PidsLimit: 256,
            CapDrop: ['ALL'],
            SecurityOpt: ['no-new-privileges:true'],
        },
    });

    try {
        await container.start();

        const waitResult = await Promise.race([
            container.wait(),
            new Promise((_, reject) =>
                setTimeout(
                    () => reject(new Error('Scanner container timed out')),
                    CONTAINER_TIMEOUT
                )
            ),
        ]);

        const rawLogs = await container.logs({
            stdout: true,
            stderr: false,
        });

        const output = sanitizeOutput(rawLogs.toString('utf8'));

        console.log(
            `[docker-scanner] Container exited with code ${waitResult.StatusCode}`
        );

        // Docker log streams include frame-header bytes that can
        // appear as stray characters (e.g. '@') before the JSON.
        // Extract JSON by finding the outermost { … } in the full output.
        const jsonStart = output.indexOf('{');
        const jsonEnd = output.lastIndexOf('}');

        if (jsonStart !== -1 && jsonEnd > jsonStart) {
            try {
                const parsed = JSON.parse(
                    output.slice(jsonStart, jsonEnd + 1)
                );

                if (parsed && typeof parsed === 'object') {
                    return parsed;
                }
            } catch (parseErr) {
                console.error(
                    '[docker-scanner] JSON parse failed:',
                    parseErr.message
                );
            }
        }

        console.error(
            '[docker-scanner] No JSON output found. Raw:',
            output.slice(0, 500)
        );

        return {
            semgrep: [],
            bandit: [],
            filesScanned: files.length,
        };
    } finally {
        try {
            await container.remove({ force: true });
        } catch {
            // Container may already be removed.
        }
    }
}

function attachCodeContext(findings, files) {
    if (!Array.isArray(files) || files.length === 0) {
        return findings;
    }

    const fileMap = new Map();
    files.forEach(f => {
        if (f.path && f.code) {
            const normalizedPath = f.path.replace(/\\/g, '/').toLowerCase();
            fileMap.set(normalizedPath, f.code);
            fileMap.set(path.basename(normalizedPath), f.code);
        }
    });

    return findings.map(finding => {
        const rawPath = (finding.file || '').replace(/\\/g, '/');
        const cleanedPath = rawPath.replace(/^\/tmp\/code\//i, '').replace(/^tmp\/code\//i, '');
        const lookupPath = cleanedPath.toLowerCase();
        let code = fileMap.get(lookupPath) || fileMap.get(path.basename(lookupPath));

        let updated = {
            ...finding,
            file: cleanedPath || finding.file
        };

        if (code) {
            const lines = code.split('\n');
            const lineNo = parseInt(finding.line, 10);
            if (!isNaN(lineNo) && lineNo > 0) {
                const start = Math.max(0, lineNo - 5);
                const end = Math.min(lines.length, lineNo + 5);
                const snippet = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
                updated.codeContext = snippet;
            }
        }

        return updated;
    });
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

async function runStaticAnalysis(filesOrPath) {
    // If caller passed an array of files, run scanners in Docker.
    if (Array.isArray(filesOrPath)) {
        console.log(
            `[docker-scanner] Running scanners on ${filesOrPath.length} files`
        );

        const raw = await runScannersInContainer(filesOrPath);

        const semgrepFindings = normalizeSemgrepFindings(
            raw.semgrep || []
        );

        const banditFindings = normalizeBanditFindings(
            raw.bandit || []
        );

        const allFindings = [...semgrepFindings, ...banditFindings];
        const enrichedFindings = attachCodeContext(allFindings, filesOrPath);

        console.log(
            `[docker-scanner] Total: ${enrichedFindings.length} ` +
            `(Semgrep ${semgrepFindings.length}, ` +
            `Bandit ${banditFindings.length})`
        );

        return enrichedFindings;
    }

    // If a path was provided, delegate to legacy scanner module if available.
    try {
        const legacy = require('./scanner/scanner');

        if (legacy && typeof legacy.runStaticAnalysis === 'function') {
            return legacy.runStaticAnalysis(filesOrPath);
        }
    } catch (err) {
        console.warn(
            '[docker-scanner] Legacy scanner not available:',
            String(err)
        );
    }

    return [];
}

module.exports = {
    checkDocker,
    runStaticAnalysis,
};
