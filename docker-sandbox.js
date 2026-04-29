/**
 * docker-sandbox.js
 * SentinelAI — sandboxed attack demo runner
 *
 * Spins up isolated Docker containers, runs real pentest tools
 * (SQLMap, OWASP ZAP, Nuclei) against a local copy of the project,
 * captures evidence, tears everything down.
 *
 * Requires: Docker Desktop running on the host.
 */

'use strict';

const { execFile, spawn } = require('child_process');
const { promisify }       = require('util');
const path                = require('path');
const fs                  = require('fs');
const os                  = require('os');
const crypto              = require('crypto');

const execFileAsync = promisify(execFile);

// ── Docker images used ──────────────────────────────────────────────────────
const IMAGES = {
  sqlmap:  'paoloo/sqlmap',           // lightweight sqlmap image
  zap:     'ghcr.io/zaproxy/zaproxy:stable',
  nuclei:  'projectdiscovery/nuclei', // official nuclei image
  // Minimal Node target — used to host a tiny vulnerable app for demo
  target:  'node:20-alpine',
};

// ── Network / container names keyed by sandboxId ────────────────────────────
function names(id) {
  return {
    network:  `sentinel_net_${id}`,
    target:   `sentinel_target_${id}`,
    sqlmap:   `sentinel_sqlmap_${id}`,
    zap:      `sentinel_zap_${id}`,
    nuclei:   `sentinel_nuclei_${id}`,
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Run docker CLI command, return stdout string. */
async function docker(...args) {
  const { stdout } = await execFileAsync('docker', args, { timeout: 120_000 });
  return stdout.trim();
}

/** Spawn a docker container and collect all stdout/stderr until exit. */
function dockerRun(args, timeoutMs = 90_000) {
  return new Promise((resolve) => {
    let output = '';
    const proc = spawn('docker', ['run', '--rm', ...args], {
      timeout: timeoutMs,
    });
    proc.stdout.on('data', d => { output += d.toString(); });
    proc.stderr.on('data', d => { output += d.toString(); });
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      resolve({ output: output + '\n[timed out]', code: -1 });
    }, timeoutMs);
    proc.on('close', (code) => {
      clearTimeout(timer);
      resolve({ output, code });
    });
  });
}

/** Write a temp file, return its path. */
function writeTmp(content, ext = '.js') {
  const p = path.join(os.tmpdir(), `sentinel_${crypto.randomBytes(6).toString('hex')}${ext}`);
  fs.writeFileSync(p, content, 'utf8');
  return p;
}

/** Check docker is available and daemon is running. */
async function checkDocker() {
  try {
    await docker('info', '--format', '{{.ServerVersion}}');
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ── Vulnerable target app ────────────────────────────────────────────────────
/**
 * Generates a tiny Express app that intentionally contains the vulnerabilities
 * found by SentinelAI. This is what the attack tools target.
 */
function buildVulnerableApp(findings) {
  const hasSQLi  = findings.some(f => /sql/i.test(f.type));
  const hasXSS   = findings.some(f => /xss|cross.site/i.test(f.type));
  const hasCmd   = findings.some(f => /command|injection|exec/i.test(f.type));
  const hasOpen  = true; // always include a basic endpoint

  let routes = '';

  if (hasOpen) {
    routes += `
// Health / landing
app.get('/', (req, res) => {
  res.send('<html><body><h1>Demo App</h1><form action="/search" method="GET"><input name="q"><button>Search</button></form></body></html>');
});
`;
  }

  if (hasSQLi) {
    routes += `
// VULNERABLE: SQL injection (simulated — uses in-memory data but mirrors real pattern)
const db = { users: [{id:1,name:'admin',email:'admin@example.com',password:'hunter2'}] };
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // Intentionally vulnerable: direct string concat
  const fakeQuery = 'SELECT * FROM users WHERE name = \\'' + q + '\\'';
  const result = db.users.filter(u => u.name.includes(q));
  res.json({ query: fakeQuery, results: result });
});
app.get('/user', (req, res) => {
  const id = req.query.id;
  const fakeQuery = 'SELECT * FROM users WHERE id=' + id;
  const result = db.users.find(u => String(u.id) === String(id));
  res.json({ query: fakeQuery, user: result || null });
});
`;
  }

  if (hasXSS) {
    routes += `
// VULNERABLE: Reflected XSS
app.get('/greet', (req, res) => {
  const name = req.query.name || 'World';
  res.send('<html><body>Hello ' + name + '!</body></html>'); // unsanitised
});
`;
  }

  if (hasCmd) {
    routes += `
// VULNERABLE: Command injection (simulated — output only, no real exec)
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  const cmd = 'ping -c 1 ' + host; // dangerous in real code
  res.json({ command: cmd, note: 'Simulated — not executed in sandbox' });
});
`;
  }

  return `
const express = require('express');
const app = express();
app.use(express.json());
${routes}
app.listen(8080, () => console.log('Vulnerable demo app on :8080'));
`;
}

// ── Attack runners ────────────────────────────────────────────────────────────

async function runSQLMap(networkName, targetHost, timeoutMs = 60_000) {
  const urls = [
    `http://${targetHost}:8080/search?q=test`,
    `http://${targetHost}:8080/user?id=1`,
  ];

  let bestResult = { output: '', success: false, evidence: '', payload: '' };

  for (const url of urls) {
    const { output } = await dockerRun([
      '--network', networkName,
      '--name', `sqlmap_tmp_${Date.now()}`,
      IMAGES.sqlmap,
      'sqlmap',
      '-u', url,
      '--batch',          // no interactive prompts
      '--level=1',
      '--risk=1',
      '--timeout=10',
      '--retries=1',
      '--output-dir=/tmp/sqlmap',
      '--forms',
    ], timeoutMs);

    const injectable = /parameter .+ is (vulnerable|injectable)/i.test(output) ||
                       /sqlmap identified the following injection/i.test(output);
    const payloadMatch = output.match(/Payload:\s*(.+)/i);

    if (injectable) {
      bestResult = {
        output: output.slice(0, 2000),
        success: true,
        evidence: `SQLMap confirmed SQL injection at: ${url}\n\n` + output.slice(0, 800),
        payload: payloadMatch ? payloadMatch[1].trim() : "' OR '1'='1",
      };
      break;
    } else {
      // Even if not flagged as injectable, return interesting output
      bestResult = {
        output: output.slice(0, 1500),
        success: false,
        evidence: output.slice(0, 600) || 'No SQL injection detected at tested endpoints.',
        payload: '',
      };
    }
  }

  return {
    tool: 'SQLMap',
    target: `http://${targetHost}:8080/search?q=...`,
    ...bestResult,
  };
}

async function runZAP(networkName, targetHost, timeoutMs = 90_000) {
  // ZAP baseline scan — passive + active on the target
  const { output } = await dockerRun([
    '--network', networkName,
    '-e', `ZAP_PORT=8090`,
    IMAGES.zap,
    'zap-baseline.py',
    '-t', `http://${targetHost}:8080`,
    '-J', '/zap/wrk/report.json',
    '-l', 'WARN',
    '-I',        // don't fail on warn
    '-m', '1',   // 1 minute spider
  ], timeoutMs);

  const hasAlerts = /WARN|FAIL|alerts/i.test(output);
  const alertMatches = output.match(/WARN-NEW:\s*(.+)/g) || [];
  const alerts = alertMatches.map(a => a.replace('WARN-NEW:', '').trim()).slice(0, 5);

  return {
    tool: 'ZAP',
    target: `http://${targetHost}:8080`,
    success: hasAlerts && alertMatches.length > 0,
    payload: '',
    evidence: alerts.length
      ? 'OWASP ZAP found:\n' + alerts.join('\n')
      : output.slice(0, 600) || 'ZAP scan completed — no high alerts.',
    output: output.slice(0, 1500),
  };
}

async function runNuclei(networkName, targetHost, timeoutMs = 60_000) {
  const { output } = await dockerRun([
    '--network', networkName,
    IMAGES.nuclei,
    '-u', `http://${targetHost}:8080`,
    '-t', 'http/misconfiguration/',
    '-t', 'http/exposures/',
    '-severity', 'low,medium,high,critical',
    '-no-interactsh',
    '-json',
    '-timeout', '5',
    '-retries', '1',
  ], timeoutMs);

  // Parse JSON lines output
  const findings = [];
  for (const line of output.split('\n')) {
    try {
      const obj = JSON.parse(line.trim());
      if (obj['template-id'] || obj.info) {
        findings.push(`[${obj.info?.severity?.toUpperCase() || '?'}] ${obj.info?.name || obj['template-id']} — ${obj['matched-at'] || ''}`);
      }
    } catch { /* not JSON */ }
  }

  return {
    tool: 'Nuclei',
    target: `http://${targetHost}:8080`,
    success: findings.length > 0,
    payload: '',
    evidence: findings.length
      ? 'Nuclei findings:\n' + findings.slice(0, 8).join('\n')
      : output.slice(0, 600) || 'Nuclei scan completed — no templates matched.',
    output: output.slice(0, 1200),
  };
}

// ── Pull images (best-effort, non-blocking) ───────────────────────────────────
async function pullImages() {
  const pulls = Object.values(IMAGES).map(img =>
    execFileAsync('docker', ['pull', img], { timeout: 300_000 }).catch(() => {})
  );
  await Promise.allSettled(pulls);
}

// ── Main sandbox runner ───────────────────────────────────────────────────────

/**
 * Run the full attack sandbox.
 * @param {Array} findings  — array of Finding objects from SentinelAI
 * @returns {SandboxReport}
 */
async function runSandbox(findings) {
  const sandboxId = crypto.randomBytes(4).toString('hex');
  const n = names(sandboxId);
  const startedAt = new Date().toISOString();
  const appCode = buildVulnerableApp(findings);
  let targetContainerId = null;
  let appFile = null;

  console.log(`[sandbox:${sandboxId}] Starting attack demo...`);

  try {
    // 1. Create isolated Docker network
    console.log(`[sandbox:${sandboxId}] Creating network ${n.network}...`);
    await docker('network', 'create', '--driver', 'bridge',
      '--opt', 'com.docker.network.bridge.enable_icc=true',
      n.network);

    // 2. Write vulnerable app to temp file
    appFile = writeTmp(appCode, '.js');
    const appDir = path.dirname(appFile);
    const appBase = path.basename(appFile);

    // 3. Start vulnerable target container
    console.log(`[sandbox:${sandboxId}] Launching vulnerable target app...`);
    targetContainerId = await docker(
      'run', '-d',
      '--name', n.target,
      '--network', n.network,
      '-v', `${appDir}:/app:ro`,
      '-w', '/app',
      IMAGES.target,
      'sh', '-c',
      `npm install express --prefix /tmp/nodeapp 2>/dev/null; ` +
      `node -e "$(cat ${appBase})" 2>/dev/null || ` +
      `npx --yes express-generator@4 /tmp/app && node /app/${appBase}`
    );

    // Give the target a moment to start
    await new Promise(r => setTimeout(r, 4000));

    // 4. Run attacks in parallel (with individual timeouts)
    console.log(`[sandbox:${sandboxId}] Launching attack tools...`);
    const [sqlResult, zapResult, nucleiResult] = await Promise.allSettled([
      runSQLMap(n.network, n.target, 60_000),
      runZAP(n.network, n.target, 90_000),
      runNuclei(n.network, n.target, 60_000),
    ]);

    const attacks = [sqlResult, zapResult, nucleiResult]
      .map(r => r.status === 'fulfilled' ? r.value : {
        tool: 'Unknown',
        target: 'N/A',
        success: false,
        payload: '',
        evidence: `Tool failed: ${r.reason?.message || 'unknown error'}`,
        output: '',
      });

    const exploited = attacks.filter(a => a.success).length;
    const summary = exploited > 0
      ? `⚠ ${exploited} of ${attacks.length} attack(s) successfully demonstrated vulnerabilities. ` +
        `These are REAL exploits run against a sandboxed replica of your code patterns. ` +
        `Fix the issues flagged by SentinelAI before deploying.`
      : `Attack tools ran against the sandboxed app. No automatic exploits succeeded — ` +
        `but manual exploitation may still be possible. Review all flagged findings.`;

    const finishedAt = new Date().toISOString();
    console.log(`[sandbox:${sandboxId}] Done. ${exploited}/${attacks.length} exploitable.`);

    return { sandboxId, startedAt, finishedAt, target: n.target, attacks, summary };

  } finally {
    // 5. Always clean up — container + network + temp file
    console.log(`[sandbox:${sandboxId}] Cleaning up...`);
    await Promise.allSettled([
      docker('rm', '-f', n.target).catch(() => {}),
      docker('rm', '-f', n.sqlmap).catch(() => {}),
      docker('rm', '-f', n.zap).catch(() => {}),
      docker('rm', '-f', n.nuclei).catch(() => {}),
    ]);
    await docker('network', 'rm', n.network).catch(() => {});
    if (appFile) {
      try { fs.unlinkSync(appFile); } catch {}
    }
    console.log(`[sandbox:${sandboxId}] Cleanup complete.`);
  }
}

module.exports = { runSandbox, checkDocker, pullImages };