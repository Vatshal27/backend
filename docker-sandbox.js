'use strict';

const Docker = require('dockerode');
const crypto = require('crypto');

const docker = new Docker();

const TARGET_IMAGE = 'node:20-alpine';
const ATTACK_IMAGE = 'node:20-alpine';

const activeSandboxes = new Map();

function createSandboxId() {
  return crypto.randomBytes(6).toString('hex');
}

function createNames(id) {
  return {
    network: `sentinel-network-${id}`,
    target: `sentinel-target-${id}`,
    attacker: `sentinel-attacker-${id}`,
  };
}

function safeError(error) {
  return error instanceof Error
    ? error.message
    : String(error);
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

  console.log(`[sandbox] Pulling ${imageName}...`);

  const stream = await docker.pull(imageName);

  await new Promise((resolve, reject) => {
    docker.modem.followProgress(
      stream,
      error => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      }
    );
  });
}

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
      reason:
        `Docker is unavailable: ${safeError(error)}`,
    };
  }
}

function detectAttackTypes(findings) {
  const combined = findings
    .map(finding => {
      return [
        finding.type,
        finding.explanation,
        finding.fix,
      ].join(' ');
    })
    .join(' ')
    .toLowerCase();

  return {
    sqlInjection:
      /sql|database injection|query injection/.test(combined),

    xss:
      /xss|cross.?site scripting|html injection/.test(combined),

    commandInjection:
      /command injection|shell injection|exec|child_process/.test(
        combined
      ),

    pathTraversal:
      /path traversal|directory traversal/.test(combined),

    authentication:
      /missing authentication|authentication bypass|unauthenticated/.test(
        combined
      ),
  };
}

function buildTargetApplication(findings) {
  const attacks = detectAttackTypes(findings);

  return `
const http = require('http');
const { URL } = require('url');

const users = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@example.local',
    role: 'administrator'
  },
  {
    id: 2,
    username: 'student',
    email: 'student@example.local',
    role: 'user'
  }
];

const files = {
  'public.txt': 'This is a public demonstration file.',
  '../secret.txt': 'SIMULATED_SECRET_VALUE'
};

function json(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json'
  });

  res.end(JSON.stringify(body));
}

function html(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8'
  });

  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/health') {
    return json(res, 200, {
      status: 'ok'
    });
  }

  if (url.pathname === '/search') {
    const query = url.searchParams.get('q') || '';

    ${
      attacks.sqlInjection
        ? `
    const simulatedQuery =
      "SELECT * FROM users WHERE username = '" +
      query +
      "'";

    const injectionDetected =
      query.includes("' OR '1'='1") ||
      query.includes("' OR 1=1");

    return json(res, 200, {
      query: simulatedQuery,
      vulnerable: injectionDetected,
      results: injectionDetected ? users : []
    });
    `
        : `
    return json(res, 200, {
      vulnerable: false,
      results: []
    });
    `
    }
  }

  if (url.pathname === '/greet') {
    const name =
      url.searchParams.get('name') ||
      'World';

    ${
      attacks.xss
        ? `
    return html(
      res,
      200,
      '<html><body>Hello ' + name + '</body></html>'
    );
    `
        : `
    const escaped = name
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    return html(
      res,
      200,
      '<html><body>Hello ' + escaped + '</body></html>'
    );
    `
    }
  }

  if (url.pathname === '/ping') {
    const host =
      url.searchParams.get('host') ||
      'localhost';

    ${
      attacks.commandInjection
        ? `
    const suspicious =
      host.includes(';') ||
      host.includes('&&') ||
      host.includes('|');

    return json(res, 200, {
      vulnerable: suspicious,
      simulatedCommand: 'ping -c 1 ' + host,
      note:
        'The command is not executed. This is a controlled simulation.'
    });
    `
        : `
    return json(res, 200, {
      vulnerable: false,
      simulatedCommand: 'ping -c 1 localhost'
    });
    `
    }
  }

  if (url.pathname === '/file') {
    const requested =
      url.searchParams.get('name') ||
      'public.txt';

    ${
      attacks.pathTraversal
        ? `
    return json(res, 200, {
      vulnerable: requested.includes('..'),
      requested,
      content:
        files[requested] ||
        'File not found'
    });
    `
        : `
    const safeName =
      requested.replace(/\\.\\./g, '');

    return json(res, 200, {
      vulnerable: false,
      requested: safeName,
      content:
        files[safeName] ||
        'File not found'
    });
    `
    }
  }

  if (url.pathname === '/admin') {
    ${
      attacks.authentication
        ? `
    return json(res, 200, {
      vulnerable: true,
      message:
        'Simulated protected administrator data',
      users
    });
    `
        : `
    return json(res, 401, {
      vulnerable: false,
      error: 'Authentication required'
    });
    `
    }
  }

  json(res, 404, {
    error: 'Not found'
  });
});

server.listen(8080, '0.0.0.0', () => {
  console.log('SentinelAI target listening on port 8080');
});
`;
}

function buildAttackerScript(types) {
  const attacks = [];

  if (types.sqlInjection) {
    attacks.push(`
await test(
  'SQL Injection',
  '/search?q=' +
    encodeURIComponent("' OR '1'='1"),
  body => body.vulnerable === true,
  "' OR '1'='1"
);
`);
  }

  if (types.xss) {
    attacks.push(`
await test(
  'Reflected XSS',
  '/greet?name=' +
    encodeURIComponent('<script>alert(1)</script>'),
  body => String(body).includes('<script>alert(1)</script>'),
  '<script>alert(1)</script>',
  true
);
`);
  }

  if (types.commandInjection) {
    attacks.push(`
await test(
  'Command Injection',
  '/ping?host=' +
    encodeURIComponent('localhost;whoami'),
  body => body.vulnerable === true,
  'localhost;whoami'
);
`);
  }

  if (types.pathTraversal) {
    attacks.push(`
await test(
  'Path Traversal',
  '/file?name=' +
    encodeURIComponent('../secret.txt'),
  body => body.vulnerable === true,
  '../secret.txt'
);
`);
  }

  if (types.authentication) {
    attacks.push(`
await test(
  'Authentication Bypass',
  '/admin',
  body => body.vulnerable === true,
  'Unauthenticated GET /admin'
);
`);
  }

  if (attacks.length === 0) {
    attacks.push(`
results.push({
  tool: 'SentinelAI Simulator',
  target: 'Generated local target',
  payload: '',
  output:
    'No supported executable attack category matched the findings.',
  evidence:
    'Static findings were preserved, but no controlled runtime simulation was available.',
  success: false
});
`);
  }

  return `
const http = require('http');

const results = [];

function request(path) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      {
        hostname: 'target',
        port: 8080,
        path,
        timeout: 10000
      },
      res => {
        let data = '';

        res.on('data', chunk => {
          data += chunk.toString();
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            data
          });
        });
      }
    );

    req.on('error', reject);

    req.on('timeout', () => {
      req.destroy(
        new Error('Request timed out')
      );
    });
  });
}

async function test(
  tool,
  path,
  predicate,
  payload,
  raw = false
) {
  try {
    const response = await request(path);

    let parsed = response.data;

    if (!raw) {
      try {
        parsed = JSON.parse(response.data);
      } catch {
        parsed = response.data;
      }
    }

    const success = Boolean(
      predicate(parsed)
    );

    results.push({
      tool,
      target:
        'http://target:8080' + path,
      payload,
      output: response.data,
      evidence: success
        ? 'The controlled target reflected the vulnerable behaviour.'
        : 'The controlled target did not exhibit the vulnerable behaviour.',
      success
    });
  } catch (error) {
    results.push({
      tool,
      target:
        'http://target:8080' + path,
      payload,
      output: '',
      evidence:
        'Attack simulation failed: ' +
        error.message,
      success: false
    });
  }
}

async function main() {
  ${attacks.join('\n')}

  process.stdout.write(
    JSON.stringify(results)
  );
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
`;
}

async function waitForContainer(container) {
  const result =
    await container.wait();

  return result.StatusCode;
}

async function getContainerLogs(container) {
  const buffer = await container.logs({
    stdout: true,
    stderr: true,
  });

  return buffer
    .toString('utf8')
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,
      ''
    );
}

async function waitForTarget() {
  await new Promise(resolve => {
    setTimeout(resolve, 2500);
  });
}

async function removeContainer(container) {
  if (!container) {
    return;
  }

  try {
    await container.remove({
      force: true,
    });
  } catch {
    // Container may already have been removed.
  }
}

async function removeNetwork(network) {
  if (!network) {
    return;
  }

  try {
    await network.remove();
  } catch {
    // Network may already have been removed.
  }
}

async function cleanupSandbox(state) {
  if (!state) {
    return;
  }

  await Promise.allSettled([
    removeContainer(state.attackerContainer),
    removeContainer(state.targetContainer),
  ]);

  await removeNetwork(state.network);
}

function parseAttackOutput(output) {
  const start = output.indexOf('[');
  const end = output.lastIndexOf(']');

  if (start === -1 || end === -1) {
    throw new Error(
      `Could not parse sandbox output: ${output}`
    );
  }

  return JSON.parse(
    output.slice(start, end + 1)
  );
}

async function runSandbox(findings) {
  if (!Array.isArray(findings)) {
    throw new Error(
      'Findings must be an array.'
    );
  }

  const sandboxId = createSandboxId();
  const names = createNames(sandboxId);

  const startedAt =
    new Date().toISOString();

  const types =
    detectAttackTypes(findings);

  const state = {
    sandboxId,
    network: null,
    targetContainer: null,
    attackerContainer: null,
  };

  activeSandboxes.set(
    sandboxId,
    state
  );

  try {
    await Promise.all([
      pullImage(TARGET_IMAGE),
      pullImage(ATTACK_IMAGE),
    ]);

    state.network =
      await docker.createNetwork({
        Name: names.network,
        Driver: 'bridge',
        Internal: true,
      });

    const targetCode =
      buildTargetApplication(findings);

    state.targetContainer =
      await docker.createContainer({
        name: names.target,
        Image: TARGET_IMAGE,

        Env: [
          `TARGET_CODE=${Buffer.from(
            targetCode,
            'utf8'
          ).toString('base64')}`,
        ],

        Cmd: [
          'sh',
          '-c',
          [
            'echo "$TARGET_CODE"',
            '| base64 -d',
            '> /tmp/target.js',
            '&& node /tmp/target.js',
          ].join(' '),
        ],

        HostConfig: {
          NetworkMode: names.network,
          Memory: 256 * 1024 * 1024,
          NanoCpus: 500_000_000,
          PidsLimit: 64,
          CapDrop: ['ALL'],
          SecurityOpt: [
            'no-new-privileges:true',
          ],
          ReadonlyRootfs: true,
          Tmpfs: {
            '/tmp': 'rw,noexec,nosuid,size=16m',
          },
        },

        NetworkingConfig: {
          EndpointsConfig: {
            [names.network]: {
              Aliases: ['target'],
            },
          },
        },
      });

    await state.targetContainer.start();
    await waitForTarget();

    const attackerCode =
      buildAttackerScript(types);

    state.attackerContainer =
      await docker.createContainer({
        name: names.attacker,
        Image: ATTACK_IMAGE,

        Env: [
          `ATTACK_CODE=${Buffer.from(
            attackerCode,
            'utf8'
          ).toString('base64')}`,
        ],

        Cmd: [
          'sh',
          '-c',
          [
            'echo "$ATTACK_CODE"',
            '| base64 -d',
            '> /tmp/attacker.js',
            '&& node /tmp/attacker.js',
          ].join(' '),
        ],

        HostConfig: {
          NetworkMode: names.network,
          Memory: 256 * 1024 * 1024,
          NanoCpus: 500_000_000,
          PidsLimit: 64,
          CapDrop: ['ALL'],
          SecurityOpt: [
            'no-new-privileges:true',
          ],
          ReadonlyRootfs: true,
          Tmpfs: {
            '/tmp': 'rw,noexec,nosuid,size=16m',
          },
        },

        NetworkingConfig: {
          EndpointsConfig: {
            [names.network]: {},
          },
        },
      });

    await state.attackerContainer.start();

    const statusCode =
      await waitForContainer(
        state.attackerContainer
      );

    const output =
      await getContainerLogs(
        state.attackerContainer
      );

    if (statusCode !== 0) {
      throw new Error(
        `Attacker container exited with code ${statusCode}: ${output}`
      );
    }

    const attacks =
      parseAttackOutput(output);

    const successfulAttacks =
      attacks.filter(
        attack => attack.success
      ).length;

    const finishedAt =
      new Date().toISOString();

    return {
      sandboxId,
      startedAt,
      finishedAt,
      target:
        'Generated isolated local demonstration application',
      attacks,
      summary:
        successfulAttacks > 0
          ? `${successfulAttacks} of ${attacks.length} controlled attack simulations reproduced vulnerable behaviour.`
          : `No controlled attack simulation reproduced vulnerable behaviour.`,
    };
  } finally {
    await cleanupSandbox(state);
    activeSandboxes.delete(sandboxId);
  }
}

async function stopSandbox() {
  const states =
    Array.from(activeSandboxes.values());

  await Promise.allSettled(
    states.map(cleanupSandbox)
  );

  activeSandboxes.clear();

  return {
    stopped: states.length,
  };
}

module.exports = {
  checkDocker,
  runSandbox,
  stopSandbox,
};