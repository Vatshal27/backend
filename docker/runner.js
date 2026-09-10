'use strict';

const crypto = require('crypto');

const {
  docker,
  getContainerLogs,
} = require('./client');

const {
  ATTACK_IMAGE,
  SANDBOX_LIMITS,
  SANDBOX_TIMEOUT,
} = require('./config');

function createId(prefix = '') {
  return (
    prefix +
    crypto.randomBytes(6).toString('hex')
  );
}

function buildPayload(finding, attackType) {
  if (
    Array.isArray(finding.attackPayloads) &&
    finding.attackPayloads.length
  ) {
    return finding.attackPayloads[0];
  }

  switch (attackType) {
    case 'sqli':
      return "' OR '1'='1";

    case 'xss':
      return '<script>alert(1)</script>';

    case 'cmdi':
      return 'localhost;whoami';

    case 'path_traversal':
      return '../secret.txt';

    case 'auth_bypass':
      return 'Unauthenticated GET /admin';

    case 'code_injection':
      return 'process.env';

    default:
      return 'test';
  }
}

function createPath(attackType, payload) {
  const encoded = encodeURIComponent(payload);

  switch (attackType) {
    case 'sqli':
      return `/search?q=${encoded}`;

    case 'xss':
      return `/greet?name=${encoded}`;

    case 'cmdi':
      return `/ping?host=${encoded}`;

    case 'path_traversal':
      return `/file?name=${encoded}`;

    case 'auth_bypass':
      return '/admin';

    case 'code_injection':
      return `/eval?code=${encoded}`;

    default:
      return '/';
  }
}

function buildAttackerScript(
  findings,
  plans,
  targetUrl
) {
  const attacks = [];

  for (const plan of plans) {
    const finding = findings.find(
      item =>
        item.id === plan.findingId
    );

    if (!finding) {
      continue;
    }

    const payload = buildPayload(
      finding,
      plan.attackType
    );

    attacks.push({
      id: createId('atk-'),
      findingId: plan.findingId,
      attackType: plan.attackType,
      validator: plan.validator,
      payload,
      path: createPath(
        plan.attackType,
        payload
      ),
    });
  }

  return `
const http = require('http');
const https = require('https');

const attacks = ${JSON.stringify(attacks)};
const targetUrl = ${JSON.stringify(targetUrl)};

const parsedTarget = new URL(targetUrl);

const transport =
  parsedTarget.protocol === 'https:'
    ? https
    : http;

const results = [];

function request(path) {
  return new Promise((resolve, reject) => {
    const url = new URL(
      path,
      targetUrl
    );

    const req = transport.get(
      {
        hostname: url.hostname,
        port:
          url.port ||
          (url.protocol === 'https:'
            ? 443
            : 80),
        path:
          url.pathname +
          url.search,
        timeout: 10000,
      },
      res => {
        let data = '';

        res.on('data', chunk => {
          data += chunk.toString();
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: data,
          });
        });
      }
    );

    req.on('error', reject);

    req.on('timeout', () => {
      req.destroy(
        new Error(
          'Request timed out'
        )
      );
    });
  });
}

function containsPayload(
  body,
  payload
) {
  return (
    typeof body === 'string' &&
    body.includes(payload)
  );
}

function detectEvidence(
  attack,
  response
) {
  const body =
    response.body || '';

  if (
    attack.attackType === 'xss'
  ) {
    return containsPayload(
      body,
      attack.payload
    );
  }

  if (
    attack.attackType === 'sqli'
  ) {
    return (
      /sql syntax|mysql|postgres|sqlite|database error|syntax error/i.test(
        body
      ) ||
      /users|query|database/i.test(
        body
      )
    );
  }

  if (
    attack.attackType ===
    'path_traversal'
  ) {
    return /root:|etc\\/passwd|secret|private|sensitive/i.test(
      body
    );
  }

  if (
    attack.attackType === 'cmdi'
  ) {
    return /uid=|gid=|whoami|command executed|command output/i.test(
      body
    );
  }

  if (
    attack.attackType ===
    'auth_bypass'
  ) {
    return (
      response.statusCode === 200 &&
      !/unauthorized|forbidden|authentication required/i.test(
        body
      )
    );
  }

  if (
    attack.attackType ===
    'code_injection'
  ) {
    return /process\\.env|NODE_|PATH=|HOME=|environment/i.test(
      body
    );
  }

  return false;
}

function createEvidence(
  attack,
  response,
  startedAt,
  finishedAt,
  confirmed
) {
  const evidence = [
    {
      id: '${createId('ev-')}',
      type: 'request',
      timestamp: startedAt,
      source: attack.validator,
      content:
        'GET ' +
        new URL(
          attack.path,
          targetUrl
        ).toString(),
    },
    {
      id: '${createId('ev-')}',
      type: 'response',
      timestamp: finishedAt,
      source: 'project-runtime',
      content:
        response.body || '',
    },
  ];

  if (confirmed) {
    evidence.push({
      id: '${createId('ev-')}',
      type: 'finding',
      timestamp: finishedAt,
      source: attack.validator,
      content:
        'Runtime behavior matched the expected vulnerability signal.',
    });
  }

  return evidence;
}

async function main() {
  for (const attack of attacks) {
    const startedAt =
      new Date().toISOString();

    try {
      const response =
        await request(
          attack.path
        );

      const confirmed =
        detectEvidence(
          attack,
          response
        );

      const finishedAt =
        new Date().toISOString();

      const requestUrl =
        new URL(
          attack.path,
          targetUrl
        ).toString();

      results.push({
        id: attack.id,
        findingId: attack.findingId,
        tool: attack.validator,
        attackType: attack.attackType,
        target: targetUrl,
        status: confirmed
          ? 'success'
          : 'inconclusive',
        payload: attack.payload,

        request: {
          method: 'GET',
          url: requestUrl,
        },

        response: {
          statusCode:
            response.statusCode,
          body:
            response.body,
        },

        startedAt,
        finishedAt,

        evidence:
          createEvidence(
            attack,
            response,
            startedAt,
            finishedAt,
            confirmed
          ),
      });
    } catch (error) {
      const finishedAt =
        new Date().toISOString();

      results.push({
        id: attack.id,
        findingId: attack.findingId,
        tool: attack.validator,
        attackType: attack.attackType,
        target: targetUrl,
        status: 'failed',
        payload: attack.payload,
        startedAt,
        finishedAt,

        evidence: [
          {
            id: '${createId('ev-')}',
            type: 'log',
            timestamp: finishedAt,
            source: attack.validator,
            content:
              error instanceof Error
                ? error.message
                : String(error),
          },
        ],
      });
    }
  }

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

async function createAttacker({
  networkName,
  containerName,
  script,
  projectValidation = false,
}) {
  const hostConfig = {
    AutoRemove: false,
    Memory:
      SANDBOX_LIMITS.memory,
    NanoCpus:
      SANDBOX_LIMITS.nanoCpus,
    PidsLimit:
      SANDBOX_LIMITS.pidsLimit,
    NetworkMode:
      projectValidation
        ? 'host'
        : networkName,
  };

  return docker.createContainer({
    Image: ATTACK_IMAGE,
    name: containerName,
    Cmd: [
      'node',
      '-e',
      script,
    ],
    HostConfig: hostConfig,
  });
}

async function runAttacks({
  networkName,
  containerName,
  findings,
  plans,
  targetUrl,
  projectValidation = false,
}) {
  if (!targetUrl) {
    throw new Error(
      'Target URL is required for runtime validation.'
    );
  }

  const resolvedTarget =
    projectValidation
      ? targetUrl
      : targetUrl.replace(
          'localhost',
          'host.docker.internal'
        );

  const script =
    buildAttackerScript(
      findings,
      plans,
      resolvedTarget
    );

  const container =
    await createAttacker({
      networkName,
      containerName,
      script,
      projectValidation,
    });

  await container.start();

  const result =
    await Promise.race([
      container.wait(),

      new Promise(
        (_, reject) =>
          setTimeout(
            () =>
              reject(
                new Error(
                  'Attack container timed out.'
                )
              ),
            SANDBOX_TIMEOUT
          )
      ),
    ]);

  const output =
    await getContainerLogs(
      container
    );

  if (
    result.StatusCode !== 0
  ) {
    throw new Error(
      `Attack container failed: ${output}`
    );
  }

  const start =
    output.indexOf('[');

  const end =
    output.lastIndexOf(']');

  if (
    start === -1 ||
    end === -1
  ) {
    throw new Error(
      'Attack container returned invalid JSON.'
    );
  }

  return {
    container,
    attacks:
      JSON.parse(
        output.slice(
          start,
          end + 1
        )
      ),
  };
}

module.exports = {
  runAttacks,
};