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
  return prefix + crypto.randomBytes(6).toString('hex');
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

function createSimulationPath(attackType, payload) {
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
  targetUrl,
  projectValidation
) {
  const attacks = [];

  for (const plan of plans) {
    const finding = findings.find(
      item => item.id === plan.findingId
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
      simulationPath:
        createSimulationPath(
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
const projectValidation = ${JSON.stringify(projectValidation)};

const parsedTarget = new URL(targetUrl);

const transport =
  parsedTarget.protocol === 'https:'
    ? https
    : http;

const results = [];

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, targetUrl);

    const requestBody = body || null;

    const headers = {};

    if (requestBody) {
      headers['Content-Type'] =
        'application/x-www-form-urlencoded';

      headers['Content-Length'] =
        Buffer.byteLength(requestBody);
    }

    const req = transport.request(
      {
        hostname: url.hostname,
        port:
          url.port ||
          (url.protocol === 'https:' ? 443 : 80),
        path:
          url.pathname +
          url.search,
        method,
        headers,
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
        new Error('Request timed out')
      );
    });

    if (requestBody) {
      req.write(requestBody);
    }

    req.end();
  });
}

function absoluteUrl(value) {
  try {
    return new URL(
      value,
      targetUrl
    ).toString();
  } catch {
    return null;
  }
}

function sameOrigin(url) {
  try {
    const parsed = new URL(
      url,
      targetUrl
    );

    return (
      parsed.protocol === parsedTarget.protocol &&
      parsed.hostname === parsedTarget.hostname &&
      parsed.port === parsedTarget.port
    );
  } catch {
    return false;
  }
}

function discoverRoutes(body) {
  const routes = [];

  const html =
    typeof body === 'string'
      ? body
      : '';

  const linkRegex =
    /<a[^>]+href=["']([^"']+)["']/gi;

  let match;

  while (
    (match = linkRegex.exec(html)) !== null
  ) {
    const url = absoluteUrl(match[1]);

    if (url && sameOrigin(url)) {
      routes.push({
        method: 'GET',
        url,
        source: 'link',
        parameters: [],
      });
    }
  }

  const formRegex =
    /<form[^>]*>([\\s\\S]*?)<\\/form>/gi;

  while (
    (match = formRegex.exec(html)) !== null
  ) {
    const formHtml = match[0];

    const actionMatch =
      formHtml.match(
        /action=["']([^"']*)["']/i
      );

    const methodMatch =
      formHtml.match(
        /method=["']([^"']+)["']/i
      );

    const action =
      actionMatch
        ? actionMatch[1]
        : '/';

    const method =
      methodMatch
        ? methodMatch[1].toUpperCase()
        : 'GET';

    const url =
      absoluteUrl(action);

    if (!url || !sameOrigin(url)) {
      continue;
    }

    const parameters = [];

    const inputRegex =
      /<(?:input|textarea|select)[^>]*name=["']([^"']+)["']/gi;

    let inputMatch;

    while (
      (inputMatch =
        inputRegex.exec(formHtml)) !== null
    ) {
      parameters.push(
        inputMatch[1]
      );
    }

    routes.push({
      method,
      url,
      source: 'form',
      parameters,
    });
  }

const fetchRegex =
  /fetch\\s*\\(\\s*["']([^"']+)["']/gi;

while (
  (match = fetchRegex.exec(html)) !== null
) {
  const url = absoluteUrl(match[1]);

  if (url && sameOrigin(url)) {
    routes.push({
      method: 'GET',
      url,
      source: 'javascript',
      parameters: [],
    });
  }
}

const axiosRegex =
  /axios\\.(?:get|post|put|patch|delete)\\s*\\(\\s*["']([^"']+)["']/gi;

while (
  (match = axiosRegex.exec(html)) !== null
) {
  const url = absoluteUrl(match[1]);

  if (url && sameOrigin(url)) {
    routes.push({
      method: 'GET',
      url,
      source: 'javascript',
      parameters: [],
    });
  }
}

  routes.push({
    method: 'GET',
    url: targetUrl,
    source: 'root',
    parameters: [],
  });

  const unique = [];
  const seen = new Set();

  for (const route of routes) {
    const key =
      route.method +
      ' ' +
      route.url;

    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    unique.push(route);
  }

  return unique.slice(0, 50);
}

function chooseRoute(attack, routes) {
  const keywords = {
    sqli: [
      'search',
      'query',
      'user',
      'login',
      'id',
      'product',
      'account',
    ],

    xss: [
      'search',
      'comment',
      'message',
      'name',
      'input',
      'profile',
      'query',
    ],

    cmdi: [
      'command',
      'cmd',
      'exec',
      'ping',
      'host',
      'file',
      'scan',
      'run',
    ],

    path_traversal: [
      'file',
      'download',
      'path',
      'document',
      'upload',
    ],

    auth_bypass: [
      'admin',
      'login',
      'dashboard',
      'account',
      'user',
    ],

    code_injection: [
      'eval',
      'execute',
      'code',
      'run',
      'expression',
      'scan',
    ],
  };

  const wanted =
    keywords[attack.attackType] || [];

  let best = null;
  let bestScore = -1;

  for (const route of routes) {
    const text = (
      route.url +
      ' ' +
      (route.parameters || []).join(' ')
    ).toLowerCase();

    let score = 0;

    for (const keyword of wanted) {
      if (text.includes(keyword)) {
        score += 3;
      }
    }

    if (route.source === 'form') {
      score += 4;
    }

    if (
      Array.isArray(route.parameters) &&
      route.parameters.length > 0
    ) {
      score += 3;
    }

    if (route.source === 'root') {
      score -= 1;
    }

    if (score > bestScore) {
      bestScore = score;
      best = route;
    }
  }

  return best || routes[0] || null;
}

function selectParameter(
  attackType,
  parameters
) {
  if (
    Array.isArray(parameters) &&
    parameters.length
  ) {
    const preferred = {
      sqli: [
        'id',
        'query',
        'q',
        'search',
        'username',
      ],

      xss: [
        'name',
        'query',
        'search',
        'comment',
        'message',
      ],

      cmdi: [
        'command',
        'cmd',
        'host',
        'ip',
        'target',
        'file',
      ],

      path_traversal: [
        'file',
        'path',
        'filename',
        'document',
      ],

      code_injection: [
        'code',
        'expression',
        'command',
        'input',
      ],
    };

    const wanted =
      preferred[attackType] || [];

    for (const name of wanted) {
      const found =
        parameters.find(
          parameter =>
            parameter.toLowerCase() ===
            name
        );

      if (found) {
        return found;
      }
    }

    return parameters[0];
  }

  const defaults = {
    sqli: 'q',
    xss: 'name',
    cmdi: 'host',
    path_traversal: 'file',
    code_injection: 'code',
  };

  return defaults[attackType] || null;
}

function buildProjectRequest(
  attack,
  route
) {
  if (!route) {
    return {
      method: 'GET',
      path: '/',
    };
  }

  const parsed =
    new URL(route.url);

  const parameter =
    selectParameter(
      attack.attackType,
      route.parameters
    );

  if (route.method === 'GET') {
    if (parameter) {
      parsed.searchParams.set(
        parameter,
        attack.payload
      );
    }

    return {
      method: 'GET',
      path:
        parsed.pathname +
        parsed.search,
      parameter,
    };
  }

  if (parameter) {
    return {
      method: route.method,
      path:
        parsed.pathname +
        parsed.search,
      body:
        encodeURIComponent(parameter) +
        '=' +
        encodeURIComponent(
          attack.payload
        ),
      parameter,
    };
  }

  return {
    method: route.method,
    path:
      parsed.pathname +
      parsed.search,
  };
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

  if (attack.attackType === 'xss') {
    return containsPayload(
      body,
      attack.payload
    );
  }

  if (attack.attackType === 'sqli') {
    return (
      /sql syntax|mysql|postgres|sqlite|database error|syntax error/i.test(
        body
      )
    );
  }

  if (
    attack.attackType ===
    'path_traversal'
  ) {
    return (
      /root:|etc\\/passwd|secret|private|sensitive/i.test(
        body
      )
    );
  }

  if (attack.attackType === 'cmdi') {
    return (
      /uid=|gid=|whoami|command executed|command output/i.test(
        body
      )
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
    return (
      /process\\.env|NODE_|PATH=|HOME=|environment/i.test(
        body
      )
    );
  }

  return false;
}

function createEvidence(
  attack,
  response,
  startedAt,
  finishedAt,
  confirmed,
  requestInfo,
  route
) {
  const evidence = [
    {
      id: '${createId('ev-')}',
      type: 'request',
      timestamp: startedAt,
      source: attack.validator,
      content:
        requestInfo.method +
        ' ' +
        new URL(
          requestInfo.path,
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

  if (route) {
    evidence.push({
      id: '${createId('ev-')}',
      type: 'log',
      timestamp: finishedAt,
      source: 'route-discovery',
      content:
        'Selected route: ' +
        JSON.stringify(route),
    });
  }

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
  let discoveryResponse;

  try {
    discoveryResponse =
      await request(
        'GET',
        '/'
      );
  } catch (error) {
    console.error(
      'SENTINEL_DISCOVERY_ERROR ' +
      (
        error instanceof Error
          ? error.message
          : String(error)
      )
    );

    process.exit(1);
  }

  const routes =
    discoverRoutes(
      discoveryResponse.body
    );

  console.error(
    'SENTINEL_DISCOVERY ' +
    JSON.stringify(routes)
  );

  for (const attack of attacks) {
    const startedAt =
      new Date().toISOString();

    try {
      let requestInfo;
      let selectedRoute = null;

      if (projectValidation) {
        selectedRoute =
          chooseRoute(
            attack,
            routes
          );

        requestInfo =
          buildProjectRequest(
            attack,
            selectedRoute
          );
      } else {
        requestInfo = {
          method: 'GET',
          path:
            attack.simulationPath,
        };
      }

      const response =
        await request(
          requestInfo.method,
          requestInfo.path,
          requestInfo.body
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
          requestInfo.path,
          targetUrl
        ).toString();

      results.push({
        id: attack.id,
        findingId:
          attack.findingId,
        tool:
          attack.validator,
        attackType:
          attack.attackType,
        target:
          targetUrl,
        status:
          confirmed
            ? 'success'
            : 'inconclusive',
        payload:
          attack.payload,

        request: {
          method:
            requestInfo.method,
          url:
            requestUrl,

          ...(requestInfo.body
            ? {
                body:
                  requestInfo.body,
              }
            : {}),

          ...(requestInfo.parameter
            ? {
                parameter:
                  requestInfo.parameter,
              }
            : {}),
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
            confirmed,
            requestInfo,
            selectedRoute
          ),
      });
    } catch (error) {
      const finishedAt =
        new Date().toISOString();

      results.push({
        id: attack.id,
        findingId:
          attack.findingId,
        tool:
          attack.validator,
        attackType:
          attack.attackType,
        target:
          targetUrl,
        status: 'failed',
        payload:
          attack.payload,
        startedAt,
        finishedAt,

        evidence: [
          {
            id: '${createId('ev-')}',
            type: 'log',
            timestamp: finishedAt,
            source:
              attack.validator,
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
    Memory: SANDBOX_LIMITS.memory,
    NanoCpus: SANDBOX_LIMITS.nanoCpus,
    PidsLimit: SANDBOX_LIMITS.pidsLimit,

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
          'target'
        );

  const script =
    buildAttackerScript(
      findings,
      plans,
      resolvedTarget,
      projectValidation
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

  if (result.StatusCode !== 0) {
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