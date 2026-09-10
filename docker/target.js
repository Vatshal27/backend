'use strict';

const {
  docker,
} = require('./client');

const {
  TARGET_IMAGE,
  SANDBOX_LIMITS,
} = require('./config');

function generateTargetApplication(
  findings,
  categories
) {
  const routes = [];

  if (categories.sqli.length > 0) {
    routes.push(`
  if (url.pathname === '/search') {
    const query = url.searchParams.get('q') || '';

    const simulatedQuery =
      "SELECT * FROM users WHERE name = '" + query + "'";

    const injectionDetected =
      query.includes("' OR ") ||
      query.includes("'--") ||
      query.includes("1=1");

    return json(res, 200, {
      query: simulatedQuery,
      vulnerable: injectionDetected,
      results: injectionDetected ? users : [],
      finding: ${JSON.stringify(
        categories.sqli[0].type || 'SQL Injection'
      )}
    });
  }`);
  }

  if (categories.xss.length > 0) {
    routes.push(`
  if (url.pathname === '/greet') {
    const name =
      url.searchParams.get('name') || 'World';

    return html(
      res,
      200,
      '<html><body>Hello ' +
      name +
      '</body></html>'
    );
  }`);
  }

  if (categories.cmdi.length > 0) {
    routes.push(`
  if (url.pathname === '/ping') {
    const host =
      url.searchParams.get('host') || 'localhost';

    const suspicious =
      host.includes(';') ||
      host.includes('&&') ||
      host.includes('|') ||
      host.includes('$(');

    return json(res, 200, {
      vulnerable: suspicious,
      simulatedCommand:
        'ping -c 1 ' + host,
      note:
        'Command execution is disabled in this sandbox.'
    });
  }`);
  }

  if (categories.path_traversal.length > 0) {
    routes.push(`
  if (url.pathname === '/file') {
    const requested =
      url.searchParams.get('name') ||
      'public.txt';

    const traversal =
      requested.includes('..');

    return json(res, 200, {
      vulnerable: traversal,
      requested,
      content: traversal
        ? 'SIMULATED_SECRET_VALUE'
        : 'This is a public demonstration file.'
    });
  }`);
  }

  if (categories.auth_bypass.length > 0) {
    routes.push(`
  if (url.pathname === '/admin') {
    return json(res, 200, {
      vulnerable: true,
      message:
        'Simulated protected administrator data',
      users
    });
  }`);
  }

  if (categories.code_injection.length > 0) {
    routes.push(`
  if (url.pathname === '/eval') {
    const code =
      url.searchParams.get('code') || '';

    return json(res, 200, {
      vulnerable: code.length > 0,
      input: code,
      note:
        'Code execution is disabled in this sandbox.'
    });
  }`);
  }

  return `
const http = require('http');
const { URL } = require('url');

const users = [
  {
    id: 1,
    username: 'demo_admin',
    email: 'admin@example.local',
    role: 'administrator'
  },
  {
    id: 2,
    username: 'demo_student',
    email: 'student@example.local',
    role: 'user'
  }
];

function json(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json'
  });

  res.end(JSON.stringify(body));
}

function html(res, status, body) {
  res.writeHead(status, {
    'Content-Type':
      'text/html; charset=utf-8'
  });

  res.end(body);
}

const server = http.createServer(
  (req, res) => {
    const url = new URL(
      req.url,
      'http://target'
    );

    if (url.pathname === '/health') {
      return json(res, 200, {
        status: 'ok'
      });
    }

    ${routes.join('\n')}

    return json(res, 404, {
      error: 'Not found'
    });
  }
);

server.listen(
  8080,
  '0.0.0.0',
  () => {
    console.log(
      'SentinelAI target listening on port 8080'
    );
  }
);
`;
}

async function createTarget(
  networkName,
  containerName,
  targetCode
) {
  const container =
    await docker.createContainer({
      name: containerName,

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
        'echo "$TARGET_CODE" | base64 -d > /tmp/target.js && node /tmp/target.js',
      ],

      ExposedPorts: {
        '8080/tcp': {},
      },

      HostConfig: {
        NetworkMode: networkName,

        /*
         * Bind the simulation only to localhost.
         *
         * HostPort "" means Docker selects
         * an available host port automatically.
         */
        PortBindings: {
          '8080/tcp': [
            {
              HostIp: '127.0.0.1',
              HostPort: '',
            },
          ],
        },

        Memory:
          SANDBOX_LIMITS.memory,

        NanoCpus:
          SANDBOX_LIMITS.nanoCpus,

        PidsLimit:
          SANDBOX_LIMITS.pidsLimit,

        CapDrop: [
          'ALL',
        ],

        SecurityOpt: [
          'no-new-privileges:true',
        ],

        ReadonlyRootfs: true,

        Tmpfs: {
          '/tmp':
            'rw,noexec,nosuid,size=16m',
        },
      },

      NetworkingConfig: {
        EndpointsConfig: {
          [networkName]: {
            Aliases: [
              'target',
            ],
          },
        },
      },
    });

  await container.start();

  /*
   * Docker assigns the host port after the
   * container starts.
   */
  const inspection =
    await container.inspect();

  const bindings =
    inspection.NetworkSettings?.Ports?.[
      '8080/tcp'
    ];

  if (
    !bindings ||
    !bindings.length ||
    !bindings[0].HostPort
  ) {
    throw new Error(
      'Docker did not assign a host port to the simulation target.'
    );
  }

  const hostPort =
    bindings[0].HostPort;

  return {
    container,
    hostPort,
    browserUrl:
      `http://localhost:${hostPort}`,
  };
}

async function waitForTarget(
  targetContainer,
  timeoutMs = 10000
) {
  const started =
    Date.now();

  while (
    Date.now() - started <
    timeoutMs
  ) {
    try {
      const exec =
        await targetContainer.exec({
          Cmd: [
            'node',
            '-e',
            `
const http = require('http');

const req = http.get(
  'http://127.0.0.1:8080/health',
  res => process.exit(
    res.statusCode === 200
      ? 0
      : 1
  )
);

req.on(
  'error',
  () => process.exit(1)
);

req.setTimeout(
  1000,
  () => process.exit(1)
);
`,
          ],

          AttachStdout: true,
          AttachStderr: true,
        });

      const stream =
        await exec.start();

      await new Promise(
        resolve => {
          stream.on(
            'end',
            resolve
          );

          stream.on(
            'close',
            resolve
          );
        }
      );

      const inspection =
        await exec.inspect();

      if (
        inspection.ExitCode === 0
      ) {
        return true;
      }
    } catch {
      // Target is not ready yet.
    }

    await new Promise(
      resolve =>
        setTimeout(
          resolve,
          500
        )
    );
  }

  return false;
}

function buildTargetInfo(
  target,
  containerName
) {
  return {
    name:
      'SentinelAI Vulnerable Target',

    url:
      target.browserUrl,

    containerId:
      target.container.id,

    status:
      'running',

    containerName,

    /*
     * Internal Docker URL remains separate
     * from the browser-facing URL.
     */
    internalUrl:
      'http://target:8080',

    browserUrl:
      target.browserUrl,
  };
}

module.exports = {
  generateTargetApplication,
  createTarget,
  waitForTarget,
  buildTargetInfo,
};