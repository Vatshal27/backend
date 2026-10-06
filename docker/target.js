'use strict';

const {
  docker,
} = require('./client');

const {
  TARGET_IMAGE,
  TARGET_PORT,
  TARGET_BIND_HOST,
  TARGET_HEALTH_URL,
  TARGET_HOST,
  TARGET_BROWSER_HOST,
  TARGET_INTERNAL_URL,
  SANDBOX_LIMITS,
  TARGET_HEALTH_TIMEOUT,
} = require('./config');

function generateTargetApplication(
  findings,
  categories
) {
  const routes = [];

  if (
    categories.sqli.length > 0
  ) {
    routes.push(`
  if (url.pathname === '/search') {
    const query =
      url.searchParams.get('q') || '';

    const simulatedQuery =
      "SELECT * FROM users WHERE name = '" +
      query +
      "'";

    const injectionDetected =
      query.includes("' OR ") ||
      query.includes("'--") ||
      query.includes("1=1");

    return json(res, 200, {
      query: simulatedQuery,
      vulnerable: injectionDetected,
      results: injectionDetected
        ? users
        : [],
      finding: ${JSON.stringify(
        categories.sqli[0].type ||
        'SQL Injection'
      )}
    });
  }`);
  }

  if (
    categories.xss.length > 0
  ) {
    routes.push(`
  if (url.pathname === '/greet') {
    const name =
      url.searchParams.get('name') ||
      'World';

    return html(
      res,
      200,
      '<html><body>Hello ' +
      name +
      '</body></html>'
    );
  }`);
  }

  if (
    categories.cmdi.length > 0
  ) {
    routes.push(`
  if (url.pathname === '/ping') {
    const host =
      url.searchParams.get('host') ||
      'localhost';

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

  if (
    categories.path_traversal.length > 0
  ) {
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

  if (
    categories.auth_bypass.length > 0
  ) {
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

  if (
    categories.code_injection.length > 0
  ) {
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

  res.end(
    JSON.stringify(body)
  );
}

function html(res, status, body) {
  res.writeHead(status, {
    'Content-Type':
      'text/html; charset=utf-8'
  });

  res.end(body);
}

const server =
  http.createServer(
    (req, res) => {
      const url =
        new URL(
          req.url,
          'http://${TARGET_HOST}'
        );

      if (
        url.pathname === '/health'
      ) {
        return json(
          res,
          200,
          {
            status: 'ok'
          }
        );
      }

      ${routes.join('\n')}

      return json(
        res,
        404,
        {
          error: 'Not found'
        }
      );
    }
  );

server.listen(
  ${TARGET_PORT},
  '${TARGET_BIND_HOST}',
  () => {
    console.log(
      'SentinelAI target listening on port ${TARGET_PORT}'
    );
  }
);
`;
}

async function createTarget(
  networkId,
  networkName,
  containerName,
  targetCode
) {
  const container =
    await docker.createContainer({
      name:
        containerName,

      Image:
        TARGET_IMAGE,

      Env: [
        `TARGET_CODE=${Buffer.from(
          targetCode,
          'utf8'
        ).toString('base64')}`,
      ],

      Cmd: [
        'sh',
        '-c',
        'echo "$TARGET_CODE" | base64 -d | node',
      ],

      ExposedPorts: {
        [`${TARGET_PORT}/tcp`]: {},
      },

      HostConfig: {
        PortBindings: {
          [`${TARGET_PORT}/tcp`]: [
            {
              HostIp:
                TARGET_BROWSER_HOST ===
                'localhost'
                  ? '127.0.0.1'
                  : TARGET_BROWSER_HOST,

              HostPort:
                '',
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

        ReadonlyRootfs:
          true,

        Tmpfs: {
          '/tmp':
            'rw,noexec,nosuid,size=16m',
        },
      },

      NetworkingConfig: {
        EndpointsConfig: {
          [networkName]: {
            Aliases: [
              TARGET_HOST,
            ],
          },
        },
      },
    });

  await container.start();

  const inspection =
    await container.inspect();

  const bindings =
    inspection
      .NetworkSettings
      ?.Ports?.[
        `${TARGET_PORT}/tcp`
      ];

  if (
    !bindings ||
    bindings.length === 0 ||
    !bindings[0].HostPort
  ) {
    throw new Error(
      'Docker did not assign a host port to the simulation target.'
    );
  }

  const hostPort =
    Number(
      bindings[0].HostPort
    );

  return {
    container,

    hostPort,

    browserUrl:
      `http://${TARGET_BROWSER_HOST}:${hostPort}`,

    internalUrl:
      TARGET_INTERNAL_URL,

    healthUrl:
      TARGET_HEALTH_URL,
  };
}

async function waitForTarget(
  targetContainer,
  timeoutMs = TARGET_HEALTH_TIMEOUT
) {
  const startedAt = Date.now();
  while (
    Date.now() - startedAt <
    timeoutMs
  ) {
    try {
      const containerState =
        await targetContainer.inspect();
      if (
        !containerState.State ||
        !containerState.State.Running
      ) {
        const logs =
          await targetContainer.logs({
            stdout: true,
            stderr: true,
            tail: 100
          });
        console.error(
          '[sandbox] Target container stopped unexpectedly.'
        );
        console.error(
          '[sandbox] Target state:',
          containerState.State
        );
        console.error(
          '[sandbox] Target logs:',
          logs.toString('utf8')
        );
        return false;
      }
      const exec =
        await targetContainer.exec({
          Cmd: [
            'node',
            '-e',
            `
const http=require('http');
const req=http.get(
  ${JSON.stringify(TARGET_HEALTH_URL)},
  res=>{
    res.resume();
    res.on(
      'end',
      ()=>{
        process.exit(
          res.statusCode===200
            ? 0
            : 1
        );
      }
    );
  }
);
req.on(
  'error',
  ()=>{
    process.exit(1);
  }
);
req.setTimeout(
  1000,
  ()=>{
    req.destroy();
    process.exit(1);
  }
);
`
          ],
          AttachStdout: true,
          AttachStderr: true
        });
      const stream =
        await exec.start({
          hijack: true,
          stdin: false
        });
      await new Promise(
        (resolve, reject) => {
          let settled = false;
          const finish = () => {
            if (settled) {
              return;
            }
            settled = true;
            resolve();
          };
          stream.on(
            'end',
            finish
          );
          stream.on(
            'close',
            finish
          );
          stream.on(
            'error',
            error => {
              if (settled) {
                return;
              }
              settled = true;
              reject(error);
            }
          );
          setTimeout(
            finish,
            2000
          );
        }
      );
      let inspection =
        await exec.inspect();
      let waitStartedAt =
        Date.now();
      while (
        inspection.Running &&
        Date.now() - waitStartedAt <
        2000
      ) {
        await new Promise(
          resolve =>
            setTimeout(
              resolve,
              50
            )
        );
        inspection =
          await exec.inspect();
      }
      if (
        inspection.ExitCode === 0
      ) {
        console.log(
          '[sandbox] Target health check passed.'
        );
        return true;
      }
      console.log(
        '[sandbox] Target health check returned exit code:',
        inspection.ExitCode
      );
    } catch (error) {
      console.log(
        '[sandbox] Target health check retry:',
        error instanceof Error
          ? error.message
          : String(error)
      );
    }
    await new Promise(
      resolve =>
        setTimeout(
          resolve,
          500
        )
    );
  }
  try {
    const inspection =
      await targetContainer.inspect();
    const logs =
      await targetContainer.logs({
        stdout: true,
        stderr: true,
        tail: 100
      });
    console.error(
      '[sandbox] Target health check failed after timeout.'
    );
    console.error(
      '[sandbox] Target state:',
      inspection.State
    );
    console.error(
      '[sandbox] Target logs:',
      logs.toString('utf8')
    );
  } catch (error) {
    console.error(
      '[sandbox] Failed to inspect unhealthy target:',
      error instanceof Error
        ? error.message
        : String(error)
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

    internalUrl:
      target.internalUrl,

    browserUrl:
      target.browserUrl,

    healthUrl:
      target.healthUrl,
  };
}

module.exports = {
  generateTargetApplication,
  createTarget,
  waitForTarget,
  buildTargetInfo,
};