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
  TARGET_INTERNAL_URL,
  SANDBOX_LIMITS,
  TARGET_HEALTH_TIMEOUT,
} = require('./config');
function generateTargetApplication(
  findings,
  categories
) {
  return `
'use strict';
const http = require('http');
const { URL } = require('url');
const users = [
  {
    id: 1,
    username: 'demo_admin',
    email: 'admin@example.local',
    role: 'administrator',
  },
  {
    id: 2,
    username: 'demo_student',
    email: 'student@example.local',
    role: 'user',
  },
];
function json(
  res,
  status,
  body
) {
  res.writeHead(
    status,
    {
      'Content-Type':
        'application/json; charset=utf-8',
    }
  );
  res.end(
    JSON.stringify(body)
  );
}
function html(
  res,
  status,
  body
) {
  res.writeHead(
    status,
    {
      'Content-Type':
        'text/html; charset=utf-8',
    }
  );
  res.end(body);
}
function createIndexPage() {
  return [
    '<!doctype html>',
    '<html>',
    '<head>',
    '<meta charset="utf-8">',
    '<title>SentinelAI Safe Simulation Target</title>',
    '</head>',
    '<body>',
    '<h1>SentinelAI Safe Simulation Target</h1>',
    '<p>Controlled synthetic application for runtime scanner self-testing.</p>',
    '<ul>',
    '<li><a href="/search?q=test">Search fixture</a></li>',
    '<li><a href="/greet?name=World">Greeting fixture</a></li>',
    '<li><a href="/ping?host=localhost">Command fixture</a></li>',
    '<li><a href="/file?name=public.txt">File fixture</a></li>',
    '<li><a href="/admin">Admin fixture</a></li>',
    '<li><a href="/eval?code=test">Code fixture</a></li>',
    '</ul>',
    '<form action="/search" method="GET">',
    '<input name="q" value="test">',
    '<button type="submit">Search</button>',
    '</form>',
    '<form action="/greet" method="GET">',
    '<input name="name" value="World">',
    '<button type="submit">Greet</button>',
    '</form>',
    '<form action="/ping" method="GET">',
    '<input name="host" value="localhost">',
    '<button type="submit">Ping</button>',
    '</form>',
    '<form action="/file" method="GET">',
    '<input name="name" value="public.txt">',
    '<button type="submit">File</button>',
    '</form>',
    '<form action="/eval" method="GET">',
    '<input name="code" value="test">',
    '<button type="submit">Evaluate</button>',
    '</form>',
    '</body>',
    '</html>',
  ].join('');
}
const server =
  http.createServer(
    (
      req,
      res
    ) => {
      const url =
        new URL(
          req.url,
          'http://${TARGET_HOST}'
        );
      if (
        url.pathname ===
        '/health'
      ) {
        return json(
          res,
          200,
          {
            status:
              'ok',
            service:
              'sentinelai-safe-simulation',
          }
        );
      }
      if (
        url.pathname ===
        '/'
      ) {
        return html(
          res,
          200,
          createIndexPage()
        );
      }
      if (
        url.pathname ===
        '/search'
      ) {
        const query =
          url.searchParams.get(
            'q'
          ) || '';
        const simulatedQuery =
          "SELECT * FROM users WHERE name = '" +
          query +
          "'";
        const injectionDetected =
          query.includes(
            "' OR "
          ) ||
          query.includes(
            "'--"
          ) ||
          query.includes(
            '1=1'
          );
        return json(
          res,
          200,
          {
            fixture:
              'sqli',
            vulnerable:
              injectionDetected,
            query:
              simulatedQuery,
            results:
              injectionDetected
                ? users
                : [],
          }
        );
      }
      if (
        url.pathname ===
        '/greet'
      ) {
        const name =
          url.searchParams.get(
            'name'
          ) ||
          'World';
        return html(
          res,
          200,
          '<html><body>Hello ' +
          name +
          '</body></html>'
        );
      }
      if (
        url.pathname ===
        '/ping'
      ) {
        const host =
          url.searchParams.get(
            'host'
          ) ||
          'localhost';
        const suspicious =
          host.includes(
            ';'
          ) ||
          host.includes(
            '&&'
          ) ||
          host.includes(
            '|'
          ) ||
          host.includes(
            '$('
          );
        return json(
          res,
          200,
          {
            fixture:
              'cmdi',
            vulnerable:
              suspicious,
            simulatedCommand:
              'ping -c 1 ' +
              host,
            simulatedOutput:
              suspicious
                ? 'uid=1000(sentinel) gid=1000(sentinel)'
                : 'PING localhost',
            note:
              'No command is executed. This response is synthetic.',
          }
        );
      }
      if (
        url.pathname ===
        '/file'
      ) {
        const requested =
          url.searchParams.get(
            'name'
          ) ||
          'public.txt';
        const traversal =
          requested.includes(
            '..'
          );
        return json(
          res,
          200,
          {
            fixture:
              'path_traversal',
            vulnerable:
              traversal,
            requested,
            content:
              traversal
                ? 'SIMULATED_SECRET_VALUE'
                : 'This is a public demonstration file.',
          }
        );
      }
      if (
        url.pathname ===
        '/admin'
      ) {
        return json(
          res,
          200,
          {
            fixture:
              'auth_bypass',
            vulnerable:
              true,
            message:
              'Simulated protected administrator data',
            users,
          }
        );
      }
      if (
        url.pathname ===
        '/eval'
      ) {
        const code =
          url.searchParams.get(
            'code'
          ) || '';
        return json(
          res,
          200,
          {
            fixture:
              'code_injection',
            vulnerable:
              code.length > 0,
            input:
              code,
            simulatedEnvironment:
              code.includes(
                'process.env'
              )
                ? {
                    NODE_ENV:
                      'simulation',
                    HOME:
                      '/home/sentinel',
                    PATH:
                      '/usr/local/bin:/usr/bin',
                  }
                : null,
            note:
              'No code is executed. This response is synthetic.',
          }
        );
      }
      return json(
        res,
        404,
        {
          error:
            'Not found',
        }
      );
    }
  );
server.listen(
  ${TARGET_PORT},
  '${TARGET_BIND_HOST}',
  () => {
    console.log(
      'SentinelAI Safe Simulation target listening on port ${TARGET_PORT}'
    );
  }
);
`;
}
async function createTarget(
  _networkId,
  networkName,
  containerName,
  targetCode
) {
  if (
    !networkName
  ) {
    throw new Error(
      'Safe Simulation requires a Docker network.'
    );
  }
  if (
    !containerName
  ) {
    throw new Error(
      'Safe Simulation requires a target container name.'
    );
  }
  if (
    typeof targetCode !==
      'string' ||
    !targetCode.trim()
  ) {
    throw new Error(
      'Safe Simulation target code is empty.'
    );
  }
  const encodedTarget =
    Buffer.from(
      targetCode,
      'utf8'
    ).toString(
      'base64'
    );
  const container =
    await docker.createContainer({
      name:
        containerName,
      Image:
        TARGET_IMAGE,
      Env: [
        `TARGET_CODE=${encodedTarget}`,
      ],
      Cmd: [
        'sh',
        '-c',
        'printf "%s" "$TARGET_CODE" | base64 -d | node',
      ],
      ExposedPorts: {
        [`${TARGET_PORT}/tcp`]:
          {},
      },
      HostConfig: {
        AutoRemove:
          false,
        Memory:
          SANDBOX_LIMITS.memory,
        NanoCpus:
          SANDBOX_LIMITS.nanoCpus,
        PidsLimit:
          SANDBOX_LIMITS.pidsLimit,
        NetworkMode:
          networkName,
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
  return {
    container,
    hostPort:
      null,
    browserUrl:
      null,
    internalUrl:
      TARGET_INTERNAL_URL,
    healthUrl:
      TARGET_HEALTH_URL,
    isolated:
      true,
  };
}
async function waitForTarget(
  targetContainer,
  timeoutMs =
    TARGET_HEALTH_TIMEOUT
) {
  if (
    !targetContainer
  ) {
    throw new Error(
      'Safe Simulation target container is required.'
    );
  }
  const startedAt =
    Date.now();
  while (
    Date.now() -
      startedAt <
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
            stdout:
              true,
            stderr:
              true,
            tail:
              100,
          });
        console.error(
          '[sandbox] Safe Simulation target stopped unexpectedly.'
        );
        console.error(
          '[sandbox] Target state:',
          containerState.State
        );
        console.error(
          '[sandbox] Target logs:',
          logs.toString(
            'utf8'
          )
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
  ${JSON.stringify(
    TARGET_HEALTH_URL
  )},
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
`,
          ],
          AttachStdout:
            true,
          AttachStderr:
            true,
        });
      const stream =
        await exec.start({
          hijack:
            true,
          stdin:
            false,
        });
      await new Promise(
        (
          resolve,
          reject
        ) => {
          let settled =
            false;
          const timeout =
            setTimeout(
              () => {
                if (
                  settled
                ) {
                  return;
                }
                settled =
                  true;
                resolve();
              },
              2000
            );
          const finish =
            () => {
              if (
                settled
              ) {
                return;
              }
              settled =
                true;
              clearTimeout(
                timeout
              );
              resolve();
            };
          stream.once(
            'end',
            finish
          );
          stream.once(
            'close',
            finish
          );
          stream.once(
            'error',
            error => {
              if (
                settled
              ) {
                return;
              }
              settled =
                true;
              clearTimeout(
                timeout
              );
              reject(
                error
              );
            }
          );
        }
      );
      let execInspection =
        await exec.inspect();
      const waitStartedAt =
        Date.now();
      while (
        execInspection.Running &&
        Date.now() -
          waitStartedAt <
          2000
      ) {
        await new Promise(
          resolve =>
            setTimeout(
              resolve,
              50
            )
        );
        execInspection =
          await exec.inspect();
      }
      if (
        execInspection.ExitCode ===
        0
      ) {
        console.log(
          '[sandbox] Safe Simulation target health check passed.'
        );
        return true;
      }
      console.log(
        '[sandbox] Safe Simulation target health check returned exit code:',
        execInspection.ExitCode
      );
    } catch (error) {
      console.log(
        '[sandbox] Safe Simulation target health check retry:',
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
        stdout:
          true,
        stderr:
          true,
        tail:
          100,
      });
    console.error(
      '[sandbox] Safe Simulation target health check failed after timeout.'
    );
    console.error(
      '[sandbox] Target state:',
      inspection.State
    );
    console.error(
      '[sandbox] Target logs:',
      logs.toString(
        'utf8'
      )
    );
  } catch (error) {
    console.error(
      '[sandbox] Failed to inspect unhealthy Safe Simulation target:',
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
  if (
    !target ||
    !target.container
  ) {
    throw new Error(
      'Safe Simulation target information is unavailable.'
    );
  }
  return {
    name:
      'SentinelAI Safe Simulation Target',
    url:
      target.internalUrl,
    containerId:
      target.container.id,
    status:
      'running',
    containerName,
    internalUrl:
      target.internalUrl,
    browserUrl:
      null,
    healthUrl:
      target.healthUrl,
    isolated:
      true,
  };
}
module.exports = {
  generateTargetApplication,
  createTarget,
  waitForTarget,
  buildTargetInfo,
};