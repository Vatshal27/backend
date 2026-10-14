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

/*
 * Safe Simulation target.
 *
 * This target is intentionally synthetic.
 * It never executes commands, evaluates supplied code,
 * reads arbitrary files, performs outbound SSRF requests,
 * mutates prototypes, deserializes attacker objects,
 * performs request smuggling, races state-changing
 * operations, or poisons a shared cache.
 *
 * The fixtures exist only so SentinelAI can regression-test
 * its runtime planning, transport, evidence, validation,
 * reporting, and UI pipeline.
 */
function generateTargetApplication(
  _findings,
  _categories
) {
  return `
'use strict';

const http = require('http');
const { URL } = require('url');

const TARGET_HOST =
  ${JSON.stringify(TARGET_HOST)};

const TARGET_PORT =
  ${JSON.stringify(TARGET_PORT)};

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
  body,
  extraHeaders = {}
) {
  res.writeHead(
    status,
    {
      'Content-Type':
        'application/json; charset=utf-8',
      ...extraHeaders,
    }
  );

  res.end(
    JSON.stringify(body)
  );
}

function html(
  res,
  status,
  body,
  extraHeaders = {}
) {
  res.writeHead(
    status,
    {
      'Content-Type':
        'text/html; charset=utf-8',
      ...extraHeaders,
    }
  );

  res.end(body);
}

function fixture(
  type,
  body = {}
) {
  return {
    fixture:
      type,

    vulnerable:
      true,

    synthetic:
      true,

    ...body,
  };
}

function firstInput(
  url
) {
  const preferred = [
    'q',
    'query',
    'input',
    'name',
    'value',
    'code',
    'host',
    'url',
    'path',
    'file',
    'template',
    'filter',
    'redirect',
  ];

  for (
    const key of preferred
  ) {
    if (
      url.searchParams.has(
        key
      )
    ) {
      return (
        url.searchParams.get(
          key
        ) || ''
      );
    }
  }

  for (
    const [
      ,
      value,
    ] of url.searchParams
  ) {
    return value || '';
  }

  return '';
}

function createIndexPage() {
  const routes = [
    '/fixture/sqli',
    '/fixture/nosqli',
    '/fixture/cmdi',
    '/fixture/code-injection',
    '/fixture/ssti',
    '/fixture/ldap',
    '/fixture/xpath',
    '/fixture/xxe',
    '/fixture/prototype-pollution',
    '/fixture/deserialization',

    '/fixture/path-traversal',
    '/fixture/lfi',
    '/fixture/file-upload',

    '/fixture/auth-bypass/admin',
    '/fixture/idor/object/2',
    '/fixture/jwt',
    '/fixture/csrf',
    '/fixture/mass-assignment',
    '/fixture/race-condition',
    '/fixture/business-logic',

    '/fixture/xss',
    '/fixture/open-redirect',
    '/fixture/ssrf',
    '/fixture/host-header',
    '/fixture/websocket-security',
    '/fixture/graphql',

    '/fixture/cors',
    '/fixture/security-headers',
    '/fixture/cookie-security',
    '/fixture/unsafe-methods',
    '/fixture/request-smuggling',
    '/fixture/cache-poisoning',

    '/fixture/sensitive-data',
    '/fixture/debug-exposure',
    '/fixture/directory-listing/',
  ];

  return [
    '<!doctype html>',
    '<html>',
    '<head>',
    '<meta charset="utf-8">',
    '<title>SentinelAI Safe Simulation Target</title>',
    '</head>',
    '<body>',
    '<h1>SentinelAI Safe Simulation Target</h1>',
    '<p>',
    'Controlled synthetic application for runtime-engine regression testing.',
    '</p>',
    '<p>',
    'Attack families: 35',
    '</p>',
    '<ul>',

    ...routes.map(
      route =>
        '<li><a href="' +
        route +
        '">' +
        route +
        '</a></li>'
    ),

    '</ul>',
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
          'http://' +
          TARGET_HOST
        );

      const path =
        url.pathname;

      /*
       * Health
       */
      if (
        path ===
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

            catalogFamilies:
              35,
          }
        );
      }

      /*
       * Fixture index
       */
      if (
        path ===
        '/'
      ) {
        return html(
          res,
          200,
          createIndexPage()
        );
      }

      /*
       * --------------------------------------------------
       * Injection
       * --------------------------------------------------
       */

      if (
        path ===
        '/fixture/sqli'
      ) {
        const input =
          firstInput(url);

        return json(
          res,
          200,
          fixture(
            'sqli',
            {
              input,

              simulatedQuery:
                "SELECT * FROM users WHERE name = '" +
                input +
                "'",

              simulatedDatabaseSignal:
                'SQL syntax error near supplied expression',

              results:
                users,

              note:
                'Synthetic SQL injection fixture. No database query is executed.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/nosqli'
      ) {
        return json(
          res,
          200,
          fixture(
            'nosqli',
            {
              input:
                firstInput(url),

              simulatedDatabaseSignal:
                'MongoDB operator expression accepted',

              results:
                users,

              note:
                'Synthetic NoSQL injection fixture. No database operation is performed.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/cmdi'
      ) {
        const input =
          firstInput(url);

        return json(
          res,
          200,
          fixture(
            'cmdi',
            {
              input,

              simulatedCommand:
                'ping -c 1 ' +
                input,

              simulatedOutput:
                'uid=1000(sentinel) gid=1000(sentinel)',

              note:
                'No operating-system command is executed.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/code-injection'
      ) {
        return json(
          res,
          200,
          fixture(
            'code_injection',
            {
              input:
                firstInput(url),

              simulatedEnvironment: {
                NODE_ENV:
                  'simulation',

                HOME:
                  '/home/sentinel',

                PATH:
                  '/usr/local/bin:/usr/bin',
              },

              note:
                'No supplied code is evaluated.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/ssti'
      ) {
        const input =
          firstInput(url);

        return json(
          res,
          200,
          fixture(
            'ssti',
            {
              input,

              rendered:
                '49',

              note:
                'Template execution is simulated only.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/ldap'
      ) {
        return json(
          res,
          200,
          fixture(
            'ldap_injection',
            {
              input:
                firstInput(url),

              simulatedFilter:
                '(&(uid=*)(objectClass=*))',

              simulatedLdapSignal:
                'LDAP filter accepted synthetic injected expression',

              note:
                'No LDAP service is contacted.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/xpath'
      ) {
        return json(
          res,
          200,
          fixture(
            'xpath_injection',
            {
              input:
                firstInput(url),

              simulatedXPathSignal:
                'XPath expression altered query truth value',

              note:
                'No XML datastore is queried.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/xxe'
      ) {
        return json(
          res,
          200,
          fixture(
            'xxe',
            {
              entity:
                'sentinel-synthetic-entity',

              simulatedExpansion:
                'SENTINEL_XXE_CANARY',

              externalRequestPerformed:
                false,

              localFileRead:
                false,

              note:
                'XXE behavior is simulated without external access or file reads.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/prototype-pollution'
      ) {
        return json(
          res,
          200,
          fixture(
            'prototype_pollution',
            {
              property:
                'sentinelPrototypeCanary',

              simulatedPollution:
                true,

              actualPrototypeMutation:
                false,

              note:
                'No JavaScript global prototype is modified.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/deserialization'
      ) {
        return json(
          res,
          200,
          fixture(
            'insecure_deserialization',
            {
              simulatedObject:
                'SentinelSyntheticSerializedObject',

              gadgetExecuted:
                false,

              note:
                'No unsafe deserialization or gadget execution occurs.',
            }
          )
        );
      }

      /*
       * --------------------------------------------------
       * File access
       * --------------------------------------------------
       */

      if (
        path ===
        '/fixture/path-traversal'
      ) {
        return json(
          res,
          200,
          fixture(
            'path_traversal',
            {
              requested:
                firstInput(url),

              content:
                'SENTINEL_PATH_TRAVERSAL_CANARY',

              actualFileRead:
                false,

              note:
                'No host or container file is read.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/lfi'
      ) {
        return json(
          res,
          200,
          fixture(
            'lfi',
            {
              requested:
                firstInput(url),

              content:
                'SENTINEL_LFI_CANARY',

              actualFileRead:
                false,

              note:
                'Local file inclusion behavior is simulated only.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/file-upload'
      ) {
        return json(
          res,
          200,
          fixture(
            'file_upload',
            {
              acceptedFilename:
                'sentinel-test.txt',

              stored:
                false,

              executed:
                false,

              note:
                'No file is written to persistent storage.',
            }
          )
        );
      }

      /*
       * --------------------------------------------------
       * Authentication / authorization
       * --------------------------------------------------
       */

      if (
        path ===
        '/fixture/auth-bypass/admin'
      ) {
        return json(
          res,
          200,
          fixture(
            'auth_bypass',
            {
              authenticated:
                false,

              authorizationRequired:
                true,

              protectedDataReturned:
                true,

              users,

              note:
                'Controlled authentication-bypass fixture.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/idor/object/2'
      ) {
        return json(
          res,
          200,
          fixture(
            'idor',
            {
              requestedObjectId:
                2,

              requestingUserId:
                1,

              objectOwnerId:
                2,

              authorizationChecked:
                false,

              object: {
                id:
                  2,

                ownerId:
                  2,

                value:
                  'SENTINEL_IDOR_CANARY',
              },
            }
          )
        );
      }

      if (
        path ===
        '/fixture/jwt'
      ) {
        return json(
          res,
          200,
          fixture(
            'jwt',
            {
              suppliedTokenAccepted:
                true,

              signatureValidated:
                false,

              claims: {
                sub:
                  'demo_student',

                role:
                  'administrator',
              },

              note:
                'No real token is issued or trusted.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/csrf'
      ) {
        return json(
          res,
          200,
          fixture(
            'csrf',
            {
              stateChangingAction:
                true,

              csrfTokenRequired:
                false,

              stateActuallyChanged:
                false,

              note:
                'No persistent state is modified.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/mass-assignment'
      ) {
        return json(
          res,
          200,
          fixture(
            'mass_assignment',
            {
              suppliedFields: {
                displayName:
                  'Sentinel User',

                role:
                  'administrator',
              },

              protectedFieldAccepted:
                true,

              persisted:
                false,

              note:
                'Privilege change is simulated only.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/race-condition'
      ) {
        return json(
          res,
          200,
          fixture(
            'race_condition',
            {
              operation:
                'synthetic-transfer',

              expectedExecutions:
                1,

              simulatedExecutions:
                2,

              concurrentMutationPerformed:
                false,

              note:
                'No concurrent state-changing operation is executed.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/business-logic'
      ) {
        return json(
          res,
          200,
          fixture(
            'business_logic',
            {
              workflow:
                'checkout',

              expectedOrder:
                [
                  'cart',
                  'payment',
                  'confirmation',
                ],

              simulatedAcceptedOrder:
                [
                  'cart',
                  'confirmation',
                ],

              actualTransactionPerformed:
                false,
            }
          )
        );
      }

      /*
       * --------------------------------------------------
       * Client / server-side web behavior
       * --------------------------------------------------
       */

      if (
        path ===
        '/fixture/xss'
      ) {
        const input =
          firstInput(url) ||
          '<script>alert(1)</script>';

        return html(
          res,
          200,
          '<!doctype html>' +
          '<html>' +
          '<body>' +
          '<div id="sentinel-reflection">' +
          input +
          '</div>' +
          '</body>' +
          '</html>'
        );
      }

      if (
        path ===
        '/fixture/open-redirect'
      ) {
        res.writeHead(
          302,
          {
            Location:
              'https://example.invalid/sentinel-open-redirect',
          }
        );

        return res.end();
      }

      if (
        path ===
        '/fixture/ssrf'
      ) {
        return json(
          res,
          200,
          fixture(
            'ssrf',
            {
              suppliedUrl:
                firstInput(url),

              simulatedOutboundRequest:
                true,

              callback:
                'SENTINEL_SSRF_CANARY',

              outboundRequestActuallyPerformed:
                false,

              note:
                'No external or internal network request is performed.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/host-header'
      ) {
        return json(
          res,
          200,
          fixture(
            'host_header_injection',
            {
              suppliedHost:
                req.headers.host ||
                '',

              generatedLink:
                'https://attacker.invalid/reset/sentinel',

              hostTrusted:
                true,

              note:
                'Synthetic Host-header trust behavior.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/websocket-security'
      ) {
        return json(
          res,
          200,
          fixture(
            'websocket_security',
            {
              websocketEndpoint:
                '/socket',

              originValidated:
                false,

              authenticationRequired:
                false,

              websocketConnectionOpened:
                false,

              note:
                'No WebSocket connection is established by this fixture.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/graphql'
      ) {
        return json(
          res,
          200,
          fixture(
            'graphql_security',
            {
              endpoint:
                '/graphql',

              introspectionEnabled:
                true,

              authorizationApplied:
                false,

              simulatedSchema: {
                queryType:
                  'Query',
              },

              note:
                'GraphQL behavior is represented synthetically.',
            }
          )
        );
      }

      /*
       * --------------------------------------------------
       * HTTP configuration
       * --------------------------------------------------
       */

      if (
        path ===
        '/fixture/cors'
      ) {
        return json(
          res,
          200,
          fixture(
            'cors',
            {
              suppliedOrigin:
                req.headers.origin ||
                'https://sentinelai.invalid',

              credentialsAllowed:
                true,
            }
          ),
          {
            'Access-Control-Allow-Origin':
              req.headers.origin ||
              '*',

            'Access-Control-Allow-Credentials':
              'true',
          }
        );
      }

      if (
        path ===
        '/fixture/security-headers'
      ) {
        return json(
          res,
          200,
          fixture(
            'security_headers',
            {
              missing: [
                'content-security-policy',
                'x-content-type-options',
                'referrer-policy',
              ],
            }
          )
        );
      }

      if (
        path ===
        '/fixture/cookie-security'
      ) {
        return json(
          res,
          200,
          fixture(
            'cookie_security',
            {
              cookie:
                'session=sentinel-synthetic',

              missingFlags: [
                'HttpOnly',
                'Secure',
                'SameSite',
              ],
            }
          ),
          {
            'Set-Cookie':
              'session=sentinel-synthetic; Path=/',
          }
        );
      }

      if (
        path ===
        '/fixture/unsafe-methods'
      ) {
        return json(
          res,
          200,
          fixture(
            'unsafe_http_methods',
            {
              acceptedMethod:
                req.method,

              allow: [
                'GET',
                'POST',
                'PUT',
                'DELETE',
                'TRACE',
              ],

              note:
                'No state-changing action is performed.',
            }
          ),
          {
            Allow:
              'GET, POST, PUT, DELETE, TRACE, OPTIONS',
          }
        );
      }

      if (
        path ===
        '/fixture/request-smuggling'
      ) {
        return json(
          res,
          200,
          fixture(
            'request_smuggling',
            {
              conflictingFramingSimulated:
                true,

              malformedStreamSent:
                false,

              proxyDesynchronizationPerformed:
                false,

              note:
                'No malformed HTTP stream or proxy desynchronization is attempted.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/cache-poisoning'
      ) {
        return json(
          res,
          200,
          fixture(
            'cache_poisoning',
            {
              unkeyedInput:
                'X-Forwarded-Host',

              simulatedCachedValue:
                'attacker.invalid',

              cacheModified:
                false,

              note:
                'No shared cache is modified.',
            }
          )
        );
      }

      /*
       * --------------------------------------------------
       * Exposure
       * --------------------------------------------------
       */

      if (
        path ===
        '/fixture/sensitive-data'
      ) {
        return json(
          res,
          200,
          fixture(
            'sensitive_data',
            {
              syntheticSecret:
                'SENTINEL_DEMO_SECRET_DO_NOT_USE',

              syntheticToken:
                'sentinel_test_token_1234567890',

              note:
                'Values are synthetic test data only.',
            }
          )
        );
      }

      if (
        path ===
        '/fixture/debug-exposure'
      ) {
        return html(
          res,
          500,
          [
            '<!doctype html>',
            '<html>',
            '<body>',
            '<h1>Debug Exception</h1>',
            '<pre>',
            'Error: SENTINEL_DEBUG_CANARY',
            '\\n    at syntheticHandler (/app/server.js:42:13)',
            '\\n    at processRequest (/app/server.js:10:5)',
            '</pre>',
            '</body>',
            '</html>',
          ].join('')
        );
      }

      if (
        path ===
          '/fixture/directory-listing' ||
        path ===
          '/fixture/directory-listing/'
      ) {
        return html(
          res,
          200,
          [
            '<!doctype html>',
            '<html>',
            '<head>',
            '<title>Index of /fixture/directory-listing/</title>',
            '</head>',
            '<body>',
            '<h1>Index of /fixture/directory-listing/</h1>',
            '<a href="../">../</a>',
            '<a href="backup.zip">backup.zip</a>',
            '<a href="config.old">config.old</a>',
            '</body>',
            '</html>',
          ].join('')
        );
      }

      return json(
        res,
        404,
        {
          error:
            'Not found',

          path,
        }
      );
    }
  );

server.listen(
  TARGET_PORT,
  ${JSON.stringify(TARGET_BIND_HOST)},
  () => {
    console.log(
      'SentinelAI Safe Simulation target listening on port ' +
      TARGET_PORT
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