'use strict';

const crypto = require('crypto');
const http = require('http');
const https = require('https');

const {
  docker,
  getDockerTargetUrl,
} = require('./client');

const {
  ATTACK_IMAGE,
  SANDBOX_LIMITS,
  SANDBOX_TIMEOUT,
  REQUEST_TIMEOUT,
} = require('./config');

const {
  getAttackDefinition,
} = require('./attacks/catalog');

const {
  buildPayloadVariants,
} = require('./attacks/payloads');

const {
  chooseApplicableRoute,
} = require('./attacks/applicability');

const {
  buildProjectRequest,
  buildBaselineRequest,
} = require('./attacks/request-builder');

const {
  discoverRoutes,
} = require('./discovery/routes');

const {
  evaluateRuntimeEvidence,
} = require('./validation/runtime-evidence');

const TEST_ORIGIN =
  'https://sentinelai.invalid';

const MAX_RESPONSE_BYTES =
  1024 * 1024;

const MAX_DISCOVERY_PAGES =
  10;

const MAX_DISCOVERY_ROUTES =
  100;

const SAFE_SIMULATION_CONCURRENCY =
  8;

const PROJECT_VALIDATION_CONCURRENCY =
  4;

// These families require trusted project-specific context before generic Project Validation can execute them safely.
const PROJECT_CONTEXT_REQUIRED =
  new Set([
    'xxe',
    'prototype_pollution',
    'insecure_deserialization',
    'file_upload',
    'idor',
    'jwt',
    'csrf',
    'mass_assignment',
    'race_condition',
    'business_logic',
    'ssrf',
    'host_header_injection',
    'websocket_security',
    'graphql_security',
    'request_smuggling',
    'cache_poisoning',
  ]);

function createId(
  prefix = ''
) {
  return (
    prefix +
    crypto
      .randomBytes(6)
      .toString('hex')
  );
}

function asArray(
  value
) {
  return Array.isArray(
    value
  )
    ? value
    : [];
}

function demuxDockerLogBuffer(
  raw
) {
  const buffer =
    Buffer.isBuffer(
      raw
    )
      ? raw
      : Buffer.from(
          raw || ''
        );

  const stdout = [];
  const stderr = [];

  let offset = 0;
  let framed = false;

  while (
    offset + 8 <=
    buffer.length
  ) {
    const streamType =
      buffer[offset];

    const validHeader =
      (
        streamType === 0 ||
        streamType === 1 ||
        streamType === 2
      ) &&
      buffer[offset + 1] === 0 &&
      buffer[offset + 2] === 0 &&
      buffer[offset + 3] === 0;

    if (
      !validHeader
    ) {
      break;
    }

    const length =
      buffer.readUInt32BE(
        offset + 4
      );

    const start =
      offset + 8;

    const end =
      start + length;

    if (
      end >
      buffer.length
    ) {
      break;
    }

    framed =
      true;

    const payload =
      buffer.subarray(
        start,
        end
      );

    if (
      streamType === 2
    ) {
      stderr.push(
        payload
      );
    } else {
      stdout.push(
        payload
      );
    }

    offset =
      end;
  }

  if (
    !framed
  ) {
    return {
      stdout:
        buffer.toString(
          'utf8'
        ),

      stderr:
        '',
    };
  }

  if (
    offset <
    buffer.length
  ) {
    stdout.push(
      buffer.subarray(
        offset
      )
    );
  }

  return {
    stdout:
      Buffer.concat(
        stdout
      ).toString(
        'utf8'
      ),

    stderr:
      Buffer.concat(
        stderr
      ).toString(
        'utf8'
      ),
  };
}

function hostRequest(
  targetUrl,
  requestInfo = {}
) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
      const url =
        new URL(
          requestInfo.path ||
          '/',
          targetUrl
        );

      const transport =
        url.protocol ===
        'https:'
          ? https
          : http;

      const body =
        requestInfo.body ===
          undefined ||
        requestInfo.body ===
          null
          ? null
          : String(
              requestInfo.body
            );

      const headers = {
        ...(
          requestInfo.headers ||
          {}
        ),
      };

      const hasContentLength =
        Object
          .keys(
            headers
          )
          .some(
            key =>
              key
                .toLowerCase() ===
              'content-length'
          );

      if (
        body !== null &&
        !hasContentLength
      ) {
        headers[
          'Content-Length'
        ] =
          Buffer.byteLength(
            body
          );
      }

      const req =
        transport.request(
          {
            hostname:
              url.hostname,

            port:
              url.port ||
              (
                url.protocol ===
                'https:'
                  ? 443
                  : 80
              ),

            method:
              requestInfo.method ||
              'GET',

            path:
              url.pathname +
              url.search,

            headers,

            timeout:
              REQUEST_TIMEOUT,
          },

          res => {
            const chunks = [];
            let size = 0;

            res.on(
              'data',
              chunk => {
                if (
                  size >=
                  MAX_RESPONSE_BYTES
                ) {
                  return;
                }

                const remaining =
                  MAX_RESPONSE_BYTES -
                  size;

                const safeChunk =
                  chunk.length >
                  remaining
                    ? chunk.subarray(
                        0,
                        remaining
                      )
                    : chunk;

                chunks.push(
                  safeChunk
                );

                size +=
                  safeChunk.length;
              }
            );

            res.on(
              'end',
              () => {
                resolve({
                  statusCode:
                    res.statusCode,

                  headers:
                    res.headers,

                  body:
                    Buffer.concat(
                      chunks
                    ).toString(
                      'utf8'
                    ),
                });
              }
            );
          }
        );

      req.on(
        'error',
        reject
      );

      req.on(
        'timeout',
        () => {
          req.destroy(
            new Error(
              'Request timed out'
            )
          );
        }
      );

      if (
        body !== null
      ) {
        req.write(
          body
        );
      }

      req.end();
    }
  );
}

function routeKey(
  route
) {
  return [
    route.method,
    route.url,
    (
      route.parameters ||
      []
    )
      .slice()
      .sort()
      .join(','),
  ].join('|');
}

async function discoverProjectRoutes(
  targetUrl
) {
  const origin =
    new URL(
      targetUrl
    ).origin;

  const queue = [
    new URL(
      targetUrl
    ).toString(),
  ];

  const visited =
    new Set();

  const collected =
    new Map();

  while (
    queue.length > 0 &&
    visited.size <
      MAX_DISCOVERY_PAGES &&
    collected.size <
      MAX_DISCOVERY_ROUTES
  ) {
    const pageUrl =
      queue.shift();

    if (
      visited.has(
        pageUrl
      )
    ) {
      continue;
    }

    let parsed;

    try {
      parsed =
        new URL(
          pageUrl
        );
    } catch {
      continue;
    }

    if (
      parsed.origin !==
      origin
    ) {
      continue;
    }

    visited.add(
      pageUrl
    );

    let response;

    try {
      response =
        await hostRequest(
          targetUrl,
          {
            method:
              'GET',

            path:
              pageUrl,

            headers:
              {},
          }
        );
    } catch {
      continue;
    }

    const routes =
      discoverRoutes(
        response.body,
        pageUrl,
        {
          maxRoutes:
            MAX_DISCOVERY_ROUTES,
        }
      );

    for (
      const route of routes
    ) {
      const key =
        routeKey(
          route
        );

      if (
        !collected.has(
          key
        )
      ) {
        collected.set(
          key,
          route
        );
      }

      if (
        route.method ===
        'GET'
      ) {
        try {
          const candidate =
            new URL(
              route.url
            );

          if (
            candidate.origin ===
              origin &&
            !visited.has(
              candidate.toString()
            ) &&
            queue.length <
              MAX_DISCOVERY_ROUTES
          ) {
            queue.push(
              candidate.toString()
            );
          }
        } catch {
          // Ignore malformed discovered URLs.
        }
      }

      if (
        collected.size >=
        MAX_DISCOVERY_ROUTES
      ) {
        break;
      }
    }
  }

  if (
    collected.size ===
    0
  ) {
    const root = {
      method:
        'GET',

      url:
        targetUrl,

      source:
        'root',

      parameters:
        [],
    };

    collected.set(
      routeKey(
        root
      ),
      root
    );
  }

  return Array.from(
    collected.values()
  ).slice(
    0,
    MAX_DISCOVERY_ROUTES
  );
}

function simulationRequest(
  attackType,
  payload
) {
  const encoded =
    encodeURIComponent(
      payload ||
      ''
    );

  switch (
    attackType
  ) {
    case 'sqli':
      return {
        method:
          'GET',

        path:
          `/fixture/sqli?q=${encoded}`,

        headers:
          {},
      };

    case 'nosqli':
      return {
        method:
          'GET',

        path:
          `/fixture/nosqli?query=${encoded}`,

        headers:
          {},
      };

    case 'cmdi':
      return {
        method:
          'GET',

        path:
          `/fixture/cmdi?host=${encoded}`,

        headers:
          {},
      };

    case 'code_injection':
      return {
        method:
          'GET',

        path:
          `/fixture/code-injection?code=${encoded}`,

        headers:
          {},
      };

    case 'ssti':
      return {
        method:
          'GET',

        path:
          `/fixture/ssti?template=${encoded}`,

        headers:
          {},
      };

    case 'ldap_injection':
      return {
        method:
          'GET',

        path:
          `/fixture/ldap?user=${encoded}`,

        headers:
          {},
      };

    case 'xpath_injection':
      return {
        method:
          'GET',

        path:
          `/fixture/xpath?user=${encoded}`,

        headers:
          {},
      };

    case 'xxe':
      return {
        method:
          'POST',

        path:
          '/fixture/xxe',

        headers: {
          'Content-Type':
            'application/xml',
        },

        body:
          '<request><value>SENTINELAI_XXE_CANARY</value></request>',
      };

    case 'prototype_pollution':
      return {
        method:
          'GET',

        path:
          '/fixture/prototype-pollution',

        headers:
          {},
      };

    case 'insecure_deserialization':
      return {
        method:
          'POST',

        path:
          '/fixture/deserialization',

        headers: {
          'Content-Type':
            'application/json',
        },

        body:
          JSON.stringify({
            serialized:
              'SENTINELAI_DESERIALIZATION_CANARY',
          }),
      };

    case 'path_traversal':
      return {
        method:
          'GET',

        path:
          `/fixture/path-traversal?file=${encoded}`,

        headers:
          {},
      };

    case 'lfi':
      return {
        method:
          'GET',

        path:
          `/fixture/lfi?file=${encoded}`,

        headers:
          {},
      };

    case 'file_upload':
      return {
        method:
          'POST',

        path:
          '/fixture/file-upload',

        headers: {
          'Content-Type':
            'application/json',
        },

        body:
          JSON.stringify({
            filename:
              'sentinelai-canary.txt',

            content:
              'SENTINELAI_UPLOAD_CANARY',
          }),
      };

    case 'auth_bypass':
      return {
        method:
          'GET',

        path:
          '/fixture/auth-bypass/admin',

        headers:
          {},
      };

    case 'idor':
      return {
        method:
          'GET',

        path:
          '/fixture/idor/object/2',

        headers: {
          'X-Sentinel-User':
            'user-1',
        },
      };

    case 'jwt':
      return {
        method:
          'GET',

        path:
          '/fixture/jwt',

        headers: {
          Authorization:
            'Bearer SENTINELAI_INVALID_TOKEN',
        },
      };

    case 'csrf':
      return {
        method:
          'POST',

        path:
          '/fixture/csrf',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',

          Cookie:
            'sentinel_session=synthetic-session',
        },

        body:
          'action=change-email',
      };

    case 'mass_assignment':
      return {
        method:
          'POST',

        path:
          '/fixture/mass-assignment',

        headers: {
          'Content-Type':
            'application/json',
        },

        body:
          JSON.stringify({
            displayName:
              'sentinel',

            role:
              'administrator',
          }),
      };

    case 'race_condition':
      return {
        method:
          'GET',

        path:
          '/fixture/race-condition',

        headers:
          {},
      };

    case 'business_logic':
      return {
        method:
          'GET',

        path:
          '/fixture/business-logic',

        headers:
          {},
      };

    case 'xss':
      return {
        method:
          'GET',

        path:
          `/fixture/xss?input=${encoded}`,

        headers:
          {},
      };

    case 'open_redirect':
      return {
        method:
          'GET',

        path:
          '/fixture/open-redirect?next=https%3A%2F%2Fexample.invalid',

        headers:
          {},
      };

    case 'ssrf':
      return {
        method:
          'GET',

        path:
          '/fixture/ssrf',

        headers:
          {},
      };

    case 'host_header_injection':
      return {
        method:
          'GET',

        path:
          '/fixture/host-header',

        headers: {
          'X-Forwarded-Host':
            'sentinelai.invalid',
        },
      };

    case 'websocket_security':
      return {
        method:
          'GET',

        path:
          '/fixture/websocket-security',

        headers:
          {},
      };

    case 'graphql_security':
      return {
        method:
          'POST',

        path:
          '/fixture/graphql',

        headers: {
          'Content-Type':
            'application/json',
        },

        body:
          JSON.stringify({
            query:
              '{ sentinelSyntheticField }',
          }),
      };

    case 'cors':
      return {
        method:
          'GET',

        path:
          '/fixture/cors',

        headers: {
          Origin:
            TEST_ORIGIN,
        },
      };

    case 'security_headers':
      return {
        method:
          'GET',

        path:
          '/fixture/security-headers',

        headers:
          {},
      };

    case 'cookie_security':
      return {
        method:
          'GET',

        path:
          '/fixture/cookie-security',

        headers:
          {},
      };

    case 'unsafe_http_methods':
      return {
        method:
          'OPTIONS',

        path:
          '/fixture/unsafe-methods',

        headers:
          {},
      };

    case 'request_smuggling':
      return {
        method:
          'GET',

        path:
          '/fixture/request-smuggling',

        headers:
          {},
      };

    case 'cache_poisoning':
      return {
        method:
          'GET',

        path:
          '/fixture/cache-poisoning',

        headers: {
          'X-Forwarded-Host':
            'sentinelai.invalid',
        },
      };

    case 'sensitive_data':
      return {
        method:
          'GET',

        path:
          '/fixture/sensitive-data',

        headers:
          {},
      };

    case 'debug_exposure':
      return {
        method:
          'GET',

        path:
          '/fixture/debug-exposure',

        headers:
          {},
      };

    case 'directory_listing':
      return {
        method:
          'GET',

        path:
          '/fixture/directory-listing/',

        headers:
          {},
      };

    default:
      return null;
  }
}

function sourceFinding(
  findings,
  plan
) {
  return (
    asArray(
      findings
    ).find(
      finding =>
        finding?.id ===
        plan?.findingId
    ) ||
    null
  );
}

function preparedAttack({
  plan,
  payload = null,
  route = null,
  request,
  baselineRequest = null,
}) {
  const definition =
    getAttackDefinition(
      plan.attackType
    );

  return {
    id:
      createId(
        'atk-'
      ),

    findingId:
      plan.findingId ||
      null,

    source:
      plan.source ||
      'runtime',

    attackType:
      plan.attackType,

    attackFamily:
      plan.attackFamily ||
      definition?.family ||
      null,

    attackName:
      plan.attackName ||
      definition?.name ||
      plan.attackType,

    validator:
      plan.validator ||
      definition?.validator ||
      'custom',

    activeProbe:
      definition?.activeProbe !==
      false,

    payload,

    selectedRoute:
      route,

    request,

    baselineRequest,
  };
}

function notApplicableAttack(
  plan,
  rationale
) {
  const timestamp =
    new Date()
      .toISOString();

  const definition =
    getAttackDefinition(
      plan.attackType
    );

  return {
    id:
      createId(
        'atk-'
      ),

    findingId:
      plan.findingId ||
      null,

    source:
      plan.source ||
      'runtime',

    tool:
      plan.validator ||
      definition?.validator ||
      'custom',

    attackType:
      plan.attackType,

    attackFamily:
      plan.attackFamily ||
      definition?.family ||
      null,

    attackName:
      plan.attackName ||
      definition?.name ||
      plan.attackType,

    status:
      'inconclusive',

    runtimeVerdict:
      'not_applicable',

    executed:
      false,

    confidence:
      100,

    rationale,

    payload:
      null,

    startedAt:
      timestamp,

    finishedAt:
      timestamp,

    evidence: [
      {
        id:
          createId(
            'ev-'
          ),

        type:
          'log',

        timestamp,

        source:
          'runtime-applicability',

        content:
          rationale,
      },
    ],
  };
}

function prepareSimulation(
  findings,
  plans
) {
  const prepared = [];
  const skipped = [];

  for (
    const plan of
    asArray(
      plans
    )
  ) {
    const definition =
      getAttackDefinition(
        plan.attackType
      );

    if (
      !definition
    ) {
      skipped.push(
        notApplicableAttack(
          plan,
          'No catalog definition exists for this attack type.'
        )
      );

      continue;
    }

    const finding =
      sourceFinding(
        findings,
        plan
      );

    const payloads =
      buildPayloadVariants(
        finding,
        plan.attackType
      );

    const variants =
      payloads.length > 0
        ? payloads
        : [
            null,
          ];

    for (
      const payload of
      variants
    ) {
      const request =
        simulationRequest(
          plan.attackType,
          payload
        );

      if (
        !request
      ) {
        skipped.push(
          notApplicableAttack(
            plan,
            `No Safe Simulation fixture request exists for ${plan.attackType}.`
          )
        );

        continue;
      }

      prepared.push(
        preparedAttack({
          plan,
          payload,
          route:
            null,
          request,
          baselineRequest:
            null,
        })
      );
    }
  }

  return {
    prepared,
    skipped,
  };
}

function rootRoute(
  routes
) {
  return (
    asArray(
      routes
    ).find(
      route =>
        route.source ===
          'root' &&
        route.method ===
          'GET'
    ) ||
    asArray(
      routes
    ).find(
      route =>
        route.method ===
        'GET'
    ) ||
    null
  );
}

function passiveRequest(
  plan,
  route
) {
  if (
    !route
  ) {
    return null;
  }

  const parsed =
    new URL(
      route.url
    );

  if (
    plan.attackType ===
    'unsafe_http_methods'
  ) {
    return {
      method:
        'OPTIONS',

      path:
        parsed.pathname +
        parsed.search,

      headers:
        {},
    };
  }

  return {
    method:
      'GET',

    path:
      parsed.pathname +
      parsed.search,

    headers:
      {},
  };
}

function specialProjectRequest(
  plan,
  route
) {
  if (
    !route
  ) {
    return null;
  }

  const parsed =
    new URL(
      route.url
    );

  if (
    plan.attackType ===
    'cors'
  ) {
    return {
      method:
        'GET',

      path:
        parsed.pathname +
        parsed.search,

      headers: {
        Origin:
          TEST_ORIGIN,
      },
    };
  }

  if (
    plan.attackType ===
    'auth_bypass'
  ) {
    return {
      method:
        'GET',

      path:
        parsed.pathname +
        parsed.search,

      headers:
        {},
    };
  }

  return null;
}

function prepareProject(
  findings,
  plans,
  routes
) {
  const prepared = [];
  const skipped = [];

  for (
    const plan of
    asArray(
      plans
    )
  ) {
    const definition =
      getAttackDefinition(
        plan.attackType
      );

    if (
      !definition
    ) {
      skipped.push(
        notApplicableAttack(
          plan,
          'The attack definition is missing from the SentinelAI catalog.'
        )
      );

      continue;
    }

    if (
      PROJECT_CONTEXT_REQUIRED.has(
        plan.attackType
      )
    ) {
      skipped.push(
        notApplicableAttack(
          plan,
          `${definition.name} requires additional trusted application context before SentinelAI can test it safely against a project runtime.`
        )
      );

      continue;
    }

    const finding =
      sourceFinding(
        findings,
        plan
      );

    if (
      definition.activeProbe ===
      false
    ) {
      const route =
        rootRoute(
          routes
        );

      const request =
        passiveRequest(
          plan,
          route
        );

      if (
        !request
      ) {
        skipped.push(
          notApplicableAttack(
            plan,
            'No safe route was available for this passive runtime check.'
          )
        );

        continue;
      }

      prepared.push(
        preparedAttack({
          plan,
          route,
          request,
        })
      );

      continue;
    }

    const route =
      plan.attackType ===
      'cors'
        ? rootRoute(
            routes
          )
        : chooseApplicableRoute(
            plan.attackType,
            routes
          );

    if (
      !route
    ) {
      skipped.push(
        notApplicableAttack(
          plan,
          'No discovered route matched the applicability requirements for this runtime check.'
        )
      );

      continue;
    }

    const special =
      specialProjectRequest(
        plan,
        route
      );

    if (
      special
    ) {
      prepared.push(
        preparedAttack({
          plan,
          route,
          request:
            special,

          baselineRequest:
            buildBaselineRequest(
              route
            ),
        })
      );

      continue;
    }

    const payloads =
      buildPayloadVariants(
        finding,
        plan.attackType
      );

    if (
      payloads.length ===
      0
    ) {
      skipped.push(
        notApplicableAttack(
          plan,
          'No safe executable payload is currently available for this applicable runtime check.'
        )
      );

      continue;
    }

    for (
      const payload of
      payloads
    ) {
      const request =
        buildProjectRequest(
          {
            attackType:
              plan.attackType,

            payload,
          },
          route
        );

      if (
        !request
      ) {
        continue;
      }

      prepared.push(
        preparedAttack({
          plan,
          payload,
          route,
          request,

          baselineRequest:
            buildBaselineRequest(
              route
            ),
        })
      );
    }
  }

  return {
    prepared,
    skipped,
  };
}

function buildAttackerScript(
  attacks,
  targetUrl,
  attackConcurrency
) {
  return `
'use strict';

const http =
  require('http');

const https =
  require('https');

const attacks =
  ${JSON.stringify(attacks)};

const targetUrl =
  ${JSON.stringify(targetUrl)};

const requestTimeout =
  ${JSON.stringify(REQUEST_TIMEOUT)};

const maxResponseBytes =
  ${JSON.stringify(MAX_RESPONSE_BYTES)};

const attackConcurrency =
  ${JSON.stringify(attackConcurrency)};

function hasHeader(
  headers,
  name
) {
  const normalized =
    String(
      name
    ).toLowerCase();

  return Object
    .keys(
      headers ||
      {}
    )
    .some(
      key =>
        key.toLowerCase() ===
        normalized
    );
}

function executeRequest(
  requestInfo
) {
  return new Promise(
    (
      resolve,
      reject
    ) => {
      const url =
        new URL(
          requestInfo.path ||
          '/',
          targetUrl
        );

      const transport =
        url.protocol ===
        'https:'
          ? https
          : http;

      const body =
        requestInfo.body ===
          undefined ||
        requestInfo.body ===
          null
          ? null
          : String(
              requestInfo.body
            );

      const headers = {
        ...(
          requestInfo.headers ||
          {}
        ),
      };

      if (
        body !== null &&
        !hasHeader(
          headers,
          'content-length'
        )
      ) {
        headers[
          'Content-Length'
        ] =
          Buffer.byteLength(
            body
          );
      }

      const req =
        transport.request(
          {
            hostname:
              url.hostname,

            port:
              url.port ||
              (
                url.protocol ===
                'https:'
                  ? 443
                  : 80
              ),

            method:
              requestInfo.method ||
              'GET',

            path:
              url.pathname +
              url.search,

            headers,

            timeout:
              requestTimeout,
          },

          res => {
            const chunks = [];
            let size = 0;

            res.on(
              'data',
              chunk => {
                if (
                  size >=
                  maxResponseBytes
                ) {
                  return;
                }

                const remaining =
                  maxResponseBytes -
                  size;

                const safeChunk =
                  chunk.length >
                  remaining
                    ? chunk.subarray(
                        0,
                        remaining
                      )
                    : chunk;

                chunks.push(
                  safeChunk
                );

                size +=
                  safeChunk.length;
              }
            );

            res.on(
              'end',
              () => {
                resolve({
                  statusCode:
                    res.statusCode,

                  headers:
                    res.headers,

                  body:
                    Buffer.concat(
                      chunks
                    ).toString(
                      'utf8'
                    ),
                });
              }
            );
          }
        );

      req.on(
        'error',
        reject
      );

      req.on(
        'timeout',
        () => {
          req.destroy(
            new Error(
              'Request timed out'
            )
          );
        }
      );

      if (
        body !== null
      ) {
        req.write(
          body
        );
      }

      req.end();
    }
  );
}

function requestEvidence(
  requestInfo
) {
  const url =
    new URL(
      requestInfo.path ||
      '/',
      targetUrl
    ).toString();

  return {
    method:
      requestInfo.method ||
      'GET',

    url,

    headers:
      requestInfo.headers ||
      {},

    ...(
      requestInfo.body !==
        undefined &&
      requestInfo.body !==
        null
        ? {
            body:
              requestInfo.body,
          }
        : {}
    ),

    ...(
      requestInfo.parameter
        ? {
            parameter:
              requestInfo.parameter,
          }
        : {}
    ),
  };
}

async function executeAttack(
  attack
) {
  const startedAt =
    new Date()
      .toISOString();

  try {
    let baselineResponse =
      null;

    if (
      attack.baselineRequest
    ) {
      baselineResponse =
        await executeRequest(
          attack.baselineRequest
        );
    }

    const response =
      await executeRequest(
        attack.request
      );

    const finishedAt =
      new Date()
        .toISOString();

    return {
      id:
        attack.id,

      findingId:
        attack.findingId,

      source:
        attack.source,

      tool:
        attack.validator,

      attackType:
        attack.attackType,

      attackFamily:
        attack.attackFamily,

      attackName:
        attack.attackName,

      activeProbe:
        attack.activeProbe,

      target:
        targetUrl,

      status:
        'executed',

      payload:
        attack.payload,

      selectedRoute:
        attack.selectedRoute,

      request:
        requestEvidence(
          attack.request
        ),

      baselineRequest:
        attack.baselineRequest
          ? requestEvidence(
              attack.baselineRequest
            )
          : null,

      baselineResponse,

      response,

      startedAt,

      finishedAt,
    };
  } catch (
    error
  ) {
    const finishedAt =
      new Date()
        .toISOString();

    return {
      id:
        attack.id,

      findingId:
        attack.findingId,

      source:
        attack.source,

      tool:
        attack.validator,

      attackType:
        attack.attackType,

      attackFamily:
        attack.attackFamily,

      attackName:
        attack.attackName,

      activeProbe:
        attack.activeProbe,

      target:
        targetUrl,

      status:
        'failed',

      payload:
        attack.payload,

      selectedRoute:
        attack.selectedRoute,

      request:
        requestEvidence(
          attack.request
        ),

      baselineRequest:
        attack.baselineRequest
          ? requestEvidence(
              attack.baselineRequest
            )
          : null,

      startedAt,

      finishedAt,

      error:
        error instanceof Error
          ? error.message
          : String(
              error
            ),
    };
  }
}

async function runWithConcurrency(
  items,
  concurrency
) {
  if (
    !Array.isArray(
      items
    ) ||
    items.length ===
      0
  ) {
    return [];
  }

  const safeConcurrency =
    Math.max(
      1,
      Math.min(
        Number.isInteger(
          concurrency
        )
          ? concurrency
          : 1,
        items.length
      )
    );

  const results =
    new Array(
      items.length
    );

  let nextIndex =
    0;

  async function worker() {
    while (
      true
    ) {
      const index =
        nextIndex;

      nextIndex +=
        1;

      if (
        index >=
        items.length
      ) {
        return;
      }

      results[index] =
        await executeAttack(
          items[index]
        );
    }
  }

  await Promise.all(
    Array.from(
      {
        length:
          safeConcurrency,
      },
      () =>
        worker()
    )
  );

  return results;
}

async function main() {
  const results =
    await runWithConcurrency(
      attacks,
      attackConcurrency
    );

  process.stdout.write(
    '__SENTINEL_ATTACK_RESULT_START__'
  );

  process.stdout.write(
    JSON.stringify(
      results
    )
  );

  process.stdout.write(
    '__SENTINEL_ATTACK_RESULT_END__'
  );
}

main().catch(
  error => {
    console.error(
      error instanceof Error
        ? error.stack ||
          error.message
        : String(
            error
          )
    );

    process.exitCode =
      1;
  }
);
`;
}

async function createAttacker({
  networkName,
  containerName,
  script,
  projectValidation = false,
}) {
  const hostConfig = {
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

    ...(
      projectValidation
        ? {
            ExtraHosts: [
              'host.docker.internal:host-gateway',
            ],
          }
        : {}
    ),

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
  };

  return docker.createContainer({
    Image:
      ATTACK_IMAGE,

    name:
      containerName,

    Cmd: [
      'node',
      '-e',
      script,
    ],

    HostConfig:
      hostConfig,
  });
}

async function executeContainer({
  networkName,
  containerName,
  attacks,
  targetUrl,
  projectValidation,
}) {
  const resolvedTarget =
    projectValidation
      ? getDockerTargetUrl(
          targetUrl
        )
      : targetUrl;

  const attackConcurrency =
    projectValidation
      ? PROJECT_VALIDATION_CONCURRENCY
      : SAFE_SIMULATION_CONCURRENCY;

  const script =
    buildAttackerScript(
      attacks,
      resolvedTarget,
      attackConcurrency
    );

  const container =
    await createAttacker({
      networkName,
      containerName,
      script,
      projectValidation,
    });

  await container.start();

  let timeoutId =
    null;

  const timeout =
    new Promise(
      (
        _,
        reject
      ) => {
        timeoutId =
          setTimeout(
            () => {
              reject(
                new Error(
                  'Attack container timed out.'
                )
              );
            },
            SANDBOX_TIMEOUT
          );
      }
    );

  let result;

  try {
    result =
      await Promise.race([
        container.wait(),
        timeout,
      ]);
  } finally {
    if (
      timeoutId !==
      null
    ) {
      clearTimeout(
        timeoutId
      );
    }
  }

  const rawLogs =
    await container.logs({
      stdout:
        true,

      stderr:
        true,
    });

  const {
    stdout,
    stderr,
  } =
    demuxDockerLogBuffer(
      rawLogs
    );

  const output =
    stdout.trim();

  const errorOutput =
    stderr.trim();

  if (
    result.StatusCode !==
    0
  ) {
    throw new Error(
      `Attack container failed: ${
        errorOutput ||
        output ||
        `exit code ${result.StatusCode}`
      }`
    );
  }

  if (
    errorOutput
  ) {
    console.log(
      '[sandbox] Attack stderr:',
      errorOutput
    );
  }

  const startMarker =
    '__SENTINEL_ATTACK_RESULT_START__';

  const endMarker =
    '__SENTINEL_ATTACK_RESULT_END__';

  const start =
    output.indexOf(
      startMarker
    );

  const end =
    output.indexOf(
      endMarker,
      start +
        startMarker.length
    );

  if (
    start === -1 ||
    end === -1 ||
    end <
      start
  ) {
    throw new Error(
      'Attack container returned invalid result markers.'
    );
  }

  const jsonText =
    output
      .slice(
        start +
          startMarker.length,
        end
      )
      .trim();

  let results;

  try {
    results =
      JSON.parse(
        jsonText
      );
  } catch (
    error
  ) {
    throw new Error(
      `Attack result JSON parsing failed: ${
        error instanceof Error
          ? error.message
          : String(
              error
            )
      }`,
      {
        cause:
          error,
      }
    );
  }

  if (
    !Array.isArray(
      results
    )
  ) {
    throw new Error(
      'Attack container returned an invalid attack result.'
    );
  }

  return {
    container,
    results,
  };
}

function legacyStatus(
  verdict
) {
  if (
    verdict ===
    'confirmed'
  ) {
    return 'success';
  }

  if (
    verdict ===
    'failed'
  ) {
    return 'failed';
  }

  return 'inconclusive';
}

function evidenceEntries(
  attack,
  evaluation
) {
  const evidence = [];

  if (
    attack.request?.url
  ) {
    evidence.push({
      id:
        createId(
          'ev-'
        ),

      type:
        'request',

      timestamp:
        attack.startedAt,

      source:
        attack.tool ||
        'runtime',

      content:
        `${
          attack.request.method ||
          'GET'
        } ${attack.request.url}`,
    });
  }

  if (
    attack.response
  ) {
    evidence.push({
      id:
        createId(
          'ev-'
        ),

      type:
        'response',

      timestamp:
        attack.finishedAt,

      source:
        'project-runtime',

      content:
        attack.response.body ||
        '',
    });
  }

  evidence.push({
    id:
      createId(
        'ev-'
      ),

    type:
      evaluation.verdict ===
      'confirmed'
        ? 'finding'
        : 'log',

    timestamp:
      attack.finishedAt,

    source:
      attack.tool ||
      'runtime-validation',

    content:
      evaluation.rationale,
  });

  return evidence;
}

function evaluateAttack(
  attack,
  projectValidation
) {
  if (
    attack.status ===
    'failed'
  ) {
    const rationale =
      attack.error ||
      'The runtime request failed.';

    return {
      ...attack,

      runtimeVerdict:
        'failed',

      confidence:
        100,

      rationale,

      evidence: [
        {
          id:
            createId(
              'ev-'
            ),

          type:
            'log',

          timestamp:
            attack.finishedAt,

          source:
            attack.tool ||
            'runtime',

          content:
            rationale,
        },
      ],
    };
  }

  const evaluation =
    evaluateRuntimeEvidence(
      attack,
      attack.response,
      {
        simulation:
          !projectValidation,

        baselineResponse:
          attack.baselineResponse,

        route:
          attack.selectedRoute,

        testOrigin:
          attack.attackType ===
          'cors'
            ? TEST_ORIGIN
            : null,
      }
    );

  return {
    ...attack,

    status:
      legacyStatus(
        evaluation.verdict
      ),

    runtimeVerdict:
      evaluation.verdict,

    confidence:
      evaluation.confidence,

    rationale:
      evaluation.rationale,

    evidence:
      evidenceEntries(
        attack,
        evaluation
      ),
  };
}

async function runAttacks({
  networkName,
  containerName,
  findings,
  plans,
  targetUrl,
  projectValidation = false,
}) {
  if (
    !targetUrl
  ) {
    throw new Error(
      'Target URL is required for runtime validation.'
    );
  }

  const safeFindings =
    asArray(
      findings
    );

  const safePlans =
    asArray(
      plans
    );

  let preparation;

  if (
    projectValidation
  ) {
    const routes =
      await discoverProjectRoutes(
        targetUrl
      );

    preparation =
      prepareProject(
        safeFindings,
        safePlans,
        routes
      );
  } else {
    preparation =
      prepareSimulation(
        safeFindings,
        safePlans
      );
  }

  if (
    preparation.prepared.length ===
    0
  ) {
    return {
      container:
        null,

      attacks:
        preparation.skipped,
    };
  }

  const execution =
    await executeContainer({
      networkName,
      containerName,

      attacks:
        preparation.prepared,

      targetUrl,

      projectValidation,
    });

  const evaluated =
    execution.results.map(
      attack =>
        evaluateAttack(
          attack,
          projectValidation
        )
    );

  return {
    container:
      execution.container,

    attacks: [
      ...evaluated,
      ...preparation.skipped,
    ],
  };
}

module.exports = {
  runAttacks,
  createAttacker,
};