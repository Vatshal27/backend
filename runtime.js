'use strict';

const fs = require('fs/promises');
const http = require('http');
const https = require('https');

const COMMON_DEV_PORTS = [
  3000,
  3001,
  4000,
  4173,
  4200,
  5000,
  5173,
  5174,
  5175,
  8000,
  8001,
  8080,
  8081,
  8082,
  8888,
];

const IGNORED_PORTS = new Set([
  631,
  11434,
  27017,
]);

const SENTINEL_BACKEND_PORT = 3000;

function decodePort(hex) {
  return parseInt(hex, 16);
}

async function readListeningPorts() {
  const files = [
    '/proc/net/tcp',
    '/proc/net/tcp6',
  ];

  const ports = new Set();

  for (const file of files) {
    try {
      const content = await fs.readFile(
        file,
        'utf8'
      );

      const lines =
        content.split('\n').slice(1);

      for (const line of lines) {
        const columns =
          line.trim().split(/\s+/);

        if (columns.length < 4) {
          continue;
        }

        const localAddress = columns[1];
        const state = columns[3];

        if (state !== '0A') {
          continue;
        }

        const separator =
          localAddress.lastIndexOf(':');

        if (separator === -1) {
          continue;
        }

        const portHex =
          localAddress.slice(
            separator + 1
          );

        const port =
          decodePort(portHex);

        if (
          port > 0 &&
          port < 65536
        ) {
          ports.add(port);
        }
      }
    } catch {
      // Ignore unavailable proc files.
    }
  }

  return ports;
}

function requestRuntime(
  protocol,
  port,
  timeoutMs = 1500
) {
  return new Promise(resolve => {
    const client =
      protocol === 'https:'
        ? https
        : http;

    const request = client.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/',
        method: 'GET',
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers: {
          'User-Agent':
            'SentinelAI-Runtime-Discovery/1.0',
        },
      },
      response => {
        let body = '';

        response.on(
          'data',
          chunk => {
            if (body.length < 8192) {
              body += chunk.toString();
            }
          }
        );

        response.on(
          'end',
          () => {
            resolve({
              reachable: true,
              protocol,
              port,
              statusCode:
                response.statusCode,
              headers:
                response.headers,
              body,
            });
          }
        );
      }
    );

    request.on(
      'error',
      () => resolve(null)
    );

    request.on(
      'timeout',
      () => {
        request.destroy();
        resolve(null);
      }
    );

    request.end();
  });
}

function identifyRuntime(result) {
  const headers =
    result.headers || {};

  const body =
    result.body || '';

  const server =
    String(
      headers.server || ''
    ).toLowerCase();

  const poweredBy =
    String(
      headers['x-powered-by'] || ''
    ).toLowerCase();

  const contentType =
    String(
      headers['content-type'] || ''
    ).toLowerCase();

  const combined = [
    server,
    poweredBy,
    contentType,
    body,
  ].join(' ');

  // Flask / Werkzeug
  if (
    /werkzeug/.test(combined) ||
    /flask/.test(combined)
  ) {
    return 'Flask';
  }

  // Django / Python WSGI
  if (
    /django/.test(combined) ||
    /wsgiref/.test(combined)
  ) {
    return 'Django';
  }

  // Express
  if (
    /express/.test(combined) ||
    poweredBy.includes('express')
  ) {
    return 'Express';
  }

  // Vite
  if (
    /vite/.test(combined) ||
    /@vite/.test(combined)
  ) {
    return 'Vite';
  }

  // Next.js
  if (
    /next\.js/.test(combined) ||
    /__next/.test(combined)
  ) {
    return 'Next.js';
  }

  // Angular
  if (/angular/.test(combined)) {
    return 'Angular';
  }

  // Vue
  if (/vue/.test(combined)) {
    return 'Vue';
  }

  // React
  if (/react/.test(combined)) {
    return 'React';
  }

  // Spring
  if (/spring/.test(combined)) {
    return 'Spring';
  }

  // Infrastructure services
  if (/cups/.test(combined)) {
    return null;
  }

  if (/ollama/.test(combined)) {
    return null;
  }

  if (
    /mongodb/.test(combined) ||
    /mongo/.test(combined)
  ) {
    return null;
  }

  return 'HTTP Application';
}

function shouldIgnorePort(port) {
  if (
    IGNORED_PORTS.has(port)
  ) {
    return true;
  }

  if (
    port === SENTINEL_BACKEND_PORT
  ) {
    return true;
  }

  // Ignore ephemeral/random services.
  if (port > 10000) {
    return true;
  }

  return false;
}

async function probePort(port) {
  if (shouldIgnorePort(port)) {
    return null;
  }

  const httpResult =
    await requestRuntime(
      'http:',
      port
    );

  if (httpResult) {
    const runtime =
      identifyRuntime(httpResult);

    if (!runtime) {
      return null;
    }

    return {
      ...httpResult,
      url:
        `http://localhost:${port}`,
      runtime,
    };
  }

  const httpsResult =
    await requestRuntime(
      'https:',
      port
    );

  if (httpsResult) {
    const runtime =
      identifyRuntime(httpsResult);

    if (!runtime) {
      return null;
    }

    return {
      ...httpsResult,
      url:
        `https://localhost:${port}`,
      runtime,
    };
  }

  return null;
}

async function discoverRuntimes() {
  const listeningPorts =
    await readListeningPorts();

  for (
    const port of COMMON_DEV_PORTS
  ) {
    listeningPorts.add(port);
  }

  const sortedPorts =
    [...listeningPorts].sort(
      (a, b) => a - b
    );

  const runtimes = [];

  for (
    const port of sortedPorts
  ) {
    const runtime =
      await probePort(port);

    if (runtime) {
      runtimes.push(runtime);
    }
  }

  const frameworkOrder = [
    'Vite',
    'Next.js',
    'React',
    'Angular',
    'Vue',
    'Flask',
    'Django',
    'Express',
    'Spring',
    'HTTP Application',
  ];

  runtimes.sort(
    (a, b) => {
      const aIndex =
        frameworkOrder.indexOf(
          a.runtime
        );

      const bIndex =
        frameworkOrder.indexOf(
          b.runtime
        );

      return (
        (aIndex === -1
          ? 999
          : aIndex) -
        (bIndex === -1
          ? 999
          : bIndex)
      );
    }
  );

  console.log('');
  console.log(
    '────────────────────────────────────────'
  );
  console.log(
    ' SentinelAI Runtime Discovery'
  );
  console.log(
    '────────────────────────────────────────'
  );

  if (!runtimes.length) {
    console.log(
      ' ✗ No application runtime detected.'
    );
  } else {
    for (const runtime of runtimes) {
      console.log(
        ` ✓ ${runtime.runtime.padEnd(18)} ` +
        `${runtime.url}`
      );
    }
  }

  console.log(
    '────────────────────────────────────────'
  );
  console.log('');

  return runtimes;
}

async function checkRuntime(targetUrl) {
  let parsed;

  try {
    parsed =
      new URL(targetUrl);
  } catch {
    throw new Error(
      'Invalid runtime URL.'
    );
  }

  const hostname =
    parsed.hostname.toLowerCase();

  const allowedHosts = [
    'localhost',
    '127.0.0.1',
    '::1',
    '[::1]',
  ];

  if (
    !allowedHosts.includes(
      hostname
    )
  ) {
    throw new Error(
      'Runtime checks are restricted to localhost.'
    );
  }

  if (
    parsed.protocol !== 'http:' &&
    parsed.protocol !== 'https:'
  ) {
    throw new Error(
      'Only HTTP and HTTPS runtimes are supported.'
    );
  }

  const port =
    parsed.port ||
    (
      parsed.protocol === 'https:'
        ? 443
        : 80
    );

  const result =
    await requestRuntime(
      parsed.protocol,
      Number(port)
    );

  if (!result) {
    return {
      reachable: false,
      url: targetUrl,
      port: Number(port),
    };
  }

  const runtime =
    identifyRuntime(result);

  console.log('');
  console.log(
    'SentinelAI Runtime Check'
  );
  console.log(
    '────────────────────────────────────────'
  );
  console.log(
    ` ✓ Runtime    ${runtime || 'HTTP Application'}`
  );
  console.log(
    ` ✓ Target     ${targetUrl}`
  );
  console.log(
    ` ✓ Port       ${port}`
  );
  console.log(
    ` ✓ Status     ${result.statusCode}`
  );
  console.log(
    '────────────────────────────────────────'
  );
  console.log('');

  return {
    reachable: true,
    url: targetUrl,
    port: Number(port),
    statusCode:
      result.statusCode,
    runtime:
      runtime || 'HTTP Application',
  };
}

module.exports = {
  discoverRuntimes,
  checkRuntime,
};