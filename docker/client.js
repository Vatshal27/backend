'use strict';
const Docker = require('dockerode');
const http = require('http');
const https = require('https');
const {
  TARGET_IMAGE,
  ATTACK_IMAGE,
  REQUEST_TIMEOUT,
} = require('./config');
const docker = new Docker();
function safeError(error) {
  return error instanceof Error
    ? error.message
    : String(error);
}
function validateProjectTargetUrl(
  targetUrl
) {
  if (
    typeof targetUrl !== 'string' ||
    !targetUrl.trim()
  ) {
    throw new Error(
      'Project validation requires targetUrl.'
    );
  }
  let parsed;
  try {
    parsed =
      new URL(targetUrl);
  } catch {
    throw new Error(
      'Invalid project target URL.'
    );
  }
  if (
    parsed.protocol !== 'http:' &&
    parsed.protocol !== 'https:'
  ) {
    throw new Error(
      'Project validation only supports HTTP and HTTPS.'
    );
  }
  const allowedHosts = [
    'localhost',
    '127.0.0.1',
    '::1',
    '[::1]',
  ];
  if (
    !allowedHosts.includes(
      parsed.hostname.toLowerCase()
    )
  ) {
    throw new Error(
      'Project validation only supports local applications.'
    );
  }
  return parsed;
}
function getDockerTargetUrl(
  targetUrl
) {
  const parsed =
    validateProjectTargetUrl(
      targetUrl
    );
  if (
    [
      'localhost',
      '127.0.0.1',
      '::1',
      '[::1]',
    ].includes(
      parsed.hostname.toLowerCase()
    )
  ) {
    parsed.hostname =
      'host.docker.internal';
  }
  return parsed.toString();
}
function cleanProxyHeaders(
  headers
) {
  const cleaned = {
    ...headers,
  };
  const hopByHop = [
    'connection',
    'proxy-connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
  ];
  for (
    const name of hopByHop
  ) {
    delete cleaned[name];
  }
  return cleaned;
}
async function startProjectProxy(
  targetUrl
) {
  const upstream =
    validateProjectTargetUrl(
      targetUrl
    );
  const transport =
    upstream.protocol === 'https:'
      ? https
      : http;
  const server =
    http.createServer(
      (
        req,
        res
      ) => {
        const headers =
          cleanProxyHeaders(
            req.headers
          );
        headers.host =
          upstream.host;
        delete headers[
          'accept-encoding'
        ];
        const upstreamRequest =
          transport.request(
            {
              protocol:
                upstream.protocol,
              hostname:
                upstream.hostname,
              port:
                upstream.port ||
                (
                  upstream.protocol ===
                  'https:'
                    ? 443
                    : 80
                ),
              method:
                req.method,
              path:
                req.url || '/',
              headers,
              timeout:
                REQUEST_TIMEOUT,
            },
            upstreamResponse => {
              const responseHeaders =
                cleanProxyHeaders(
                  upstreamResponse.headers
                );
              res.writeHead(
                upstreamResponse.statusCode ||
                502,
                responseHeaders
              );
              upstreamResponse.pipe(
                res
              );
            }
          );
        upstreamRequest.on(
          'timeout',
          () => {
            upstreamRequest.destroy(
              new Error(
                'Project proxy upstream request timed out.'
              )
            );
          }
        );
        upstreamRequest.on(
          'error',
          error => {
            if (
              res.headersSent
            ) {
              res.destroy(
                error
              );
              return;
            }
            res.statusCode =
              502;
            res.setHeader(
              'Content-Type',
              'application/json'
            );
            res.end(
              JSON.stringify({
                error:
                  'SentinelAI project proxy could not reach the local runtime.',
                detail:
                  safeError(
                    error
                  ),
              })
            );
          }
        );
        req.on(
          'error',
          error => {
            upstreamRequest.destroy(
              error
            );
          }
        );
        req.pipe(
          upstreamRequest
        );
      }
    );
  server.on(
    'clientError',
    (
      _error,
      socket
    ) => {
      if (
        socket.writable
      ) {
        socket.end(
          'HTTP/1.1 400 Bad Request\r\n\r\n'
        );
      }
    }
  );
  await new Promise(
    (
      resolve,
      reject
    ) => {
      const onError =
        error => {
          server.off(
            'listening',
            onListening
          );
          reject(
            error
          );
        };
      const onListening =
        () => {
          server.off(
            'error',
            onError
          );
          resolve();
        };
      server.once(
        'error',
        onError
      );
      server.once(
        'listening',
        onListening
      );
      server.listen(
        0,
        '0.0.0.0'
      );
    }
  );
  const address =
    server.address();
  if (
    !address ||
    typeof address ===
      'string'
  ) {
    await stopProjectProxy({
      server,
    });
    throw new Error(
      'SentinelAI project proxy did not receive a TCP port.'
    );
  }
  const localUrl =
    `http://127.0.0.1:${address.port}`;
  const dockerUrl =
    getDockerTargetUrl(
      localUrl
    );
  console.log(
    '[sandbox] Project proxy:',
    `${dockerUrl} -> ${upstream.toString()}`
  );
  return {
    server,
    port:
      address.port,
    targetUrl:
      upstream.toString(),
    localUrl,
    dockerUrl,
  };
}
async function stopProjectProxy(
  proxy
) {
  if (
    !proxy ||
    !proxy.server
  ) {
    return;
  }
  const server =
    proxy.server;
  try {
    if (
      typeof server.closeIdleConnections ===
      'function'
    ) {
      server.closeIdleConnections();
    }
    await new Promise(
      resolve => {
        server.close(
          () =>
            resolve()
        );
        setTimeout(
          () => {
            if (
              typeof server.closeAllConnections ===
              'function'
            ) {
              server.closeAllConnections();
            }
            resolve();
          },
          1000
        );
      }
    );
  } catch {
    // Proxy may already be closed.
  }
}
async function checkDocker() {
  try {
    const info =
      await docker.info();
    return {
      ok: true,
      version:
        info.ServerVersion,
    };
  } catch (error) {
    return {
      ok: false,
      reason:
        `Docker is unavailable: ${safeError(error)}`,
    };
  }
}
async function imageExists(
  imageName
) {
  try {
    await docker
      .getImage(imageName)
      .inspect();
    return true;
  } catch {
    return false;
  }
}
async function pullImage(
  imageName
) {
  if (
    await imageExists(
      imageName
    )
  ) {
    return;
  }
  console.log(
    `[sandbox] Pulling ${imageName}...`
  );
  const stream =
    await docker.pull(
      imageName
    );
  await new Promise(
    (
      resolve,
      reject
    ) => {
      docker.modem.followProgress(
        stream,
        error => {
          if (
            error
          ) {
            reject(
              error
            );
            return;
          }
          resolve();
        }
      );
    }
  );
}
async function ensureImages(
  options = {}
) {
  const {
    includeTarget = true,
  } = options;
  if (
    includeTarget
  ) {
    await pullImage(
      TARGET_IMAGE
    );
  }
  await pullImage(
    ATTACK_IMAGE
  );
}
async function createNetwork(
  name,
  options = {}
) {
  const {
    hostAccess = false,
  } = options;
  const network =
    await docker.createNetwork({
      Name:
        name,
      Driver:
        'bridge',
      Internal:
        !hostAccess,
      CheckDuplicate:
        true,
      Options: {
        'com.docker.network.bridge.enable_icc':
          'true',
      },
    });
  return {
    dockerNetwork:
      network,
    id:
      network.id,
    name,
  };
}
async function removeNetwork(
  network
) {
  if (
    !network
  ) {
    return;
  }
  try {
    const dockerNetwork =
      network.dockerNetwork ||
      network;
    await dockerNetwork.remove();
  } catch {
    // Network may already be gone.
  }
}
async function removeContainer(
  container
) {
  if (
    !container
  ) {
    return;
  }
  try {
    await container.remove({
      force:
        true,
    });
  } catch {
    // Container may already be gone.
  }
}
async function getContainerLogs(
  container
) {
  const buffer =
    await container.logs({
      stdout:
        true,
      stderr:
        true,
    });
  return buffer
    .toString(
      'utf8'
    )
    .replace(
      /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,
      ''
    );
}
module.exports = {
  docker,
  checkDocker,
  ensureImages,
  createNetwork,
  removeNetwork,
  removeContainer,
  getContainerLogs,
  getDockerTargetUrl,
  startProjectProxy,
  stopProjectProxy,
};