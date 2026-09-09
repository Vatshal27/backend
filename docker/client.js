'use strict';

const Docker = require('dockerode');

const {
  TARGET_IMAGE,
  ATTACK_IMAGE,
} = require('./config');

const docker = new Docker();

function safeError(error) {
  return error instanceof Error
    ? error.message
    : String(error);
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
    (resolve, reject) => {
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
    }
  );
}

async function ensureImages(
  options = {}
) {
  const {
    includeTarget = true,
  } = options;

  if (includeTarget) {
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

  return docker.createNetwork({
    Name: name,

    Driver: 'bridge',

    Internal:
      !hostAccess,

    CheckDuplicate: true,

    Options: {
      'com.docker.network.bridge.enable_icc':
        'false',
    },
  });
}

async function removeNetwork(
  network
) {
  if (!network) {
    return;
  }

  try {
    await network.remove();
  } catch {
    // Network may already be gone.
  }
}

async function removeContainer(
  container
) {
  if (!container) {
    return;
  }

  try {
    await container.remove({
      force: true,
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

module.exports = {
  docker,
  checkDocker,
  ensureImages,
  createNetwork,
  removeNetwork,
  removeContainer,
  getContainerLogs,
};