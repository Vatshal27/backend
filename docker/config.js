'use strict';

const TARGET_IMAGE =
  process.env.SENTINEL_TARGET_IMAGE ||
  'node:20-alpine';

const ATTACK_IMAGE =
  process.env.SENTINEL_ATTACK_IMAGE ||
  'node:20-alpine';

const TARGET_PORT =
  Number(
    process.env.SENTINEL_TARGET_PORT ||
    8080
  );

const SANDBOX_LIMITS = {
  memory:
    Number(
      process.env.SENTINEL_MEMORY ||
      256
    ) *
    1024 *
    1024,

  nanoCpus:
    Number(
      process.env.SENTINEL_CPU ||
      0.5
    ) *
    1_000_000_000,

  pidsLimit:
    Number(
      process.env.SENTINEL_PIDS ||
      64
    )
};

const SANDBOX_TIMEOUT =
  Number(
    process.env.SENTINEL_TIMEOUT ||
    180000
  );

const TARGET_HEALTH_TIMEOUT =
  Number(
    process.env.SENTINEL_HEALTH_TIMEOUT ||
    15000
  );

const REQUEST_TIMEOUT =
  Number(
    process.env.SENTINEL_REQUEST_TIMEOUT ||
    10000
  );

const LOCAL_HOSTS = [
  'localhost',
  '127.0.0.1',
  '::1',
  '[::1]',
  'host.docker.internal'
];

const TARGET_BIND_HOST =
  process.env.SENTINEL_TARGET_BIND_HOST ||
  '127.0.0.1';

const TARGET_HOST =
  process.env.SENTINEL_TARGET_HOST ||
  'target';

const TARGET_INTERNAL_URL =
  `http://${TARGET_HOST}:${TARGET_PORT}`;

module.exports = {
  TARGET_IMAGE,
  ATTACK_IMAGE,
  TARGET_PORT,
  TARGET_BIND_HOST,
  TARGET_HOST,
  TARGET_INTERNAL_URL,
  LOCAL_HOSTS,
  SANDBOX_LIMITS,
  SANDBOX_TIMEOUT,
  TARGET_HEALTH_TIMEOUT,
  REQUEST_TIMEOUT
};