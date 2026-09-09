'use strict';

const TARGET_IMAGE = 'node:20-alpine';
const ATTACK_IMAGE = 'node:20-alpine';

const SANDBOX_LIMITS = {
  memory: 256 * 1024 * 1024,
  nanoCpus: 500_000_000,
  pidsLimit: 64,
};

const SANDBOX_TIMEOUT = 180_000;

module.exports = {
  TARGET_IMAGE,
  ATTACK_IMAGE,
  SANDBOX_LIMITS,
  SANDBOX_TIMEOUT,
};