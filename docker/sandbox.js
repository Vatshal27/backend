'use strict';

const crypto = require('crypto');

const {
  checkDocker,
  ensureImages,
  createNetwork,
  removeNetwork,
  removeContainer,
} = require('./client');

const {
  generateTargetApplication,
  createTarget,
  waitForTarget,
  buildTargetInfo,
} = require('./target');

const {
  createAttackPlan,
  createCategories,
} = require('./planner');

const {
  runAttacks,
} = require('./runner');

const {
  normalizeEvidence,
} = require('./evidence');

const {
  validateAttacks,
} = require('./validator');

const {
  buildReport,
} = require('./report');

const {
  SANDBOX_TIMEOUT,
} = require('./config');

const activeSandboxes = new Map();

function createId(prefix = '') {
  return (
    prefix +
    crypto.randomBytes(6).toString('hex')
  );
}

function normalizeTargetUrl(targetUrl) {
  if (!targetUrl) {
    throw new Error(
      'No project runtime URL was provided.'
    );
  }

  let parsed;

  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new Error(
      `Invalid project runtime URL: ${targetUrl}`
    );
  }

  if (
    !['http:', 'https:'].includes(
      parsed.protocol
    )
  ) {
    throw new Error(
      'Only HTTP and HTTPS project runtimes are supported.'
    );
  }

  const hostname =
    parsed.hostname.toLowerCase();

  const allowedHosts = [
    'localhost',
    '127.0.0.1',
    '::1',
    '[::1]',
    'host.docker.internal',
  ];

  if (
    !allowedHosts.includes(hostname)
  ) {
    throw new Error(
      'Project validation is restricted to a local runtime.'
    );
  }

  return parsed.toString().replace(
    /\/$/,
    ''
  );
}

function createEvent(
  events,
  stage,
  status,
  description,
  tool,
  findingId
) {
  events.push({
    id: createId('evt-'),
    step: events.length + 1,
    timestamp:
      new Date().toISOString(),
    stage,
    ...(tool ? { tool } : {}),
    status,
    description,
    ...(findingId
      ? { findingId }
      : {}),
  });
}

async function runSandbox(options = {}) {
  const {
    findings = [],
    mode = 'simulation',
    targetUrl,
  } = options;

  if (!Array.isArray(findings)) {
    throw new Error(
      'Sandbox findings must be an array.'
    );
  }

  if (
    mode !== 'simulation' &&
    mode !== 'project-validation'
  ) {
    throw new Error(
      `Unsupported sandbox mode: ${mode}`
    );
  }

  const sandboxId =
    createId('sandbox-');

  const startedAt =
    new Date().toISOString();

  const events = [];
  const containers = {
    target: null,
    attacker: null,
    scanner: null,
  };

  let network = null;
  let target = null;


  const runtimeTarget =
    mode === 'project-validation'
      ? normalizeTargetUrl(
          targetUrl
        )
      : null;

  try {
    createEvent(
      events,
      'initialization',
      'started',
      mode ===
        'project-validation'
        ? 'Initializing controlled validation against the local project runtime.'
        : 'Initializing isolated simulation environment.'
    );

    const dockerStatus =
      await checkDocker();

    if (!dockerStatus.ok) {
      throw new Error(
        dockerStatus.reason ||
          'Docker is unavailable.'
      );
    }

    createEvent(
      events,
      'initialization',
      'success',
      `Docker ${dockerStatus.version} is available.`
    );

    await ensureImages({
    includeTarget:
        mode === 'simulation',
    });

    createEvent(
      events,
      'initialization',
      'success',
      'Required sandbox images are available.'
    );

    network =
    await createNetwork(
        `sentinelai-${sandboxId}`,
        {
        hostAccess:
            mode === 'project-validation',
        }
    );

    createEvent(
      events,
      'network',
      'success',
      'Isolated validator network created.'
    );

    const categories =
      createCategories(
        findings
      );

    const plans =
      createAttackPlan(
        findings,
        mode ===
          'project-validation'
          ? runtimeTarget
          : undefined
      );

    createEvent(
      events,
      'attack',
      'success',
      `${plans.length} runtime validation plan(s) created.`
    );

    if (
      mode === 'simulation'
    ) {
      const targetCode =
        generateTargetApplication(
          findings,
          categories
        );

      target =
        await createTarget(
          network.name,
          `sentinelai-target-${sandboxId}`,
          targetCode
        );

      containers.target =
        target;

      createEvent(
        events,
        'target',
        'running',
        'Synthetic vulnerable target started.'
      );

      const ready =
        await waitForTarget(
          target
        );

      if (!ready) {
        throw new Error(
          'Synthetic target failed its health check.'
        );
      }

      createEvent(
        events,
        'target',
        'success',
        'Synthetic target is healthy and ready for validation.'
      );
    } else {
      createEvent(
        events,
        'target',
        'success',
        `Using local project runtime at ${runtimeTarget}.`
      );
    }

const attackExecution =
  await Promise.race([
    runAttacks({
      networkName:
        network.name,
      containerName:
        `sentinelai-attacker-${sandboxId}`,
      findings,
      plans,
      targetUrl:
        mode ===
        'project-validation'
          ? runtimeTarget
          : 'http://target:8080',
    }),

    new Promise(
      (_, reject) =>
        setTimeout(
          () =>
            reject(
              new Error(
                'Sandbox validation timed out.'
              )
            ),
          SANDBOX_TIMEOUT
        )
    ),
  ]);

    const attacks =
    normalizeEvidence(
        attackExecution.attacks
    );

    containers.attacker =
      attackExecution.container;

    createEvent(
      events,
      'attack',
      'success',
      `${attacks.length} validation attack(s) completed.`
    );

    const validations =
      validateAttacks(
        findings,
        attacks
      );

    createEvent(
      events,
      'evidence',
      'success',
      'Validation evidence normalized and verdicts generated.'
    );

    const finishedAt =
      new Date().toISOString();

    const report =
      buildReport({
        sandboxId,
        mode,
        startedAt,
        finishedAt,
        target:
          mode ===
          'project-validation'
            ? {
                name:
                  'Local Project Runtime',
                url:
                  runtimeTarget,
                containerId: '',
                status:
                  'running',
              }
            : buildTargetInfo(
                target,
                `sentinelai-target-${sandboxId}`
              ),
        containers,
        events,
        attacks,
        validations,
      });

    activeSandboxes.set(
      sandboxId,
      {
        sandboxId,
        network,
        target,
        attacker:
          containers.attacker,
      }
    );

    return report;
  } catch (error) {
    createEvent(
      events,
      'initialization',
      'failed',
      error instanceof Error
        ? error.message
        : String(error)
    );

    throw error;
  } finally {
    if (containers.attacker) {
      await removeContainer(
        containers.attacker
      );
    }

    if (containers.target) {
      await removeContainer(
        containers.target
      );
    }

    await removeNetwork(
      network
    );

    activeSandboxes.delete(
      sandboxId
    );
  }
}

async function stopSandbox(
  sandboxId
) {
  const sandbox =
    activeSandboxes.get(
      sandboxId
    );

  if (!sandbox) {
    return {
      stopped: false,
      reason:
        'Sandbox is no longer active.',
    };
  }

  await removeContainer(
    sandbox.attacker
  );

  await removeContainer(
    sandbox.target
  );

  await removeNetwork(
    sandbox.network
  );

  activeSandboxes.delete(
    sandboxId
  );

  return {
    stopped: true,
    sandboxId,
  };
}

module.exports = {
  checkDocker,
  runSandbox,
  stopSandbox,
};