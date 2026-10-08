'use strict';
const crypto = require('crypto');
const {
  checkDocker,
  ensureImages,
  createNetwork,
  removeNetwork,
  removeContainer,
  startProjectProxy,
  stopProjectProxy,
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
  writeReportFiles,
} = require('./report-writer');
const {
  SANDBOX_TIMEOUT,
  LOCAL_HOSTS,
} = require('./config');

const activeSandboxes =
  new Map();

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

function normalizeTargetUrl(
  targetUrl
) {
  if (
    typeof targetUrl !==
      'string' ||
    !targetUrl.trim()
  ) {
    throw new Error(
      'No project runtime URL was provided.'
    );
  }

  let parsed;

  try {
    parsed =
      new URL(
        targetUrl
      );
  } catch {
    throw new Error(
      `Invalid project runtime URL: ${targetUrl}`
    );
  }

  if (
    ![
      'http:',
      'https:',
    ].includes(
      parsed.protocol
    )
  ) {
    throw new Error(
      'Only HTTP and HTTPS project runtimes are supported.'
    );
  }

  const hostname =
    parsed.hostname
      .toLowerCase();

  if (
    !LOCAL_HOSTS.includes(
      hostname
    )
  ) {
    throw new Error(
      'Project validation is restricted to a local runtime.'
    );
  }

  return parsed
    .toString()
    .replace(
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
    id:
      createId(
        'evt-'
      ),
    step:
      events.length + 1,
    timestamp:
      new Date().toISOString(),
    stage,
    ...(tool
      ? { tool }
      : {}),
    status,
    description,
    ...(findingId
      ? { findingId }
      : {}),
  });
}

function restoreProjectTargetUrls(
  attacks,
  projectProxy,
  runtimeTarget
) {
  if (
    !Array.isArray(
      attacks
    ) ||
    !projectProxy ||
    !runtimeTarget
  ) {
    return attacks;
  }

  const runtimeOrigin =
    new URL(
      runtimeTarget
    ).origin;

  const proxyOrigins =
    [
      projectProxy.localUrl,
      projectProxy.dockerUrl,
    ]
      .filter(Boolean)
      .map(
        value =>
          new URL(
            value
          ).origin
      );

  function restore(
    value
  ) {
    if (
      typeof value !==
      'string'
    ) {
      return value;
    }

    let restored =
      value;

    for (
      const proxyOrigin of
        proxyOrigins
    ) {
      restored =
        restored
          .split(
            proxyOrigin
          )
          .join(
            runtimeOrigin
          );
    }

    return restored;
  }

  return attacks.map(
    attack => ({
      ...attack,
      target:
        restore(
          attack.target
        ),
      request:
        attack.request
          ? {
              ...attack.request,
              url:
                restore(
                  attack.request.url
                ),
            }
          : attack.request,
      evidence:
        Array.isArray(
          attack.evidence
        )
          ? attack.evidence.map(
              item => ({
                ...item,
                content:
                  restore(
                    item.content
                  ),
              })
            )
          : attack.evidence,
    })
  );
}

async function runSandbox(
  options = {}
) {
  const {
    findings = [],
    mode = 'simulation',
    targetUrl,
  } = options;

  if (
    !Array.isArray(
      findings
    )
  ) {
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
    createId(
      'sandbox-'
    );

  const startedAt =
    new Date().toISOString();

  const events = [];

  const containers = {
    target:
      null,
    attacker:
      null,
    scanner:
      null,
  };

  let network =
    null;

  let targetDetails =
    null;

  let projectProxy =
    null;

  const runtimeTarget =
    mode ===
      'project-validation'
      ? normalizeTargetUrl(
          targetUrl
        )
      : null;

  const sandboxState = {
    sandboxId,
    network:
      null,
    containers,
    proxy:
      null,
  };

  activeSandboxes.set(
    sandboxId,
    sandboxState
  );

  try {
    createEvent(
      events,
      'initialization',
      'started',
      mode ===
        'project-validation'
        ? 'Initializing controlled validation against the local project runtime.'
        : 'Initializing isolated Safe Simulation environment.'
    );

    const dockerStatus =
      await checkDocker();

    if (
      !dockerStatus.ok
    ) {
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
        mode ===
        'simulation',
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
            mode ===
            'project-validation',
        }
      );

    if (
      !network ||
      !network.id ||
      !network.name ||
      !network.dockerNetwork
    ) {
      throw new Error(
        'Docker network was not created correctly.'
      );
    }

    sandboxState.network =
      network.dockerNetwork;

    console.log(
      '[sandbox] Docker network:',
      network.id,
      network.name
    );

    createEvent(
      events,
      'network',
      'success',
      mode ===
        'project-validation'
        ? 'Controlled bridge network created with local host access.'
        : 'Isolated internal Docker network created for Safe Simulation.'
    );

    let attackTargetUrl;

    if (
      mode ===
      'simulation'
    ) {
      const categories =
        createCategories(
          findings
        );

      const targetCode =
        generateTargetApplication(
          findings,
          categories
        );

      const targetName =
        `sentinelai-target-${sandboxId}`;

      targetDetails =
        await createTarget(
          network.id,
          network.name,
          targetName,
          targetCode
        );

      if (
        !targetDetails ||
        !targetDetails.container ||
        !targetDetails.internalUrl
      ) {
        throw new Error(
          'Safe Simulation target was not created correctly.'
        );
      }

      containers.target =
        targetDetails.container;

      createEvent(
        events,
        'target',
        'running',
        `Synthetic Safe Simulation target started at ${targetDetails.internalUrl}.`
      );

      const ready =
        await waitForTarget(
          targetDetails.container
        );

      if (
        !ready
      ) {
        throw new Error(
          'Safe Simulation target failed its health check.'
        );
      }

      createEvent(
        events,
        'target',
        'success',
        `Synthetic Safe Simulation target is healthy inside the isolated sandbox at ${targetDetails.internalUrl}.`
      );

      attackTargetUrl =
        targetDetails.internalUrl;
    } else {
      projectProxy =
        await startProjectProxy(
          runtimeTarget
        );

      sandboxState.proxy =
        projectProxy;

      attackTargetUrl =
        projectProxy.localUrl;

      console.log(
        '[sandbox] Original project target:',
        runtimeTarget
      );

      console.log(
        '[sandbox] Proxy target:',
        projectProxy.dockerUrl
      );

      createEvent(
        events,
        'target',
        'success',
        `Local project runtime ${runtimeTarget} is available through the temporary SentinelAI validation proxy.`
      );
    }

    if (
      !attackTargetUrl
    ) {
      throw new Error(
        'No runtime target URL was resolved.'
      );
    }

    console.log(
      '[sandbox] Mode:',
      mode
    );

    console.log(
      '[sandbox] Attack target:',
      attackTargetUrl
    );

    const plans =
      createAttackPlan(
        findings,
        attackTargetUrl
      );

    if (
      !Array.isArray(
        plans
      )
    ) {
      throw new Error(
        'Runtime planner returned an invalid plan set.'
      );
    }

    createEvent(
      events,
      'attack',
      'success',
      `${plans.length} runtime validation plan(s) created.`
    );

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
            attackTargetUrl,
          projectValidation:
            mode ===
            'project-validation',
        }),

        new Promise(
          (
            _,
            reject
          ) =>
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

    if (
      !attackExecution ||
      !Array.isArray(
        attackExecution.attacks
      )
    ) {
      throw new Error(
        'Runtime attacker returned an invalid result.'
      );
    }

    containers.attacker =
      attackExecution.container ||
      null;

    let attacks =
      normalizeEvidence(
        attackExecution.attacks
      );

    if (
      mode ===
      'project-validation'
    ) {
      attacks =
        restoreProjectTargetUrls(
          attacks,
          projectProxy,
          runtimeTarget
        );
    }

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

    let reportTarget;

    if (
      mode ===
      'project-validation'
    ) {
      reportTarget = {
        name:
          'Local Project Runtime',
        url:
          runtimeTarget,
        containerId:
          '',
        status:
          'running',
        internalUrl:
          null,
        browserUrl:
          runtimeTarget,
        healthUrl:
          runtimeTarget,
        isolated:
          false,
      };
    } else {
      reportTarget =
        buildTargetInfo(
          targetDetails,
          `sentinelai-target-${sandboxId}`
        );
    }

    const report =
      buildReport({
        sandboxId,
        mode,
        startedAt,
        finishedAt,
        target:
          reportTarget,
        containers,
        events,
        attacks,
        validations,
        findings,
      });

    const reportFiles =
      await writeReportFiles(
        report
      );

    report.reportFiles =
      reportFiles;

    return report;
  } catch (error) {
    createEvent(
      events,
      'sandbox',
      'failed',
      error instanceof Error
        ? error.message
        : String(
            error
          )
    );

    throw error;
  } finally {
    await Promise.allSettled([
      removeContainer(
        containers.attacker
      ),
      removeContainer(
        containers.target
      ),
    ]);

    await stopProjectProxy(
      projectProxy
    );

    if (
      network
    ) {
      await removeNetwork(
        network.dockerNetwork
      );
    }

    activeSandboxes.delete(
      sandboxId
    );
  }
}

async function stopSandbox(
  sandboxId
) {
  const states =
    sandboxId
      ? [
          activeSandboxes.get(
            sandboxId
          ),
        ].filter(
          Boolean
        )
      : Array.from(
          activeSandboxes.values()
        );

  if (
    !states.length
  ) {
    return {
      stopped:
        0,
      ...(sandboxId
        ? {
            sandboxId,
          }
        : {}),
    };
  }

  await Promise.allSettled(
    states.map(
      async state => {
        await Promise.allSettled([
          removeContainer(
            state.containers
              ?.attacker
          ),
          removeContainer(
            state.containers
              ?.target
          ),
        ]);

        await stopProjectProxy(
          state.proxy
        );

        await removeNetwork(
          state.network
        );
      }
    )
  );

  for (
    const state of states
  ) {
    activeSandboxes.delete(
      state.sandboxId
    );
  }

  return {
    stopped:
      states.length,
    ...(sandboxId
      ? {
          sandboxId,
        }
      : {}),
  };
}

module.exports = {
  checkDocker,
  runSandbox,
  stopSandbox,
};