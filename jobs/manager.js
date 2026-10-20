'use strict';
const { randomUUID } = require('node:crypto');

function createJobManager({ maxConcurrent = 1, maxJobs = 30, maxEvents = 200,
  timeoutMs = 300000, retentionMs = 3600000,
  sanitize = value => require('../security/redact').redact(value) } = {}) {
  const jobs = new Map();
  const queue = [];
  const listeners = new Map();
  let active = 0;
  let closed = false;
  const terminal = job => ['completed', 'failed', 'cancelled'].includes(job.status);
  function snapshot(job) {
    if (!job) return null;
    const { task, controller, promise, ...publicJob } = job;
    return structuredClone(publicJob);
  }
  function emit(job, event) {
    job.updatedAt = new Date().toISOString();
    const clean = sanitize(event);
    job.events.push({ stage: String(clean.stage || 'job'), status: String(clean.status || 'running'),
      description: String(clean.description || '').slice(0, 2000),
      ...(typeof clean.networkId === 'string' ? { networkId: clean.networkId } : {}),
      ...(typeof clean.containerId === 'string' ? { containerId: clean.containerId } : {}),
      ...(typeof clean.runId === 'string' ? { runId: clean.runId } : {}),
      sequence: ++job.lastSequence, timestamp: job.updatedAt });
    if (job.events.length > maxEvents) job.events.shift();
    for (const listener of listeners.get(job.id) || []) {
      try { listener(snapshot(job)); } catch { /* A disconnected subscriber cannot break a job. */ }
    }
  }
  function prune() {
    const cutoff = Date.now() - retentionMs;
    for (const [id, job] of jobs) {
      if (terminal(job) && Date.parse(job.updatedAt) < cutoff) {
        jobs.delete(id);
        listeners.delete(id);
      }
    }
  }
  function pump() {
    if (closed) return;
    while (active < maxConcurrent && queue.length) {
      const job = queue.shift();
      if (terminal(job)) continue;
      active++;
      job.status = 'running';
      emit(job, { stage: 'job', status: 'running', description: 'Execution started.' });
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        job.cancelRequested = true;
        job.controller.abort(new Error('Job execution timed out.'));
        emit(job, { stage: 'job', status: 'running', description: 'Timeout reached; stopping and cleaning up.' });
      }, timeoutMs);
      timer.unref();
      job.promise = (async () => {
        try {
          const result = await job.task({ signal: job.controller.signal, emit: event => emit(job, event),
            checkpoint: value => {
              if (terminal(job)) return null;
              job.result = sanitize(value);
              job.updatedAt = new Date().toISOString();
              emit(job, { stage: 'result-checkpoint', status: 'running', description: 'Partial analysis checkpoint updated.' });
              return snapshot(job);
            } });
          if (job.controller.signal.aborted) throw job.controller.signal.reason;
          job.result = sanitize(result);
          job.status = 'completed';
        } catch (error) {
          job.status = timedOut ? 'failed' : job.controller.signal.aborted ? 'cancelled' : 'failed';
          job.error = String(sanitize(error?.message || 'Job execution failed.')).slice(0, 2000);
        } finally {
          clearTimeout(timer);
          job.task = null;
          job.controller = null;
          active--;
                emit(job, { stage: 'job', status: job.status,
            description: job.status === 'completed' ? 'Execution completed.' : job.error || 'Execution cancelled.' });
          pump();
        }
      })();
    }
  }
  return {
    submit(kind, task) {
      prune();
      if (closed) throw Object.assign(new Error('Job service is shutting down.'), { statusCode: 503 });
      if (jobs.size >= maxJobs) throw Object.assign(new Error('Job capacity reached; retry after retained jobs expire.'), { statusCode: 429 });
      const job = { id: randomUUID(), kind, status: 'queued', createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(), events: [], lastSequence: 0, cancelRequested: false,
        controller: new AbortController(), task };
      jobs.set(job.id, job);
      queue.push(job);
      emit(job, { stage: 'job', status: 'queued', description: 'Queued for execution.' });
      setImmediate(pump);
      return snapshot(job);
    },
    get(id) { prune(); return snapshot(jobs.get(id)); },
    stats() { return { active, queued: queue.length, retained: jobs.size }; },
    cancel(id) {
      const job = jobs.get(id);
      if (!job) return null;
      if (terminal(job) || job.cancelRequested) return snapshot(job);
      job.cancelRequested = true;
      job.controller.abort(new Error('Cancelled by user.'));
      if (job.status === 'queued') {
        const index = queue.indexOf(job);
        if (index !== -1) queue.splice(index, 1);
        job.status = 'cancelled';
        job.task = null;
        job.controller = null;
      }
      emit(job, { stage: 'job', status: job.status,
        description: job.status === 'cancelled' ? 'Cancelled before execution.' : 'Cancellation requested; waiting for cleanup.' });
      return snapshot(job);
    },
    subscribe(id, listener) {
      if (!jobs.has(id)) return null;
      if (!listeners.has(id)) listeners.set(id, new Set());
      listeners.get(id).add(listener);
      return () => {
        const set = listeners.get(id);
        set?.delete(listener);
        if (!set?.size) listeners.delete(id);
      };
    },
    async close() {
      closed = true;
      for (const id of jobs.keys()) this.cancel(id);
      await Promise.allSettled([...jobs.values()].map(job => job.promise).filter(Boolean));
      listeners.clear();
    },
  };
}
module.exports = { createJobManager };
