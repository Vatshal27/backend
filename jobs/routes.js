'use strict';
const express = require('express');

function validateRequest(body, capabilities) {
  if (!body || body.kind !== 'scan') throw new Error('kind must be scan. Safe Simulation and Project Validation use their dedicated endpoints.');
  const profile = body.profile || 'source';
  if (!capabilities.profiles.some(item => item.id === profile && item.supported !== false)) throw new Error('Unknown or unsupported scan profile.');
  if (!Array.isArray(body.files) || body.files.length > 500) throw new Error('files must be an array of at most 500 entries.');
  if (profile === 'dependencies' || profile === 'comprehensive') {
    const expectedLocks = body.expectedLockfiles;
    if (!Array.isArray(expectedLocks) || expectedLocks.length > 100 || expectedLocks.some(path => typeof path !== 'string' || !/(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(path))) {
      throw new Error('expectedLockfiles must list detected lockfiles for dependency scans.');
    }
    const suppliedLocks = new Set(body.files.map(file => file?.path).filter(path => typeof path === 'string'));
    const missingLocks = expectedLocks.filter(path => !suppliedLocks.has(path));
    if (missingLocks.length) throw new Error('One or more dependency lockfiles were omitted or exceeded collection limits; rescan with a supported complete lockfile.');
  }
  let size = 0;
  const seen = new Set();
  const files = body.files.map(file => {
    if (typeof file?.path !== 'string' || typeof file.content !== 'string') throw new Error('Each file needs a path and string content.');
    const path = file.path;
    const parts = path.replace(/\\/g, '/').split('/');
    const basename = parts.at(-1).toLowerCase();
    const isLockfile = /^(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(basename);
    const isManifest = /^(?:package\.json|requirements[^/]*\.txt|pyproject\.toml|pipfile|cargo\.toml|composer\.json|gemfile|go\.mod|pom\.xml|build\.gradle)$/.test(basename);
    const isInfrastructure = /^(?:dockerfile(?:[.-].*)?|docker-compose.*\.ya?ml|compose\.ya?ml)$/.test(basename) || /\.(?:tf|tfvars|ya?ml)$/.test(basename);
    if ((isLockfile || isManifest) && !['dependencies', 'comprehensive'].includes(profile)) throw new Error('Dependency manifests are not enabled for this profile.');
    if (isInfrastructure && !['infrastructure', 'comprehensive'].includes(profile)) throw new Error('Infrastructure files are not enabled for this profile.');
    const supportedCode = /\.(?:js|mjs|cjs|ts|py|go|php|java|rb|cs|cpp|c|rs|html|css|jsx|tsx|vue|svelte|sql|sh)$/.test(basename);
    if (!supportedCode && !((isLockfile || isManifest) && ['dependencies', 'comprehensive'].includes(profile)) &&
        !(isInfrastructure && ['infrastructure', 'comprehensive'].includes(profile))) throw new Error('File type is not enabled for this profile.');
    if (!path || path.length > 500 || /[\x00-\x1f]/.test(path) || /^(?:[A-Za-z]:|[\\/])/.test(path) ||
      parts.some(part => ['..', '.', '', 'node_modules', '.git'].includes(part)) ||
      parts.some(part => /^(?:\.env(?:\..*)?|id_rsa|id_ed25519|credentials(?:\.json)?)$/i.test(part)) ||
      /\.(?:pem|key|p12|pfx)$/i.test(path)) throw new Error('Unsafe, excluded, or credential file path.');
    const normalized = parts.join('/');
    if (seen.has(normalized)) throw new Error('Duplicate file path.');
    seen.add(normalized);
    const bytes = Buffer.byteLength(file.content);
    if (/\.json$/i.test(path) && (isLockfile || isManifest)) {
      try { JSON.parse(file.content); } catch { throw new Error('Dependency JSON must parse before submission.'); }
    }
    size += bytes;
    if (bytes > 2 * 1024 * 1024 || size > 5 * 1024 * 1024) throw new Error('Source input exceeds scan size limits.');
    return { path: normalized, content: file.content };
  });
  return { kind: 'scan', profile, files, expectedLockfiles: body.expectedLockfiles || [], options: { allowAdvisoryNetwork: body.options?.allowAdvisoryNetwork === true } };
}

function createSecurityRouter({ manager, capabilities, execute }) {
  const router = express.Router();
  // These endpoints can start Docker jobs. Accept only direct loopback extension-host traffic.
  router.use((req, res, next) => {
    const address = req.socket.remoteAddress;
    const hostname = req.hostname?.toLowerCase();
    if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(address) ||
      !['127.0.0.1', 'localhost', '[::1]', '::1'].includes(hostname) ||
      !['127.0.0.1', 'localhost', '[::1]', '::1'].includes(String(req.headers.host || '').replace(/:\d+$/, '').toLowerCase()) ||
      (req.headers.origin && (() => { try { return new URL(req.headers.origin).host !== req.headers.host; } catch { return true; } })()) ||
      (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'none')) {
      return res.status(403).json({ error: 'Security jobs are restricted to the local extension host.' });
    }
    next();
  });
  router.get('/capabilities', (_req, res) => res.json(capabilities()));
  router.post('/jobs', (req, res) => {
    try {
      const request = validateRequest(req.body, capabilities());
      const job = manager.submit(request.kind, context => execute(request, context));
      res.status(202).json({ job });
    } catch (error) {
      res.status(error.statusCode || 400).json({ error: error.message });
    }
  });
  router.get('/jobs/:id', (req, res) => {
    const job = manager.get(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found or expired.' });
    res.json({ job });
  });
  router.delete('/jobs/:id', (req, res) => {
    const job = manager.cancel(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found or expired.' });
    res.json({ job });
  });
  router.get('/jobs/:id/events', (req, res) => {
    const job = manager.get(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found or expired.' });
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.flushHeaders();
    let unsubscribe;
    let heartbeat;
    let closed = false;
    const terminal = value => ['completed', 'failed', 'cancelled'].includes(value.status);
    const send = value => {
      if (res.writableEnded || closed) return;
      const accepted = res.write(`id: ${value.lastSequence}\nevent: snapshot\ndata: ${JSON.stringify({ job: value })}\n\n`);
      if (!accepted) {
        closed = true;
        unsubscribe?.();
        clearInterval(heartbeat);
        res.once('drain', () => {
          if (terminal(value)) res.end();
          else {
            closed = false;
            unsubscribe = manager.subscribe(value.id, send);
            heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 15000);
            heartbeat.unref();
          }
        });
        return;
      }
      if (terminal(value)) {
        unsubscribe?.();
        clearInterval(heartbeat);
        res.end();
      }
    };
    if (!terminal(job)) {
      unsubscribe = manager.subscribe(job.id, send);
      heartbeat = setInterval(() => res.write(': heartbeat\n\n'), 15000);
      heartbeat.unref();
    }
    res.on('close', () => { closed = true; unsubscribe?.(); clearInterval(heartbeat); });
    send(job);
  });
  return router;
}
module.exports = { createSecurityRouter, validateRequest };
