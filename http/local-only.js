'use strict';
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
function createLocalOnlyMiddleware() {
  return (req, res, next) => {
    if (!LOOPBACK.has(req.socket.remoteAddress)) return res.status(403).json({ error: 'SentinelAI backend is local-only.' });
    const host = String(req.headers.host || '').replace(/:\d+$/, '').toLowerCase();
    if (!HOSTS.has(host)) return res.status(403).json({ error: 'Unrecognized local Host header.' });
    if (req.headers.origin) {
      try {
        const origin = new URL(req.headers.origin);
        if (!['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname.toLowerCase())) return res.status(403).json({ error: 'Unrecognized local Origin.' });
        if (origin.host.toLowerCase() !== String(req.headers.host || '').toLowerCase()) return res.status(403).json({ error: 'Cross-origin local requests are not allowed.' });
      } catch { return res.status(403).json({ error: 'Invalid Origin.' }); }
    }
    next();
  };
}
module.exports = { createLocalOnlyMiddleware };
