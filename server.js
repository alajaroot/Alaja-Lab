'use strict';
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const { initSqlDb } = require('./lib/sqldb');
const { markHit } = require('./lib/internal-state');

const PORT = process.env.PORT || 4010;

async function main() {
  // This lab deliberately executes arbitrary player-supplied code in a few places
  // (A05-hard debug console, A09-medium's simulated XSS bot). A malformed or
  // fire-and-forget payload there should never be able to take the whole server down.
  process.on('unhandledRejection', (err) => {
    console.error('[unhandledRejection - ignored, likely from a lab payload]', err && err.message);
  });
  process.on('uncaughtException', (err) => {
    console.error('[uncaughtException - ignored, likely from a lab payload]', err && err.message);
  });

  await initSqlDb(); // must finish before A03 routes are hit

  const app = express();
  app.set('port', PORT);
  app.use(cookieParser());
  app.use(express.json({ limit: '500kb' }));
  app.use(express.static(path.join(__dirname, 'public')));

  // ---- Core lab plumbing ----
  app.use('/api/auth', require('./routes/auth'));
  app.use('/api/lab', require('./routes/lab'));

  // ---- OWASP Top 10 challenge routers ----
  app.use('/api/a01', require('./routes/a01'));
  app.use('/api/a02', require('./routes/a02'));
  app.use('/api/a03', require('./routes/a03'));
  app.use('/api/a04', require('./routes/a04'));
  app.use('/api/a05', require('./routes/a05'));
  app.use('/api/a06', require('./routes/a06'));
  app.use('/api/a07', require('./routes/a07'));
  app.use('/api/a08', require('./routes/a08'));
  app.use('/api/a09', require('./routes/a09'));
  app.use('/api/a10', require('./routes/a10'));

  // ---- "Internal-only" endpoints used as SSRF targets ----
  // These deliberately only answer requests that both (a) originate from the
  // server's own loopback address, AND (b) carry a marker header that ONLY the
  // lab's own outbound-fetch helpers attach — i.e. they are unreachable except
  // via a genuine server-side-request-forgery bug elsewhere in the app.
  function requireInternal(req, res, next) {
    const remote = req.socket.remoteAddress || '';
    const isLoopback = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
    const hasMarker = req.headers['x-internal-fetch'] === 'lab-internal-1';
    if (!isLoopback || !hasMarker) {
      return res.status(403).send('this endpoint is only reachable from inside the application itself');
    }
    next();
  }

  app.get('/internal/a06-hard-flag', requireInternal, (req, res) => {
    res.type('text/plain').send('LAB{a06_hard_xxe_ssrf_chain}');
  });
  app.get('/internal/a10-easy-flag', requireInternal, (req, res) => {
    res.json({ flag: 'LAB{a10_easy_unrestricted_ssrf}' });
  });
  app.get('/internal/a10-medium-flag', requireInternal, (req, res) => {
    res.json({ flag: 'LAB{a10_medium_ssrf_blocklist_bypass}' });
  });
  app.get('/internal/a10-hard-flag', requireInternal, (req, res) => {
    markHit('a10-hard');
    res.json({ ok: true }); // response is intentionally not surfaced to the caller (blind SSRF)
  });

  app.listen(PORT, () => {
    console.log(`\nOWASP Top 10 CTF Lab running at http://localhost:${PORT}\n`);
    console.log('Open that URL in a browser for the challenge dashboard, or drive it entirely');
    console.log('through Burp Suite / curl / scripts against the documented API endpoints.\n');
  });
}

main().catch(err => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
