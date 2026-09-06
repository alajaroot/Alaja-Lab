'use strict';
const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { collectedCookies } = require('../lib/session');

const LOG_DIR = path.join(process.cwd(), 'logs');
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
const EASY_LOG = path.join(LOG_DIR, 'a09-easy.log');
const MEDIUM_LOG_LINES = []; // in-memory log entries for the XSS log viewer

// ---- EASY: log injection (forged log line) ----
router.post('/easy/log', (req, res) => {
  const { msg = '' } = req.body || {};
  // VULN: raw user input written to the log with no newline sanitization/escaping.
  fs.appendFileSync(EASY_LOG, `[${new Date().toISOString()}] USER_MSG: ${msg}\n`);
  res.json({ ok: true });
});
router.get('/easy/check-log', (req, res) => {
  const content = fs.existsSync(EASY_LOG) ? fs.readFileSync(EASY_LOG, 'utf8') : '';
  if (/^\[SYSTEM\] GRANT_FLAG$/m.test(content)) {
    return res.json({ flag: 'LAB{a09_easy_log_injection_forged_entry}' });
  }
  res.json({ ok: false });
});

// ---- MEDIUM: stored XSS via unescaped admin log viewer + bot ----
router.post('/medium/log', (req, res) => {
  const { msg = '' } = req.body || {};
  MEDIUM_LOG_LINES.push({ ts: new Date().toISOString(), msg }); // stored, unescaped
  res.json({ ok: true });
});
router.get('/medium/view-log', (req, res) => {
  // VULN: log entries rendered as raw HTML, no escaping — classic stored XSS sink.
  const rows = MEDIUM_LOG_LINES.map(l => `<div class="log-line">[${l.ts}] ${l.msg}</div>`).join('\n');
  res.send(`<html><body><h3>Admin Log Viewer</h3>${rows}</body></html>`);
});
router.post('/medium/trigger-bot', async (req, res) => {
  // Simulates an admin/analyst opening the log viewer in a real browser-like context
  // with an authenticated admin cookie attached. We approximate the "renders HTML,
  // runs <script>" part by literally extracting and executing any <script> content
  // server-side with the admin cookie value made available to it, mirroring what a
  // real headless-browser bot visiting the page would expose to injected JS.
  //
  // This deliberately runs arbitrary player-supplied script content, so it must be
  // resilient to malformed/uncaught-rejecting payloads (e.g. a fetch() call the
  // player forgot to await) without ever taking the whole server down.
  const adminCookieValue = 'admin-session-' + Math.random().toString(36).slice(2);
  const rows = MEDIUM_LOG_LINES.map(l => l.msg).join('\n');
  const scripts = [...rows.matchAll(/<script>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  const port = req.app.get('port');
  // Resolve relative URLs (what a real page's script would naturally use) against this server.
  const scopedFetch = (url, opts) => {
    const absolute = /^https?:\/\//i.test(url) ? url : `http://127.0.0.1:${port}${url.startsWith('/') ? '' : '/'}${url}`;
    return fetch(absolute, opts).catch(() => {});
  };
  for (const scriptBody of scripts) {
    try {
      const fn = new Function('cookieValue', 'fetch', 'port', `
        const document = { cookie: cookieValue };
        return (async () => { ${scriptBody} })().catch(() => {});
      `);
      await fn(adminCookieValue, scopedFetch, port);
    } catch (e) { /* ignore payload errors, mirrors a real bot silently failing */ }
  }
  // Give any fire-and-forget (un-awaited) fetches a moment to land before responding.
  await new Promise(r => setTimeout(r, 150));
  res.json({ ok: true, message: 'admin bot visited the log viewer' });
});
router.post('/medium/collect', express.text({ type: '*/*' }), (req, res) => {
  collectedCookies.push(String(req.body));
  res.json({ ok: true });
});
router.get('/medium/collected', (req, res) => {
  // Simulates checking the logs on your own attacker-controlled collection server.
  res.json({ collected: collectedCookies });
});
router.get('/medium/flag', (req, res) => {
  const auth = req.headers['x-admin-cookie'];
  if (auth && collectedCookies.includes(auth)) {
    return res.json({ flag: 'LAB{a09_medium_stored_xss_log_viewer}' });
  }
  res.status(403).json({ error: 'present a stolen admin cookie via X-Admin-Cookie header' });
});

// ---- HARD: unmonitored mass enumeration ----
const TOTAL_PAGES = 500;
const FLAG_PAGE = 317; // fixed so write-ups are reproducible; not disclosed to the player
router.get('/hard/export', (req, res) => {
  const page = Number(req.query.page) || 1;
  // VULN: no auth, no rate limiting, no logging/alerting on this bulk-export endpoint at all.
  const note = page === FLAG_PAGE
    ? 'LAB{a09_hard_unmonitored_mass_enumeration}'
    : `decoy record #${page} - nothing to see here`;
  res.json({ page, totalPages: TOTAL_PAGES, note });
});

module.exports = router;
