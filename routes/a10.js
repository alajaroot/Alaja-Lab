'use strict';
const express = require('express');
const router = express.Router();
const { wasHit } = require('../lib/internal-state');

function getPort(req) {
  return req.app.get('port');
}

// ---- EASY: fully unrestricted SSRF ----
router.post('/easy/fetch-avatar', express.json(), async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    // VULN: no validation of the target URL at all; the server fetches anything.
    const r = await fetch(url, { headers: { 'x-internal-fetch': 'lab-internal-1' } });
    const text = await r.text();
    res.json({ status: r.status, body: text });
  } catch (e) {
    res.status(400).json({ error: 'fetch error: ' + e.message });
  }
});

// ---- MEDIUM: naive denylist, bypassable ----
function isBlockedByNaiveDenylist(url) {
  const blocked = ['localhost', '127.0.0.1'];
  return blocked.some(b => url.toLowerCase().includes(b));
}
router.post('/medium/fetch-avatar-v2', express.json(), async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  // VULN: denylist is a naive substring check — trivially bypassed with alternate
  // loopback representations (127.1, 0x7f000001, [::1], etc.) that don't contain
  // the literal blocked substrings.
  if (isBlockedByNaiveDenylist(url)) {
    return res.status(403).json({ error: 'blocked target' });
  }
  try {
    const r = await fetch(url, { headers: { 'x-internal-fetch': 'lab-internal-1' } });
    const text = await r.text();
    res.json({ status: r.status, body: text });
  } catch (e) {
    res.status(400).json({ error: 'fetch error: ' + e.message });
  }
});

// ---- HARD: blind SSRF via webhook + open redirect chain ----
let registeredWebhook = null;

router.post('/hard/register-webhook', express.json(), (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  const abs = url.startsWith('http') ? url : `http://127.0.0.1:${getPort(req)}${url}`;
  // VULN: registration-time validation only looks at hostname + path, never at
  // query-string targets of an otherwise "safe" endpoint like our own /redirect helper.
  let parsed;
  try { parsed = new URL(abs); } catch (e) { return res.status(400).json({ error: 'invalid url' }); }
  const hostBlocked = ['127.0.0.1', 'localhost'].includes(parsed.hostname);
  const pathBlocked = /internal/i.test(parsed.pathname);
  if (hostBlocked && pathBlocked) {
    return res.status(403).json({ error: 'internal targets blocked at registration' });
  }
  registeredWebhook = abs;
  res.json({ ok: true, registered: registeredWebhook });
});

// Open redirect endpoint elsewhere in the app (a legitimate-looking feature on its own).
router.get('/hard/redirect', (req, res) => {
  const { to } = req.query;
  if (!to) return res.status(400).json({ error: 'to required' });
  // VULN: redirects to any target, no allow-list — a classic open redirect.
  res.redirect(to);
});

router.post('/hard/fire-webhook', async (req, res) => {
  if (!registeredWebhook) return res.status(400).json({ error: 'no webhook registered' });
  try {
    // VULN: the webhook dispatcher follows redirects blindly (default fetch behavior),
    // so a registered "safe-looking" URL that 302s to an internal target still gets reached.
    // The response body is intentionally NOT returned to the caller - this is blind SSRF.
    await fetch(registeredWebhook, { headers: { 'x-internal-fetch': 'lab-internal-1' }, redirect: 'follow' });
    res.json({ ok: true, message: 'webhook fired (response not shown - blind)' });
  } catch (e) {
    res.status(200).json({ ok: false, message: 'webhook fire failed (response not shown - blind)' });
  }
});

router.get('/hard/check-flag', (req, res) => {
  if (wasHit('a10-hard')) {
    return res.json({ flag: 'LAB{a10_hard_blind_ssrf_redirect_chain}' });
  }
  res.json({ ok: false, message: 'internal target not confirmed reached yet' });
});

module.exports = router;
