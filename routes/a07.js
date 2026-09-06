'use strict';
const express = require('express');
const router = express.Router();
const { findUserByUsername } = require('../lib/db');
const jwtLib = require('../lib/insecure-jwt');

// ---- EASY: no lockout + weak/common password ----
router.post('/easy/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = findUserByUsername(username);
  // VULN: unlimited attempts, no delay, no lockout, no CAPTCHA.
  if (u && u.password === password) {
    return res.json({ ok: true, flag: username === 'weakuser' ? 'LAB{a07_easy_no_lockout_weak_password}' : undefined });
  }
  res.status(401).json({ error: 'invalid credentials' });
});

// ---- MEDIUM: session fixation ----
// A separate mini session store just for this challenge, to keep it self-contained.
const fixationSessions = new Map(); // sid -> { role }
router.get('/medium/set-session', (req, res) => {
  const sid = req.query.sid;
  if (!sid) return res.status(400).json({ error: 'sid query param required' });
  // VULN: the app accepts a client-chosen session identifier at all.
  fixationSessions.set(sid, fixationSessions.get(sid) || { role: 'anonymous' });
  res.cookie('fix_sid', sid, { httpOnly: false, sameSite: 'lax' });
  res.json({ ok: true, sid });
});
router.post('/medium/admin-visits-link', (req, res) => {
  const { sid } = req.body || {};
  if (!sid) return res.status(400).json({ error: 'sid required' });
  // Simulates the admin clicking your crafted link and logging in —
  // VULN: the session id is NOT regenerated on login, so it becomes authenticated as admin.
  fixationSessions.set(sid, { role: 'admin' });
  res.json({ ok: true, message: 'admin "clicked" your link and logged in using that session id' });
});
router.get('/medium/flag', (req, res) => {
  const sid = req.cookies.fix_sid;
  const s = sid && fixationSessions.get(sid);
  if (!s || s.role !== 'admin') return res.status(403).json({ error: 'not authenticated as admin' });
  res.json({ flag: 'LAB{a07_medium_session_fixation}' });
});

// ---- HARD: MFA step-skip logic flaw ----
router.post('/hard/login-step1', (req, res) => {
  const { username, password } = req.body || {};
  const u = findUserByUsername(username);
  if (!u || u.password !== password) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwtLib.sign({ sub: u.username, role: u.role, step: 'mfa_pending' }, { alg: 'HS256' });
  res.json({ ok: true, token, message: 'Now call /verify-otp with the code sent to your device.' });
});
router.post('/hard/verify-otp', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  try {
    const payload = jwtLib.verify(token);
    const { otp } = req.body || {};
    if (otp !== '000000') return res.status(401).json({ error: 'incorrect OTP' }); // real OTP intentionally unknown to the player
    const verifiedToken = jwtLib.sign({ ...payload, step: 'mfa_verified' }, { alg: 'HS256' });
    res.json({ ok: true, token: verifiedToken });
  } catch (e) {
    res.status(401).json({ error: 'invalid token' });
  }
});
router.get('/hard/admin-flag', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  try {
    const payload = jwtLib.verify(token);
    // VULN: only checks role, never checks payload.step === 'mfa_verified'.
    if (payload.role !== 'admin') return res.status(403).json({ error: 'admins only' });
    res.json({ flag: 'LAB{a07_hard_mfa_step_skip}' });
  } catch (e) {
    res.status(401).json({ error: 'invalid token' });
  }
});

module.exports = router;
