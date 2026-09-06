'use strict';
const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const { rawQuery } = require('../lib/sqldb');
const jwtLib = require('../lib/insecure-jwt');

// ---- EASY: classic SQL injection login bypass ----
// This is the SITE'S real, single login endpoint — it also happens to have zero
// rate limiting (see A07-easy) and a special-cased MFA branch (see A07-hard),
// exactly like a single real login endpoint can carry several distinct flaws at once.
router.post('/easy/login', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  // VULN: raw string concatenation into SQL — no parameterized query.
  const sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  try {
    const rows = rawQuery(sql);
    if (rows.length === 0) return res.status(401).json({ error: 'invalid credentials', sql });
    const row = rows[0];
    if (row.username === 'mfauser') {
      // This account has MFA enabled — issue a "pending" token instead of logging straight in.
      const token = jwtLib.sign({ sub: 'mfauser', role: 'admin', step: 'mfa_pending' }, { alg: 'HS256' });
      return res.json({ ok: true, mfaRequired: true, token, message: 'Verification code sent to your device.' });
    }
    if (row.username === 'admin') {
      return res.json({ ok: true, user: row, flag: 'LAB{a03_easy_sqli_login_bypass}' });
    }
    if (row.username === 'weakuser') {
      return res.json({ ok: true, user: row, flag: 'LAB{a07_easy_no_lockout_weak_password}' });
    }
    res.json({ ok: true, user: row });
  } catch (e) {
    res.status(400).json({ error: 'SQL error: ' + e.message, sql });
  }
});

// ---- MEDIUM: blind boolean-based SQL injection ----
router.get('/medium/search', (req, res) => {
  const name = req.query.name || '';
  // VULN: raw concatenation again, but this endpoint ONLY ever returns true/false — a blind oracle.
  const sql = `SELECT * FROM products WHERE name LIKE '%${name}%'`;
  try {
    const rows = rawQuery(sql);
    res.json({ found: rows.length > 0 });
  } catch (e) {
    res.status(400).json({ found: false, error: 'query error' });
  }
});

// ---- HARD: OS command injection ----
router.post('/hard/ping', (req, res) => {
  const { host = '' } = req.body || {};
  // VULN: user input concatenated directly into a shell command.
  const cmd = `ping -c 1 ${host}`;
  exec(cmd, { timeout: 4000 }, (err, stdout, stderr) => {
    res.json({ command: cmd, stdout: stdout || '', stderr: stderr || (err ? String(err.message) : '') });
  });
});

module.exports = router;
