'use strict';
const express = require('express');
const router = express.Router();
const { users, findUserByUsername, md5 } = require('../lib/db');
const jwtLib = require('../lib/insecure-jwt');

// ---- EASY: sensitive data exposure (base64 "encoding" mistaken for protection) ----
router.get('/easy/users', (req, res) => {
  // VULN: dumps every user's "recoveryCode" field, which is just base64, not encryption.
  res.json({ users: users.map(u => ({ username: u.username, recoveryCode: u.recoveryCode })) });
});

// ---- MEDIUM: weak unsalted MD5 hash leak + crackable login ----
router.get('/medium/leak', (req, res) => {
  // VULN: "internal" hash dump exposed publicly; MD5 with no salt is fast to crack.
  res.json({ note: 'internal-hash-dump.csv (leaked)', username: 'admin', passwordHash: md5('P@ssw0rd123') });
});
router.post('/medium/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = findUserByUsername(username);
  if (!u || !u.passwordHash) return res.status(401).json({ error: 'invalid credentials' });
  if (md5(password) !== u.passwordHash) return res.status(401).json({ error: 'invalid credentials' });
  res.json({ flag: 'LAB{a02_medium_md5_no_salt_cracked}' });
});

// ---- HARD: JWT alg:none forgery ----
router.get('/hard/token', (req, res) => {
  const token = jwtLib.sign({ sub: 'guest', role: 'user' }, { alg: 'HS256' });
  res.json({ token });
});
router.get('/hard/admin', (req, res) => {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  try {
    const payload = jwtLib.verify(token); // VULN: verify() trusts the token's own "alg" header
    if (payload.role !== 'admin') return res.status(403).json({ error: 'admins only' });
    res.json({ flag: 'LAB{a02_hard_jwt_alg_none_forged}' });
  } catch (e) {
    res.status(401).json({ error: 'invalid token: ' + e.message });
  }
});

module.exports = router;
