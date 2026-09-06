'use strict';
const express = require('express');
const router = express.Router();
const { createUser, findUserByUsername } = require('../lib/db');
const { ensureSession, setSessionData, currentUser } = require('../lib/session');

router.post('/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (findUserByUsername(username)) return res.status(409).json({ error: 'username taken' });
  const u = createUser(username, password);
  const sid = ensureSession(req, res);
  setSessionData(sid, { userId: u.id });
  res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = findUserByUsername(username);
  if (!u || u.password !== password) return res.status(401).json({ error: 'invalid credentials' });
  const sid = ensureSession(req, res);
  setSessionData(sid, { userId: u.id });
  res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role } });
});

router.post('/logout', (req, res) => {
  res.clearCookie('sid');
  res.json({ ok: true });
});

router.get('/me', (req, res) => {
  const u = currentUser(req);
  if (!u) return res.json({ user: null });
  res.json({ user: { id: u.id, username: u.username, role: u.role } });
});

module.exports = router;
