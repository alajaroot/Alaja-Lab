'use strict';
const { v4: uuidv4 } = require('uuid');
const { findUserById } = require('./db');

// Simple server-side session store keyed by opaque session id (cookie: "sid").
// NOTE: for A07-medium (session fixation) this store deliberately does NOT
// rotate/regenerate the session id on login - that omission IS the vulnerability.
const sessions = new Map(); // sid -> { userId, mfaVerified, ... }
const progress = new Map(); // playerId -> Set(challengeId) solved
const collectedCookies = []; // for A09-medium XSS cookie exfiltration demo

function ensurePlayer(req, res) {
  let pid = req.cookies.player;
  if (!pid || !progress.has(pid)) {
    pid = uuidv4();
    progress.set(pid, new Set());
    res.cookie('player', pid, { httpOnly: false, sameSite: 'lax' });
  }
  return pid;
}

function ensureSession(req, res) {
  let sid = req.cookies.sid;
  if (!sid) {
    sid = uuidv4();
    res.cookie('sid', sid, { httpOnly: false, sameSite: 'lax' }); // httpOnly:false is itself a minor, intentional lab looseness for A09-medium XSS cookie theft
  }
  if (!sessions.has(sid)) sessions.set(sid, {});
  return sid;
}

function getSessionData(sid) {
  return sessions.get(sid) || {};
}
function setSessionData(sid, data) {
  sessions.set(sid, { ...getSessionData(sid), ...data });
}

function currentUser(req) {
  const sid = req.cookies.sid;
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s || !s.userId) return null;
  return findUserById(s.userId);
}

function requireLogin(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'login required' });
  req.user = user;
  next();
}

module.exports = {
  sessions, progress, collectedCookies,
  ensurePlayer, ensureSession, getSessionData, setSessionData,
  currentUser, requireLogin
};
