'use strict';
const express = require('express');
const router = express.Router();
const { findUserById, users } = require('../lib/db');
const { requireLogin, currentUser } = require('../lib/session');

// ---- EASY: IDOR ----
// VULN: no ownership check — any logged-in user can view any user's profile by ID.
router.get('/easy/profile/:id', requireLogin, (req, res) => {
  const target = findUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'not found' });
  const { password, passwordHash, ...safe } = target;
  if (target.username === 'admin') safe.internalNote = 'LAB{a01_easy_idor_profile_leak}';
  res.json(safe);
});

// ---- MEDIUM: missing function-level access control via spoofable header ----
router.get('/medium/admin/users', (req, res) => {
  const isAdmin = req.headers['x-admin'] === 'true'; // VULN: trusts a client-supplied header
  if (!isAdmin) return res.status(403).json({ error: 'admins only' });
  res.json({
    flag: 'LAB{a01_medium_header_trust_bypass}',
    users: users.map(u => ({ id: u.id, username: u.username, role: u.role }))
  });
});

// ---- HARD: mass assignment -> privilege escalation ----
router.patch('/hard/profile', requireLogin, (req, res) => {
  const user = req.user;
  // VULN: no allow-list — the entire request body is merged into the user record,
  // including fields like "role" that should never be client-editable.
  Object.assign(user, req.body);
  const { password, passwordHash, ...safe } = user;
  res.json({ ok: true, profile: safe });
});
router.get('/hard/admin-flag', requireLogin, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admins only' });
  res.json({ flag: 'LAB{a01_hard_mass_assignment_role_escalation}' });
});

module.exports = router;
