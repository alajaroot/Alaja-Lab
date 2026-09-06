'use strict';
const express = require('express');
const router = express.Router();
const vm = require('vm');

// ---- EASY: leftover default credentials on a legacy admin panel ----
router.post('/easy/legacy-login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === 'admin' && password === 'admin123') {
    return res.json({ ok: true, flag: 'LAB{a05_easy_default_credentials_still_active}' });
  }
  res.status(401).json({ error: 'invalid credentials' });
});

// ---- MEDIUM: exposed backup file ----
// Served as a static file — see server.js static mount of /static -> public/static
// File lives at public/static/backups/site-backup-2024.txt

// ---- HARD: undocumented debug console (expression evaluator with require() exposed) ----
router.post('/hard/debug-console', (req, res) => {
  const { expr } = req.body || {};
  if (!expr) return res.status(400).json({ error: 'expr required' });
  try {
    // VULN: sandbox still exposes require(), so it's not really a sandbox at all.
    const sandbox = { require, result: undefined };
    vm.createContext(sandbox);
    const script = new vm.Script(`result = (${expr})`);
    script.runInContext(sandbox, { timeout: 2000 });
    res.json({ result: sandbox.result });
  } catch (e) {
    res.status(400).json({ error: 'evaluation error: ' + e.message });
  }
});

module.exports = router;
