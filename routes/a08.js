'use strict';
const express = require('express');
const router = express.Router();

globalThis.__A08_EASY_FLAG__ = 'LAB{a08_easy_insecure_eval_deserialization}';

// ---- EASY: insecure cookie deserialization via eval() ----
router.get('/easy/prefs', (req, res) => {
  const cookie = req.cookies.prefs;
  if (!cookie) {
    // Set a normal, honestly-behaved default cookie so the feature "works" out of the box.
    const defaultPrefs = Buffer.from(JSON.stringify({ theme: 'dark' })).toString('base64');
    res.cookie('prefs', defaultPrefs, { httpOnly: false, sameSite: 'lax' });
    return res.json({ theme: 'dark' });
  }
  try {
    const decoded = Buffer.from(cookie, 'base64').toString('utf8');
    // VULN: eval() instead of JSON.parse() — decoded content is executed as JS, not just parsed as data.
    // eslint-disable-next-line no-eval
    const prefs = eval('(' + decoded + ')');
    res.json(prefs);
  } catch (e) {
    res.status(400).json({ error: 'could not read prefs cookie: ' + e.message });
  }
});

// ---- MEDIUM: unsigned plugin / update fetch with no integrity check ----
router.post('/medium/install-plugin', express.json(), async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    // VULN: fetches and executes remote code with no signature/checksum/allow-list verification.
    const source = await (await fetch(url)).text();
    const moduleObj = { exports: {} };
    const wrapper = new Function('module', 'exports', 'require', source);
    wrapper(moduleObj, moduleObj.exports, require);
    const result = typeof moduleObj.exports.run === 'function' ? moduleObj.exports.run() : null;
    res.json({ pluginLoadedFrom: url, result });
  } catch (e) {
    res.status(400).json({ error: 'plugin load error: ' + e.message });
  }
});

// ---- HARD: prototype pollution -> auth bypass ----
function unsafeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      // VULN: no filtering of dangerous keys like __proto__ / constructor / prototype.
      if (typeof target[key] !== 'object' || target[key] === null) target[key] = {};
      unsafeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
const appSettings = {};
router.post('/hard/update-settings', express.json(), (req, res) => {
  unsafeDeepMerge(appSettings, req.body || {});
  res.json({ ok: true, settings: appSettings });
});
router.get('/hard/admin-flag', (req, res) => {
  const probe = {}; // a brand-new plain object — should NOT have isAdmin unless the prototype was polluted
  if (probe.isAdmin === true) {
    return res.json({ flag: 'LAB{a08_hard_prototype_pollution_auth_bypass}' });
  }
  res.status(403).json({ error: 'admins only' });
});

module.exports = router;
