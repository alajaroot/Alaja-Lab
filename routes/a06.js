'use strict';
const express = require('express');
const router = express.Router();
const { parseWithExternalEntities, extractTag } = require('../lib/legacy-xml-parser');
const { deserialize } = require('../lib/insecure-deserialize');

// Fake outdated-version banner for the whole A06 router, as a discoverable clue.
router.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'LegacyXMLLib/1.2.0 (EOL 2019, known XXE issues)');
  next();
});

const xmlBodyParser = express.text({ type: ['application/xml', 'text/xml', 'text/plain'], limit: '200kb' });

// ---- EASY: XXE reading a local flag file ----
router.post('/easy/import-xml', xmlBodyParser, async (req, res) => {
  try {
    const { xml } = await parseWithExternalEntities(req.body || '');
    const data = extractTag(xml, 'data');
    const out = { parsed: data };
    if (typeof data === 'string' && data.includes('LAB{')) out.flag = data.trim();
    res.json(out);
  } catch (e) {
    res.status(400).json({ error: 'XML parse error: ' + e.message });
  }
});

// ---- MEDIUM: insecure deserialization (node-serialize style) ----
router.post('/medium/import-session', express.json(), (req, res) => {
  const { blob } = req.body || {};
  if (!blob) return res.status(400).json({ error: 'blob required' });
  try {
    const obj = deserialize(blob); // VULN: eval-based deserialization of attacker-controlled data
    res.json({ result: obj });
  } catch (e) {
    res.status(400).json({ error: 'deserialize error: ' + e.message });
  }
});

// ---- HARD: XXE used for SSRF against an internal-only endpoint ----
router.post('/hard/import-xml', xmlBodyParser, async (req, res) => {
  try {
    const { xml } = await parseWithExternalEntities(req.body || '');
    const data = extractTag(xml, 'data');
    const out = { parsed: data };
    if (typeof data === 'string' && data.includes('LAB{')) out.flag = data.trim();
    res.json(out);
  } catch (e) {
    res.status(400).json({ error: 'XML parse error: ' + e.message });
  }
});

module.exports = router;
