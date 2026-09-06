'use strict';
const express = require('express');
const router = express.Router();
const { CATALOG, md5 } = require('../lib/db');

// ---- EASY: brute-forceable coupon code, no rate limiting ----
const VALID_COUPON = '7392'; // 4-digit code, no lockout/rate limit on the endpoint below
router.get('/easy/redeem', (req, res) => {
  const { code } = req.query;
  if (code === VALID_COUPON) {
    return res.json({ ok: true, flag: 'LAB{a04_easy_no_rate_limit_bruteforce}' });
  }
  res.json({ ok: false });
});

// ---- MEDIUM: client-trusted price manipulation ----
router.post('/medium/checkout', (req, res) => {
  const { itemId, price } = req.body || {};
  const item = CATALOG[itemId];
  if (!item) return res.status(404).json({ error: 'unknown item' });
  // VULN: server trusts the client-submitted "price" instead of item.price.
  const paid = Number(price);
  if (Number.isNaN(paid) || paid < 0) return res.status(400).json({ error: 'invalid price' });
  const order = { itemId, catalogPrice: item.price, paid };
  if (paid < 1.0) {
    return res.json({ ok: true, order, flag: 'LAB{a04_medium_client_side_price_trust}' });
  }
  res.json({ ok: true, order });
});

// ---- HARD: predictable password reset token ----
router.post('/hard/forgot-password', (req, res) => {
  const { username = 'admin' } = req.body || {};
  const minuteBucket = Math.floor(Date.now() / 60000);
  // VULN: token derived from low-entropy, guessable inputs (username + current minute).
  res.json({
    ok: true,
    message: `If an account exists for ${username}, a reset token was generated. (In this lab it's not emailed to you — figure out the scheme.)`,
    serverTimeHint: new Date().toISOString()
  });
  void minuteBucket;
});
router.post('/hard/reset-password', (req, res) => {
  const { username = 'admin', token, newPassword } = req.body || {};
  const minuteBucket = Math.floor(Date.now() / 60000);
  const candidates = [minuteBucket, minuteBucket - 1]; // tolerate clock/minute-boundary drift
  const valid = candidates.some(mb => md5(`${username}:${mb}`) === token);
  if (!valid) return res.status(400).json({ error: 'invalid or expired token' });
  res.json({ ok: true, newPassword, flag: 'LAB{a04_hard_predictable_reset_token}' });
});

module.exports = router;
