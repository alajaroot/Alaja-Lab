'use strict';
// A minimal, INTENTIONALLY INSECURE JWT-like implementation for lab purposes.
// Real JWT libraries let you pin the expected algorithm; this one (on purpose)
// trusts whatever "alg" the token's own header claims, including "none".
const crypto = require('crypto');

const SECRET = 'labsecret'; // deliberately weak/guessable, used for HS256 tokens issued by the lab

function b64url(input) {
  return Buffer.from(JSON.stringify(input)).toString('base64url');
}
function b64urlDecode(str) {
  return JSON.parse(Buffer.from(str, 'base64url').toString('utf8'));
}

function sign(payload, { alg = 'HS256' } = {}) {
  const header = { alg, typ: 'JWT' };
  const h = b64url(header);
  const p = b64url(payload);
  if (alg === 'none') {
    return `${h}.${p}.`;
  }
  const sig = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

// VULNERABLE: honors whatever alg the presented token claims.
function verify(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [h, p, s] = parts;
  const header = b64urlDecode(h);
  const payload = b64urlDecode(p);

  if (header.alg === 'none') {
    // Accepts unsigned tokens if the header says so. This is the bug.
    return payload;
  }
  if (header.alg === 'HS256') {
    const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64url');
    if (expected !== s) throw new Error('bad signature');
    return payload;
  }
  throw new Error('unsupported alg');
}

module.exports = { sign, verify };
