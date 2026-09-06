'use strict';
const crypto = require('crypto');

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

// Plain in-memory "user directory" used by most challenges (A01, A02, A04, A07, A08).
// Deliberately insecure in various ways per-challenge — see routes/*.js for how each is (ab)used.
const users = [
  { id: 1, username: 'alice', password: 'alice123', role: 'user', bio: 'QA engineer.', recoveryCode: Buffer.from('LAB{a02_easy_base64_is_not_encryption}').toString('base64') },
  { id: 2, username: 'bob', password: 'bob123', role: 'user', bio: 'Backend dev.', recoveryCode: Buffer.from('bob-recovery-2024').toString('base64') },
  { id: 42, username: 'legacy-admin', password: 'admin123', role: 'admin', bio: 'Old admin panel, never decommissioned.' },
  { id: 77, username: 'weakuser', password: 'password1', role: 'user', bio: 'Never changed the default password.' },
  { id: 88, username: 'mfauser', password: 'MfaTest#2024', role: 'admin', bio: 'Admin account protected by (flawed) MFA.' },
  {
    id: 99, username: 'admin', role: 'admin', bio: 'Primary administrator.',
    // Weak, unsalted MD5 of a common password — crackable via hashcat/john/online lookups.
    passwordHash: md5('P@ssw0rd123'),
    recoveryCode: Buffer.from('admin-master-recovery-key').toString('base64')
  }
];

let nextUserId = 1000;
function createUser(username, password) {
  const u = { id: nextUserId++, username, password, role: 'user', bio: '' };
  users.push(u);
  return u;
}
function findUserByUsername(username) {
  return users.find(u => u.username === username);
}
function findUserById(id) {
  return users.find(u => u.id === Number(id));
}

// Common-password list for the A07-easy brute force target ("weakuser" / password1)
const COMMON_PASSWORDS = [
  '123456', 'password', '123456789', '12345678', '12345', 'qwerty',
  '111111', '123123', 'abc123', 'password1', 'iloveyou', 'admin'
];

// A04-medium product catalog (server-side source of truth for price)
const CATALOG = {
  1: { id: 1, name: 'Premium Widget', price: 499.99 }
};

module.exports = { users, createUser, findUserByUsername, findUserById, md5, COMMON_PASSWORDS, CATALOG };
