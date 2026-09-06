'use strict';
const initSqlJs = require('sql.js');

let db = null;

async function initSqlDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT,
      password TEXT,
      role TEXT
    );
    CREATE TABLE products (
      id INTEGER PRIMARY KEY,
      name TEXT,
      description TEXT
    );
    CREATE TABLE secrets (
      id INTEGER PRIMARY KEY,
      label TEXT,
      value TEXT
    );
  `);
  db.run(`INSERT INTO users (id, username, password, role) VALUES
    (1, 'alice', 'alice123', 'user'),
    (2, 'bob', 'bob123', 'user'),
    (77, 'weakuser', 'password1', 'user'),
    (88, 'mfauser', 'MfaTest#2024', 'admin'),
    (99, 'admin', 'S3cur3AdminPass!', 'admin');`);
  db.run(`INSERT INTO products (id, name, description) VALUES
    (1, 'Wireless Mouse', 'Ergonomic wireless mouse'),
    (2, 'Mechanical Keyboard', 'RGB mechanical keyboard'),
    (3, 'USB-C Hub', '7-in-1 USB-C hub');`);
  db.run(`INSERT INTO secrets (id, label, value) VALUES
    (1, 'flag', 'LAB{a03_medium_blind_sqli_extracted}');`);
  return db;
}

function getDb() {
  if (!db) throw new Error('sql.js DB not initialized yet');
  return db;
}

// Runs a raw SQL string and returns rows as an array of objects.
// Deliberately no parameterization here — callers build vulnerable queries on purpose.
function rawQuery(sql) {
  const stmt = getDb().prepare(sql);
  const rows = [];
  try {
    while (stmt.step()) rows.push(stmt.getAsObject());
  } finally {
    stmt.free();
  }
  return rows;
}

module.exports = { initSqlDb, getDb, rawQuery };
