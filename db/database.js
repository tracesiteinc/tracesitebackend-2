const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || './tracesite.db';
const db = new Database(path.resolve(DB_PATH));

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─────────────────────────────────────────────
//  SCHEMA
// ─────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    email       TEXT    NOT NULL UNIQUE,
    password    TEXT    NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'user',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    url         TEXT    NOT NULL,
    verdict     TEXT    NOT NULL,           -- 'safe' | 'suspicious' | 'scam'
    score       INTEGER NOT NULL,           -- 0 (safe) to 100 (scam)
    details     TEXT    NOT NULL DEFAULT '{}', -- JSON: signals, flags
    ip_address  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    url         TEXT    NOT NULL,
    reason      TEXT    NOT NULL,           -- 'phishing' | 'investment_scam' | 'fake_ecommerce' | 'malware' | 'other'
    description TEXT,
    status      TEXT    NOT NULL DEFAULT 'pending',  -- 'pending' | 'confirmed' | 'dismissed'
    reviewed_by INTEGER REFERENCES users(id),
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS flagged_urls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url           TEXT    NOT NULL UNIQUE,
    report_count  INTEGER NOT NULL DEFAULT 1,
    confirmed     INTEGER NOT NULL DEFAULT 0,  -- 1 = admin confirmed scam
    first_seen    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_reported TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_scans_url     ON scans(url);
  CREATE INDEX IF NOT EXISTS idx_scans_user    ON scans(user_id);
  CREATE INDEX IF NOT EXISTS idx_reports_url   ON reports(url);
  CREATE INDEX IF NOT EXISTS idx_reports_user  ON reports(user_id);
  CREATE INDEX IF NOT EXISTS idx_flagged_url   ON flagged_urls(url);
`);

// ─────────────────────────────────────────────
//  HELPER FUNCTIONS
// ─────────────────────────────────────────────

const userQueries = {
  create: db.prepare(`
    INSERT INTO users (name, email, password, role)
    VALUES (@name, @email, @password, @role)
  `),
  findByEmail: db.prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`),
  findById:    db.prepare(`SELECT * FROM users WHERE id = ? LIMIT 1`),
  updateRole:  db.prepare(`UPDATE users SET role = ? WHERE id = ?`),
};

const scanQueries = {
  create: db.prepare(`
    INSERT INTO scans (user_id, url, verdict, score, details, ip_address)
    VALUES (@user_id, @url, @verdict, @score, @details, @ip_address)
  `),
  findByUrl: db.prepare(`
    SELECT * FROM scans WHERE url = ? ORDER BY created_at DESC LIMIT 10
  `),
  recentByUser: db.prepare(`
    SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 20
  `),
  stats: db.prepare(`
    SELECT
      COUNT(*) AS total_scans,
      SUM(CASE WHEN verdict = 'scam'       THEN 1 ELSE 0 END) AS total_scams,
      SUM(CASE WHEN verdict = 'safe'       THEN 1 ELSE 0 END) AS total_safe,
      SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) AS total_suspicious
    FROM scans
  `),
};

const reportQueries = {
  create: db.prepare(`
    INSERT INTO reports (user_id, url, reason, description)
    VALUES (@user_id, @url, @reason, @description)
  `),
  findByUrl:   db.prepare(`SELECT * FROM reports WHERE url = ? ORDER BY created_at DESC`),
  pending:     db.prepare(`SELECT r.*, u.name AS reporter_name, u.email AS reporter_email FROM reports r LEFT JOIN users u ON r.user_id = u.id WHERE r.status = 'pending' ORDER BY r.created_at DESC`),
  updateStatus: db.prepare(`UPDATE reports SET status = ?, reviewed_by = ? WHERE id = ?`),
  all:         db.prepare(`SELECT * FROM reports ORDER BY created_at DESC LIMIT 50`),
};

const flaggedQueries = {
  upsert: db.prepare(`
    INSERT INTO flagged_urls (url) VALUES (?)
    ON CONFLICT(url) DO UPDATE SET
      report_count  = report_count + 1,
      last_reported = datetime('now')
  `),
  findByUrl:  db.prepare(`SELECT * FROM flagged_urls WHERE url = ? LIMIT 1`),
  confirm:    db.prepare(`UPDATE flagged_urls SET confirmed = 1 WHERE id = ?`),
  topFlagged: db.prepare(`SELECT * FROM flagged_urls ORDER BY report_count DESC LIMIT 20`),
};

module.exports = {
  db,
  userQueries,
  scanQueries,
  reportQueries,
  flaggedQueries,
};
