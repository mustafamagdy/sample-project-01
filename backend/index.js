const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change';

const db = new Database(path.resolve(__dirname, 'susa.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  alias TEXT UNIQUE NOT NULL,
  target_url TEXT NOT NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER NOT NULL,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  referrer TEXT,
  ip_hash TEXT,
  ua_hash TEXT,
  FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_links_alias ON links(alias);
CREATE INDEX IF NOT EXISTS idx_links_user ON links(user_id);
CREATE INDEX IF NOT EXISTS idx_clicks_link_ts ON clicks(link_id, ts);
`);

app.use(cors({ origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173' }));
app.use(express.json());

function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing auth token' });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const insertUser = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const insertLink = db.prepare('INSERT INTO links (user_id, alias, target_url, expires_at) VALUES (?, ?, ?, ?)');
const findLinkByAlias = db.prepare('SELECT * FROM links WHERE alias = ?');
const findLinkById = db.prepare('SELECT * FROM links WHERE id = ?');
const deleteLinkById = db.prepare('DELETE FROM links WHERE id = ? AND user_id = ?');
const linkAggregatesStmt = db.prepare(`
  SELECT l.id, l.alias, l.target_url, l.expires_at, l.created_at,
         IFNULL(COUNT(c.id), 0) AS total_clicks,
         MAX(c.ts) AS last_click
  FROM links l
  LEFT JOIN clicks c ON c.link_id = l.id
  WHERE l.user_id = ?
  GROUP BY l.id
  ORDER BY l.created_at DESC
`);
const countClicksStmt = db.prepare('SELECT COUNT(*) AS total FROM clicks WHERE link_id = ?');
const lastClickStmt = db.prepare('SELECT MAX(ts) AS last_click FROM clicks WHERE link_id = ?');
const topReferrersStmt = db.prepare(`
  SELECT referrer, COUNT(*) AS total
  FROM clicks
  WHERE link_id = ? AND referrer IS NOT NULL AND referrer != ''
  GROUP BY referrer
  ORDER BY total DESC
  LIMIT 5
`);
const insertClickStmt = db.prepare('INSERT INTO clicks (link_id, referrer, ip_hash, ua_hash) VALUES (?, ?, ?, ?)');

function isValidEmail(email) {
  return typeof email === 'string' && email.includes('@') && email.length <= 255;
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 6;
}

function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (err) {
    return false;
  }
}

function isValidAlias(alias) {
  return typeof alias === 'string' && /^[a-zA-Z0-9_-]{3,30}$/.test(alias);
}

function generateAlias() {
  return Math.random().toString(36).slice(2, 8);
}

app.post('/auth/signup', (req, res) => {
  const { email, password } = req.body || {};

  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: 'Invalid email or password' });
  }

  const existing = findUserByEmail.get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const info = insertUser.run(email.toLowerCase(), passwordHash);
  const user = findUserById.get(info.lastInsertRowid);
  const token = createToken(user);

  res.status(201).json({ token });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!isValidEmail(email) || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const user = findUserByEmail.get(email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = createToken(user);
  res.json({ token });
});

app.post('/links', authMiddleware, (req, res) => {
  const { targetUrl, alias, expiresAt } = req.body || {};

  if (!isValidUrl(targetUrl)) {
    return res.status(400).json({ error: 'Invalid target URL' });
  }

  let finalAlias = alias;
  if (finalAlias) {
    if (!isValidAlias(finalAlias)) {
      return res.status(400).json({ error: 'Invalid alias' });
    }
    if (findLinkByAlias.get(finalAlias)) {
      return res.status(409).json({ error: 'Alias already in use' });
    }
  } else {
    let candidate = '';
    do {
      candidate = generateAlias();
    } while (findLinkByAlias.get(candidate));
    finalAlias = candidate;
  }

  let storedExpiry = null;
  if (expiresAt) {
    const date = new Date(expiresAt);
    if (Number.isNaN(date.getTime())) {
      return res.status(400).json({ error: 'Invalid expiration date' });
    }
    storedExpiry = date.toISOString();
  }

  const info = insertLink.run(req.user.id, finalAlias, targetUrl, storedExpiry);
  const link = findLinkById.get(info.lastInsertRowid);

  res.status(201).json({
    id: link.id,
    alias: link.alias,
    targetUrl: link.target_url,
    expiresAt: link.expires_at,
    createdAt: link.created_at,
    shortUrl: `${BASE_URL}/r/${link.alias}`,
    totalClicks: 0,
    lastClick: null
  });
});

app.get('/links', authMiddleware, (req, res) => {
  const rows = linkAggregatesStmt.all(req.user.id);
  const links = rows.map((row) => ({
    id: row.id,
    alias: row.alias,
    targetUrl: row.target_url,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    totalClicks: row.total_clicks,
    lastClick: row.last_click,
    shortUrl: `${BASE_URL}/r/${row.alias}`
  }));

  res.json({ links });
});

app.delete('/links/:id', authMiddleware, (req, res) => {
  const linkId = Number(req.params.id);
  if (!Number.isInteger(linkId)) {
    return res.status(400).json({ error: 'Invalid link id' });
  }

  const result = deleteLinkById.run(linkId, req.user.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Link not found' });
  }

  res.status(204).send();
});

app.get('/links/:id/stats', authMiddleware, (req, res) => {
  const linkId = Number(req.params.id);
  if (!Number.isInteger(linkId)) {
    return res.status(400).json({ error: 'Invalid link id' });
  }

  const link = findLinkById.get(linkId);
  if (!link || link.user_id !== req.user.id) {
    return res.status(404).json({ error: 'Link not found' });
  }

  const totalClicks = countClicksStmt.get(linkId).total;
  const lastClick = lastClickStmt.get(linkId).last_click;
  const topReferrers = topReferrersStmt.all(linkId).map((row) => ({
    referrer: row.referrer,
    total: row.total
  }));

  res.json({
    link: {
      id: link.id,
      alias: link.alias,
      targetUrl: link.target_url,
      expiresAt: link.expires_at,
      createdAt: link.created_at
    },
    stats: {
      totalClicks,
      lastClick,
      topReferrers
    }
  });
});

app.get('/r/:alias', (req, res) => {
  const { alias } = req.params;
  const link = findLinkByAlias.get(alias);
  if (!link) {
    return res.status(404).json({ error: 'Link not found' });
  }

  if (link.expires_at && new Date(link.expires_at).getTime() < Date.now()) {
    return res.status(410).json({ error: 'Link expired' });
  }

  const referrer = req.get('referer') || null;
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const userAgent = req.get('user-agent') || 'unknown';

  const ipHash = crypto.createHash('sha256').update(ip).digest('hex');
  const uaHash = crypto.createHash('sha256').update(userAgent).digest('hex');

  insertClickStmt.run(link.id, referrer, ipHash, uaHash);

  res.redirect(301, link.target_url);
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Unexpected error' });
});

app.listen(PORT, () => {
  console.log(`Backend listening on ${PORT}`);
});
