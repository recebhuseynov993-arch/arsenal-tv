const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'arsenal.db'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'DEV_ONLY_change_this_secret';
const IS_PROD = process.env.NODE_ENV === 'production';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function setAuthCookie(res, user) {
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 7*24*60*60*1000 });
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Daxil olmamisiniz.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Sessiya bitib. Yeniden daxil olun.' }); }
}

app.post('/api/register', (req, res) => {
  let { username, email, password, displayName } = req.body || {};
  username = (username || '').trim().toLowerCase();
  email = (email || '').trim().toLowerCase();
  displayName = (displayName || '').trim();
  if (!username || !email || !password) return res.status(400).json({ error: 'Butun xanalar mecburidir.' });
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'Istifadeci adi 3-20 simvol, herf/reqem/_ olmalidir.' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'E-poct duzgun deyil.' });
  if (password.length < 6) return res.status(400).json({ error: 'Sifre en azi 6 simvol olmalidir.' });
  if (!displayName) displayName = username;
  try {
    const hash = bcrypt.hashSync(password, 10);
    const info = db.prepare('INSERT INTO users (username,email,password,display_name) VALUES (?,?,?,?)').run(username, email, hash, displayName);
    setAuthCookie(res, { id: info.lastInsertRowid, username });
    res.json({ ok: true, user: { username, displayName } });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Bu istifadeci adi ve ya e-poct artiq var.' });
    res.status(500).json({ error: 'Server xetasi.' });
  }
});

app.post('/api/login', (req, res) => {
  let { login, password } = req.body || {};
  login = (login || '').trim().toLowerCase();
  if (!login || !password) return res.status(400).json({ error: 'Giris ve sifre mecburidir.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(login, login);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Giris ve ya sifre yanlisdir.' });
  setAuthCookie(res, user);
  res.json({ ok: true, user: { username: user.username, displayName: user.display_name } });
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT username,email,display_name,created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Istifadeci tapilmadi.' });
  res.json({ user: { username: user.username, email: user.email, displayName: user.display_name, createdAt: user.created_at } });
});

app.listen(PORT, () => console.log('ARSENAL TV server isleyir: port ' + PORT));
