const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');

const app = express();
const DB_PATH = path.join(__dirname, 'database.db');

// ── DATABASE SETUP ──────────────────────────────────────────────
let db;

async function initDB() {
  const SQL = await initSqlJs();

  // Load existing DB file if it exists, otherwise create fresh
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
    console.log('📂 Loaded existing database from', DB_PATH);
  } else {
    db = new SQL.Database();
    console.log('🆕 Created new database at', DB_PATH);
  }

  // Create tables if they don't exist
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      username  TEXT UNIQUE NOT NULL,
      email     TEXT UNIQUE NOT NULL,
      password  TEXT NOT NULL,
      createdAt TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS security_logs (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      type      TEXT NOT NULL,
      username  TEXT NOT NULL,
      ip        TEXT NOT NULL,
      status    TEXT NOT NULL,
      time      TEXT NOT NULL
    )
  `);

  saveDB();
  console.log('✅ Database ready\n');
}

// Save DB to disk after every write operation
function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Helper: find user by username
function findUser(username) {
  const result = db.exec(
    'SELECT * FROM users WHERE username = ?', [username]
  );
  if (!result.length || !result[0].values.length) return null;
  const [id, uname, email, password, createdAt] = result[0].values[0];
  return { id, username: uname, email, password, createdAt };
}

// Helper: check duplicate username or email
function userExists(username, email) {
  const result = db.exec(
    'SELECT id FROM users WHERE username = ? OR email = ?', [username, email]
  );
  return result.length > 0 && result[0].values.length > 0;
}

// Helper: insert user
function insertUser(username, email, hashedPassword) {
  db.run(
    'INSERT INTO users (username, email, password, createdAt) VALUES (?, ?, ?, ?)',
    [username, email, hashedPassword, new Date().toISOString()]
  );
  saveDB();
}

// Helper: insert log
function insertLog(type, username, ip, status) {
  db.run(
    'INSERT INTO security_logs (type, username, ip, status, time) VALUES (?, ?, ?, ?, ?)',
    [type, username, ip, status, new Date().toISOString()]
  );
  saveDB();
}

// Helper: get recent logs
function getRecentLogs(limit = 20) {
  const result = db.exec(
    `SELECT type, username, ip, status, time
     FROM security_logs
     ORDER BY id DESC
     LIMIT ?`, [limit]
  );
  if (!result.length) return [];
  return result[0].values.map(([type, username, ip, status, time]) =>
    ({ type, username, ip, status, time })
  );
}

// ── MIDDLEWARE ──────────────────────────────────────────────────
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'ssdlc-secure-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 1000 * 60 * 30 }
}));

// ── RATE LIMITING ───────────────────────────────────────────────
const attemptTracker = {};

function checkRateLimit(ip) {
  const now = Date.now();
  if (!attemptTracker[ip]) attemptTracker[ip] = [];
  attemptTracker[ip] = attemptTracker[ip].filter(t => now - t < 60000);
  return attemptTracker[ip].length >= 5;
}

function recordAttempt(ip) {
  if (!attemptTracker[ip]) attemptTracker[ip] = [];
  attemptTracker[ip].push(Date.now());
}

// ── ROUTES ──────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ── API: Register ───────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.json({ success: false, message: 'All fields are required.' });
  if (password.length < 8)
    return res.json({ success: false, message: 'Password must be at least 8 characters.' });
  if (userExists(username, email))
    return res.json({ success: false, message: 'Username or email already exists.' });

  const hashedPassword = await bcrypt.hash(password, 12);
  insertUser(username, email, hashedPassword);
  insertLog('REGISTER', username, req.ip, 'SUCCESS');

  res.json({ success: true, message: 'Account created successfully!' });
});

// ── API: Login ──────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (checkRateLimit(ip)) {
    insertLog('LOGIN', username, ip, 'BLOCKED');
    return res.json({ success: false, message: 'Too many attempts. Please wait 1 minute.' });
  }

  const user = findUser(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    recordAttempt(ip);
    insertLog('LOGIN', username || '(unknown)', ip, 'FAILED');
    return res.json({ success: false, message: 'Invalid username or password.' });
  }

  req.session.user = { username: user.username, email: user.email };
  insertLog('LOGIN', username, ip, 'SUCCESS');

  res.json({ success: true, message: 'Login successful!', redirect: '/dashboard' });
});

// ── API: Me ─────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.session.user });
});

// ── API: Logs ───────────────────────────────────────────────────
app.get('/api/logs', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  res.json(getRecentLogs(20));
});

// ── API: Logout ─────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ── START ───────────────────────────────────────────────────────
const PORT = 3000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ SSDLC Server running at http://localhost:${PORT}`);
    console.log(`💾 Database file: ${DB_PATH}`);
    console.log(`   Homepage:  http://localhost:${PORT}/`);
    console.log(`   Register:  http://localhost:${PORT}/register`);
    console.log(`   Login:     http://localhost:${PORT}/login`);
    console.log(`   Dashboard: http://localhost:${PORT}/dashboard\n`);
  });
});
