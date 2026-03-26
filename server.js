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

// ── PROGRESSIVE LOCKOUT ─────────────────────────────────────────
//
//  Attempt tier | Lockout duration  | What it means
//  -------------|-------------------|----------------------------
//   1 –  5      | No lockout        | Normal usage tolerance
//   6 – 10      | 1 minute          | Suspicious, slow them down
//  11 – 15      | 5 minutes         | Likely brute force
//  16 – 20      | 15 minutes        | Aggressive attacker
//  21+          | PERMANENT lock    | Must be manually unlocked
//
const lockoutTracker = {};
// { [ip]: { attempts: Number, lockedUntil: timestamp|null, permanent: bool } }

const LOCKOUT_TIERS = [
  { minAttempts:  6, maxAttempts: 10, durationMs:      60 * 1000, label: '1 minute'   },
  { minAttempts: 11, maxAttempts: 15, durationMs:  5 * 60 * 1000, label: '5 minutes'  },
  { minAttempts: 16, maxAttempts: 20, durationMs: 15 * 60 * 1000, label: '15 minutes' },
  { minAttempts: 21, maxAttempts: Infinity, durationMs: null,      label: 'PERMANENT'  },
];

function getLockoutTier(attempts) {
  return LOCKOUT_TIERS.find(t => attempts >= t.minAttempts && attempts <= t.maxAttempts) || null;
}

function getTracker(ip) {
  if (!lockoutTracker[ip]) {
    lockoutTracker[ip] = { attempts: 0, lockedUntil: null, permanent: false };
  }
  return lockoutTracker[ip];
}

// Returns { blocked: bool, message: string, remainingSecs: number|null }
function checkRateLimit(ip) {
  const tracker = getTracker(ip);
  const now = Date.now();

  // Permanently locked
  if (tracker.permanent) {
    return { blocked: true, message: 'Account permanently locked due to repeated attacks. Contact admin.', remainingSecs: null };
  }

  // Currently in a timed lockout
  if (tracker.lockedUntil && now < tracker.lockedUntil) {
    const remainingSecs = Math.ceil((tracker.lockedUntil - now) / 1000);
    const mins = Math.floor(remainingSecs / 60);
    const secs = remainingSecs % 60;
    const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
    return { blocked: true, message: `Too many failed attempts. Try again in ${timeStr}.`, remainingSecs };
  }

  // Lockout expired — clear the lock but keep attempt count
  if (tracker.lockedUntil && now >= tracker.lockedUntil) {
    tracker.lockedUntil = null;
  }

  return { blocked: false };
}

function recordAttempt(ip) {
  const tracker = getTracker(ip);
  tracker.attempts += 1;

  const tier = getLockoutTier(tracker.attempts);
  if (!tier) return; // under 6 attempts, no lockout yet

  if (tier.durationMs === null) {
    // Permanent lockout
    tracker.permanent = true;
    tracker.lockedUntil = null;
    console.log(`🔴 PERMANENT lockout applied to IP: ${ip} (${tracker.attempts} attempts)`);
  } else {
    // Timed lockout
    tracker.lockedUntil = Date.now() + tier.durationMs;
    console.log(`🟡 Lockout applied to IP: ${ip} — ${tier.label} (${tracker.attempts} attempts)`);
  }
}

// Returns lockout info for dashboard display
function getLockoutInfo(ip) {
  const tracker = getTracker(ip);
  const now = Date.now();
  return {
    ip,
    attempts: tracker.attempts,
    permanent: tracker.permanent,
    lockedUntil: tracker.lockedUntil,
    remainingSecs: tracker.lockedUntil ? Math.max(0, Math.ceil((tracker.lockedUntil - now) / 1000)) : 0,
    status: tracker.permanent ? 'PERMANENT' :
            tracker.lockedUntil && now < tracker.lockedUntil ? 'LOCKED' :
            tracker.attempts >= 6 ? 'WATCHING' : 'CLEAN'
  };
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

  // Check progressive lockout FIRST
  const lockout = checkRateLimit(ip);
  if (lockout.blocked) {
    const status = getTracker(ip).permanent ? 'PERMANENT' : 'BLOCKED';
    insertLog('LOGIN', username || '(unknown)', ip, status);
    return res.json({
      success: false,
      message: lockout.message,
      remainingSecs: lockout.remainingSecs,
      attempts: getTracker(ip).attempts
    });
  }

  const user = findUser(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    recordAttempt(ip);
    const tracker = getTracker(ip);
    const tier = getLockoutTier(tracker.attempts);
    insertLog('LOGIN', username || '(unknown)', ip, 'FAILED');

    // Tell the user their attempt count and next lockout threshold
    let hint = `Invalid username or password. (Attempt ${tracker.attempts})`;
    if (tracker.attempts === 5) hint += ' — Warning: next failure triggers lockout.';
    if (tier) hint = `${tier.permanent ? 'Account permanently locked.' : `Locked for ${tier.label}.`} (${tracker.attempts} attempts)`;

    return res.json({ success: false, message: hint, attempts: tracker.attempts });
  }

  // Successful login — reset attempt counter for this IP
  if (lockoutTracker[ip]) {
    lockoutTracker[ip] = { attempts: 0, lockedUntil: null, permanent: false };
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

// ── API: Lockout Status (for dashboard) ─────────────────────────
app.get('/api/lockouts', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const active = Object.keys(lockoutTracker)
    .map(ip => getLockoutInfo(ip))
    .filter(t => t.attempts > 0)
    .sort((a, b) => b.attempts - a.attempts);
  res.json(active);
});

// ── API: Unlock IP (admin action) ───────────────────────────────
app.post('/api/unlock', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { ip } = req.body;
  if (lockoutTracker[ip]) {
    lockoutTracker[ip] = { attempts: 0, lockedUntil: null, permanent: false };
    insertLog('UNLOCK', req.session.user.username, ip, 'UNLOCKED');
  }
  res.json({ success: true, message: `IP ${ip} has been unlocked.` });
});


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
