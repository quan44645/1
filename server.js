require('dotenv').config();
const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// ─── EMAIL CONFIG ───
const EMAIL_USER = process.env.EMAIL_USER || 'quan44645@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || '';
const RESET_TOKEN_EXPIRY = 15 * 60 * 1000;

let transporter = null;
let emailEnabled = false;

// ─── RATE LIMITING ───
const rateLimits = new Map();
const RATE_WINDOW = 60 * 1000;
const RATE_MAX_REQUESTS = 60;
const AUTH_RATE_MAX = 10;

function rateLimiter(maxReq = RATE_MAX_REQUESTS) {
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    if (!rateLimits.has(key)) {
      rateLimits.set(key, []);
    }
    const hits = rateLimits.get(key).filter(t => now - t < RATE_WINDOW);
    if (hits.length >= maxReq) {
      return res.status(429).json({ error: 'Quá nhiều yêu cầu, vui lòng thử lại sau' });
    }
    hits.push(now);
    rateLimits.set(key, hits);
    next();
  };
}

// ─── INPUT VALIDATION ───
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.trim().replace(/[<>'"]/g, '');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function initEmailTransporter() {
  if (!EMAIL_PASS) {
    console.log('⚠️  EMAIL_PASS chưa cấu hình — gửi email bị tắt');
    return;
  }
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: EMAIL_USER, pass: EMAIL_PASS }
  });
  transporter.verify().then(() => {
    emailEnabled = true;
    console.log('📧 Email transporter sẵn sàng');
  }).catch(err => {
    emailEnabled = false;
    console.log('⚠️  Email transporter lỗi:', err.message);
  });
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(rateLimiter());

// ─── DATABASE ───
let db;
const DB_PATH = path.join(__dirname, 'database.sqlite');

// Helper: run parameterized query and return last inserted id
function dbRun(sql, params = []) {
  db.run(sql, params);
  const result = db.exec('SELECT last_insert_rowid()');
  return result.length ? result[0].values[0][0] : null;
}

// Helper: run query and return first row as object
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (!stmt.step()) {
    stmt.free();
    return null;
  }
  const cols = stmt.getColumnNames();
  const vals = stmt.get();
  stmt.free();
  const row = {};
  cols.forEach((c, i) => row[c] = vals[i]);
  return row;
}

// Helper: run query and return all rows as objects
function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    const row = {};
    cols.forEach((c, i) => row[c] = vals[i]);
    rows.push(row);
  }
  stmt.free();
  return rows;
}

async function initDatabase() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
    console.log('📂 Loaded existing database');
  } else {
    db = new SQL.Database();
    console.log('🆕 Created new database');
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT DEFAULT '',
      avatar TEXT DEFAULT 'default',
      created_at TEXT DEFAULT (datetime('now')),
      last_login TEXT DEFAULT NULL,
      is_active INTEGER DEFAULT 1
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS game_saves (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL UNIQUE,
      gold REAL DEFAULT 10,
      gems REAL DEFAULT 0,
      total_gold REAL DEFAULT 0,
      total_clicks INTEGER DEFAULT 0,
      click_power INTEGER DEFAULT 1,
      idle_mine INTEGER DEFAULT 0,
      depth_level INTEGER DEFAULT 0,
      depth_mul REAL DEFAULT 1,
      hatch_speed_level INTEGER DEFAULT 0,
      gem_chance REAL DEFAULT 0.02,
      breed_luck REAL DEFAULT 0,
      dragons_json TEXT DEFAULT '{}',
      custom_dragons_json TEXT DEFAULT '{}',
      upgrade_levels_json TEXT DEFAULT '{}',
      breeding_parent1 TEXT DEFAULT NULL,
      breeding_parent2 TEXT DEFAULT NULL,
      breed_start_time INTEGER DEFAULT 0,
      prestige_level INTEGER DEFAULT 0,
      prestige_mul REAL DEFAULT 1,
      last_tick TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (account_id) REFERENCES accounts(id)
    )
  `);

  // Migration: add prestige columns if missing
  try {
    db.run(`ALTER TABLE game_saves ADD COLUMN prestige_level INTEGER DEFAULT 0`);
  } catch (e) { /* column exists */ }
  try {
    db.run(`ALTER TABLE game_saves ADD COLUMN prestige_mul REAL DEFAULT 1`);
  } catch (e) { /* column exists */ }

  db.run(`
    CREATE TABLE IF NOT EXISTS achievements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL,
      achievement_key TEXT NOT NULL,
      unlocked_at TEXT DEFAULT (datetime('now')),
      UNIQUE(account_id, achievement_key),
      FOREIGN KEY (account_id) REFERENCES accounts(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS leaderboard_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL,
      total_gold REAL DEFAULT 0,
      total_dragons INTEGER DEFAULT 0,
      total_species INTEGER DEFAULT 0,
      total_clicks INTEGER DEFAULT 0,
      snapshot_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (account_id) REFERENCES accounts(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (account_id) REFERENCES accounts(id)
    )
  `);

  saveDbToDisk();
  console.log('✅ Database initialized');
  initEmailTransporter();
}

function saveDbToDisk() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// ─── AUTH MIDDLEWARE ───
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.username = decoded.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token không hợp lệ' });
  }
}

// ─── API: ĐĂNG KÝ ───
app.post('/api/register', rateLimiter(AUTH_RATE_MAX), async (req, res) => {
  try {
    const username = sanitize(req.body.username);
    const email = sanitize(req.body.email);
    const password = req.body.password;
    const display_name = sanitize(req.body.display_name || '');

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Thiếu thông tin: username, email, password' });
    }
    if (username.length < 3) return res.status(400).json({ error: 'Username phải >= 3 ký tự' });
    if (password.length < 6) return res.status(400).json({ error: 'Password phải >= 6 ký tự' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Email không hợp lệ' });

    const existing = dbGet(`SELECT id FROM accounts WHERE username = ? OR email = ?`, [username, email]);
    if (existing) {
      return res.status(400).json({ error: 'Username hoặc email đã tồn tại' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const dn = display_name || username;

    const userId = dbRun(
      `INSERT INTO accounts (username, email, password_hash, display_name) VALUES (?, ?, ?, ?)`,
      [username, email, password_hash, dn]
    );

    dbRun(`INSERT INTO game_saves (account_id) VALUES (?)`, [userId]);

    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '7d' });

    saveDbToDisk();
    res.json({
      success: true,
      message: 'Đăng ký thành công!',
      token,
      user: { id: userId, username, email, display_name: dn }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: ĐĂNG NHẬP ───
app.post('/api/login', rateLimiter(AUTH_RATE_MAX), async (req, res) => {
  try {
    const username = sanitize(req.body.username);
    const password = req.body.password;

    if (!username || !password) {
      return res.status(400).json({ error: 'Thiếu username và password' });
    }

    const user = dbGet(
      `SELECT id, username, email, password_hash, display_name, avatar FROM accounts WHERE username = ? AND is_active = 1`,
      [username]
    );

    if (!user) {
      return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Sai tài khoản hoặc mật khẩu' });

    dbRun(`UPDATE accounts SET last_login = datetime('now') WHERE id = ?`, [user.id]);

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    saveDbToDisk();
    res.json({
      success: true,
      message: 'Đăng nhập thành công!',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        avatar: user.avatar
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: QUÊN MẬT KHẨU ───
app.post('/api/forgot-password', rateLimiter(5), async (req, res) => {
  try {
    const email = sanitize(req.body.email);
    if (!email) return res.status(400).json({ error: 'Vui lòng nhập email' });

    const user = dbGet(
      `SELECT id, username, display_name FROM accounts WHERE email = ? AND is_active = 1`,
      [email]
    );

    if (!user) {
      return res.json({ success: true, message: 'Nếu email tồn tại, chúng tôi đã gửi link đặt lại mật khẩu' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRY).toISOString();

    dbRun(
      `INSERT INTO password_resets (account_id, token, expires_at) VALUES (?, ?, ?)`,
      [user.id, token, expiresAt]
    );

    const resetLink = `http://localhost:${PORT}/index.html?reset_token=${token}`;

    if (emailEnabled && transporter) {
      const mailOptions = {
        from: `"Idle Dragon Mining" <${EMAIL_USER}>`,
        to: email,
        subject: 'Đặt lại mật khẩu - Idle Dragon Mining Empire',
        html: `
          <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:20px;background:#1a0a2e;color:#e0e0e0;border-radius:15px;">
            <h2 style="text-align:center;color:#f7c948;">🐉 Đặt lại mật khẩu</h2>
            <p>Xin chào <strong>${user.display_name}</strong>,</p>
            <p>Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản <strong>${user.username}</strong>.</p>
            <p>Nhấn vào nút bên dưới để đặt lại mật khẩu (link hết hạn sau 15 phút):</p>
            <div style="text-align:center;margin:25px 0;">
              <a href="${resetLink}" style="display:inline-block;padding:14px 30px;background:linear-gradient(135deg,#ff6b35,#f7c948);color:#1a0a2e;text-decoration:none;border-radius:10px;font-weight:bold;font-size:16px;">Đặt lại mật khẩu</a>
            </div>
            <p style="color:#888;font-size:12px;">Nếu bạn không yêu cầu đặt lại mật khẩu, vui lòng bỏ qua email này.</p>
            <hr style="border-color:rgba(255,255,255,.1);">
            <p style="text-align:center;color:#555;font-size:11px;">Idle Dragon Mining Empire &copy; 2026</p>
          </div>
        `
      };

      try {
        await transporter.sendMail(mailOptions);
        saveDbToDisk();
        return res.json({ success: true, message: 'Nếu email tồn tại, chúng tôi đã gửi link đặt lại mật khẩu' });
      } catch (mailErr) {
        console.error('Send mail error:', mailErr.message);
      }
    }

    saveDbToDisk();
    res.json({
      success: true,
      message: 'Email chưa được cấu hình. Link đặt lại mật khẩu (hết hạn sau 15 phút):',
      reset_link: resetLink
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Lỗi khi xử lý yêu cầu' });
  }
});

// ─── API: ĐẶT LẠI MẬT KHẨU ───
app.post('/api/reset-password', rateLimiter(5), async (req, res) => {
  try {
    const token = sanitize(req.body.token);
    const new_password = req.body.new_password;

    if (!token || !new_password) return res.status(400).json({ error: 'Thiếu thông tin' });
    if (new_password.length < 6) return res.status(400).json({ error: 'Mật khẩu phải >= 6 ký tự' });

    const reset = dbGet(
      `SELECT id, account_id, expires_at FROM password_resets WHERE token = ? AND used = 0 ORDER BY created_at DESC LIMIT 1`,
      [token]
    );

    if (!reset) {
      return res.status(400).json({ error: 'Token không hợp lệ hoặc đã được sử dụng' });
    }

    if (new Date() > new Date(reset.expires_at)) {
      return res.status(400).json({ error: 'Token đã hết hạn, vui lòng yêu cầu lại' });
    }

    const passwordHash = await bcrypt.hash(new_password, 10);
    dbRun(`UPDATE accounts SET password_hash = ? WHERE id = ?`, [passwordHash, reset.account_id]);
    dbRun(`UPDATE password_resets SET used = 1 WHERE id = ?`, [reset.id]);

    saveDbToDisk();
    res.json({ success: true, message: 'Đặt lại mật khẩu thành công! Bạn có thể đăng nhập ngay.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: THÔNG TIN TÀI KHOẢN ───
app.get('/api/profile', authMiddleware, (req, res) => {
  try {
    const user = dbGet(
      `SELECT id, username, email, display_name, avatar, created_at, last_login FROM accounts WHERE id = ?`,
      [req.userId]
    );
    if (!user) return res.status(404).json({ error: 'Không tìm thấy tài khoản' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: CẬP NHẬT PROFILE ───
app.put('/api/profile', authMiddleware, (req, res) => {
  try {
    const display_name = req.body.display_name ? sanitize(req.body.display_name) : null;
    const avatar = req.body.avatar ? sanitize(req.body.avatar) : null;

    if (display_name) dbRun(`UPDATE accounts SET display_name = ? WHERE id = ?`, [display_name, req.userId]);
    if (avatar) dbRun(`UPDATE accounts SET avatar = ? WHERE id = ?`, [avatar, req.userId]);

    saveDbToDisk();
    res.json({ success: true, message: 'Cập nhật thành công!' });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: LƯU GAME ───
app.post('/api/save', authMiddleware, (req, res) => {
  try {
    const d = req.body;

    dbRun(`
      UPDATE game_saves SET
        gold = ?, gems = ?, total_gold = ?, total_clicks = ?,
        click_power = ?, idle_mine = ?, depth_level = ?, depth_mul = ?,
        hatch_speed_level = ?, gem_chance = ?, breed_luck = ?,
        dragons_json = ?, custom_dragons_json = ?, upgrade_levels_json = ?,
        breeding_parent1 = ?, breeding_parent2 = ?, breed_start_time = ?,
        prestige_level = ?, prestige_mul = ?,
        last_tick = datetime('now'), updated_at = datetime('now')
      WHERE account_id = ?
    `, [
      d.gold || 10, d.gems || 0, d.totalGold || 0, d.totalClicks || 0,
      d.clickPower || 1, d.idleMine || 0, d.depthLevel || 0, d.depthMul || 1,
      d.hatchSpeedLevel || 0, d.gemChance || 0.02, d.breedLuck || 0,
      JSON.stringify(d.dragons || {}), JSON.stringify(d.customDragons || {}),
      JSON.stringify(d.upgradeLevels || {}),
      d.breedParent1 ? JSON.stringify(d.breedParent1) : null,
      d.breedParent2 ? JSON.stringify(d.breedParent2) : null,
      d.breedStartTime || 0,
      d.prestigeLevel || 0, d.prestigeMul || 1,
      req.userId
    ]);

    // Cập nhật leaderboard
    const totalDragons = Object.values(d.dragons || {}).reduce((a, b) => a + b, 0)
      + Object.values(d.customDragons || {}).reduce((a, b) => a + (b.count || 0), 0);
    dbRun(
      `INSERT OR REPLACE INTO leaderboard_snapshots (account_id, total_gold, total_dragons, total_species, total_clicks) VALUES (?, ?, ?, ?, ?)`,
      [req.userId, d.totalGold || 0, totalDragons, Object.keys(d.customDragons || {}).length, d.totalClicks || 0]
    );

    // Check achievements server-side
    checkAndUnlockAchievements(req.userId, d);

    saveDbToDisk();
    res.json({ success: true, message: 'Đã lưu game!' });
  } catch (err) {
    console.error('Save error:', err);
    res.status(500).json({ error: 'Lỗi lưu game' });
  }
});

// ─── API: TẢI GAME ───
app.get('/api/load', authMiddleware, (req, res) => {
  try {
    const row = dbGet(`SELECT * FROM game_saves WHERE account_id = ?`, [req.userId]);
    if (!row) {
      return res.json({ exists: false });
    }

    res.json({
      exists: true,
      data: {
        gold: row.gold,
        gems: row.gems,
        totalGold: row.total_gold,
        totalClicks: row.total_clicks,
        clickPower: row.click_power,
        idleMine: row.idle_mine,
        depthLevel: row.depth_level,
        depthMul: row.depth_mul,
        hatchSpeedLevel: row.hatch_speed_level,
        gemChance: row.gem_chance,
        breedLuck: row.breed_luck,
        dragons: JSON.parse(row.dragons_json || '{}'),
        customDragons: JSON.parse(row.custom_dragons_json || '{}'),
        upgradeLevels: JSON.parse(row.upgrade_levels_json || '{}'),
        breedParent1: row.breeding_parent1 ? JSON.parse(row.breeding_parent1) : null,
        breedParent2: row.breeding_parent2 ? JSON.parse(row.breeding_parent2) : null,
        breedStartTime: row.breed_start_time,
        prestigeLevel: row.prestige_level || 0,
        prestigeMul: row.prestige_mul || 1,
        lastTick: row.last_tick
      }
    });
  } catch (err) {
    console.error('Load error:', err);
    res.status(500).json({ error: 'Lỗi tải game' });
  }
});

// ─── API: BẢNG XẾP HẠNG ───
app.get('/api/leaderboard', authMiddleware, (req, res) => {
  try {
    const data = dbAll(`
      SELECT a.username, a.display_name, a.avatar, l.total_gold, l.total_dragons, l.total_species, l.total_clicks
      FROM leaderboard_snapshots l
      JOIN accounts a ON a.id = l.account_id
      WHERE a.is_active = 1
      ORDER BY l.total_gold DESC
      LIMIT 20
    `);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: DANH SÁCH TÀI KHOẢN (admin) ───
app.get('/api/accounts', authMiddleware, (req, res) => {
  try {
    const data = dbAll(`
      SELECT id, username, email, display_name, avatar, created_at, last_login, is_active
      FROM accounts ORDER BY created_at DESC
    `);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: THỐNG KÊ DATABASE ───
app.get('/api/stats', authMiddleware, (req, res) => {
  try {
    const accounts = dbGet(`SELECT COUNT(*) as total FROM accounts`);
    const saves = dbGet(`SELECT COUNT(*) as total FROM game_saves`);
    const topGold = dbGet(`SELECT MAX(total_gold) as max FROM leaderboard_snapshots`);

    res.json({
      total_accounts: accounts?.total || 0,
      total_saves: saves?.total || 0,
      max_gold: topGold?.max || 0
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── ACHIEVEMENTS SYSTEM ───
const ACHIEVEMENT_DEFS = {
  first_click: { name: 'First Click!', emoji: '⛏️', desc: 'Click the mine for the first time' },
  click_100: { name: 'Clicker', emoji: '👆', desc: '100 total clicks' },
  click_1000: { name: 'Click Master', emoji: '🔥', desc: '1,000 total clicks' },
  click_10000: { name: 'Click Legend', emoji: '⚡', desc: '10,000 total clicks' },
  gold_1000: { name: 'Pocket Change', emoji: '💰', desc: 'Earn 1,000 total gold' },
  gold_1m: { name: 'Millionaire', emoji: '🤑', desc: 'Earn 1,000,000 total gold' },
  gold_1b: { name: 'Billionaire', emoji: '👑', desc: 'Earn 1,000,000,000 total gold' },
  first_dragon: { name: 'Dragon Tamer', emoji: '🐉', desc: 'Buy your first dragon' },
  dragons_10: { name: 'Dragon Army', emoji: '🐲', desc: 'Own 10 dragons total' },
  dragons_50: { name: 'Dragon Lord', emoji: '🦅', desc: 'Own 50 dragons total' },
  first_breed: { name: 'Breeder', emoji: '🥚', desc: 'Breed your first dragon' },
  first_gem: { name: 'Gem Finder', emoji: '💎', desc: 'Find your first gem' },
  gems_100: { name: 'Gem Collector', emoji: '💠', desc: 'Collect 100 gems' },
  depth_10: { name: 'Deep Digger', emoji: '🕳️', desc: 'Reach depth level 10' },
  first_prestige: { name: 'Rebirth', emoji: '🌟', desc: 'Prestige for the first time' },
  legendary_dragon: { name: 'Legendary!', emoji: '✨', desc: 'Own a legendary dragon' },
  dragons_100: { name: 'Dragon Emperor', emoji: '👑', desc: 'Own 100 dragons total' },
  breed_master: { name: 'Breed Master', emoji: '🧬', desc: 'Discover 5 bred species' },
  all_elements: { name: 'Elementalist', emoji: '🌈', desc: 'Own dragons of 8 different elements' }
};

function checkAndUnlockAchievements(userId, d) {
  const checks = [
    ['first_click', () => d.totalClicks >= 1],
    ['click_100', () => d.totalClicks >= 100],
    ['click_1000', () => d.totalClicks >= 1000],
    ['click_10000', () => d.totalClicks >= 10000],
    ['gold_1000', () => d.totalGold >= 1000],
    ['gold_1m', () => d.totalGold >= 1000000],
    ['gold_1b', () => d.totalGold >= 1000000000],
    ['first_dragon', () => Object.values(d.dragons || {}).some(c => c > 0)],
    ['dragons_10', () => Object.values(d.dragons || {}).reduce((a, b) => a + b, 0) >= 10],
    ['dragons_50', () => Object.values(d.dragons || {}).reduce((a, b) => a + b, 0) >= 50],
    ['first_breed', () => Object.keys(d.customDragons || {}).length > 0],
    ['first_gem', () => (d.gems || 0) >= 1],
    ['gems_100', () => (d.gems || 0) >= 100],
    ['depth_10', () => (d.depthLevel || 0) >= 10],
    ['first_prestige', () => (d.prestigeLevel || 0) >= 1],
    ['legendary_dragon', () => {
      const dragonDefs = ['celestial', 'void', 'cosmic', 'divine', 'eternal'];
      return dragonDefs.some(id => (d.dragons?.[id] || 0) > 0);
    }],
    ['dragons_100', () => Object.values(d.dragons || {}).reduce((a, b) => a + b, 0) >= 100],
    ['breed_master', () => Object.keys(d.customDragons || {}).length >= 5],
    ['all_elements', () => {
      const elements = new Set();
      const allDragons = [
        {id:'flame',element:'fire'},{id:'aqua',element:'water'},{id:'rocky',element:'earth'},
        {id:'leafy',element:'nature'},{id:'breeze',element:'wind'},{id:'sparky',element:'electric'},
        {id:'venom',element:'poison'},{id:'frosty',element:'ice'},{id:'shadow',element:'dark'},
        {id:'phoenix',element:'fire'},{id:'thunder',element:'electric'},{id:'kraken',element:'water'},
        {id:'crystal',element:'crystal'},{id:'ancient',element:'earth'},{id:'zephyr',element:'wind'},
        {id:'toxic',element:'poison'},{id:'celestial',element:'legendary'},{id:'radiant',element:'light'},
        {id:'void',element:'dark'},{id:'cosmic',element:'legendary'},{id:'divine',element:'light'},
        {id:'eternal',element:'legendary'}
      ];
      for (const dr of allDragons) {
        if ((d.dragons?.[dr.id] || 0) > 0) elements.add(dr.element);
      }
      return elements.size >= 8;
    }]
  ];

  for (const [key, check] of checks) {
    if (check()) {
      try {
        dbRun(
          `INSERT OR IGNORE INTO achievements (account_id, achievement_key) VALUES (?, ?)`,
          [userId, key]
        );
      } catch (e) { /* already unlocked */ }
    }
  }
}

// ─── API: ACHIEVEMENTS ───
app.get('/api/achievements', authMiddleware, (req, res) => {
  try {
    const unlocked = dbAll(
      `SELECT achievement_key, unlocked_at FROM achievements WHERE account_id = ?`,
      [req.userId]
    );
    const unlockedKeys = new Set(unlocked.map(a => a.achievement_key));

    const all = Object.entries(ACHIEVEMENT_DEFS).map(([key, def]) => ({
      key,
      ...def,
      unlocked: unlockedKeys.has(key),
      unlocked_at: unlocked.find(a => a.achievement_key === key)?.unlocked_at || null
    }));

    res.json({
      achievements: all,
      unlocked_count: unlocked.length,
      total_count: all.length
    });
  } catch (err) {
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── API: PRESTIGE ───
app.post('/api/prestige', authMiddleware, (req, res) => {
  try {
    const row = dbGet(`SELECT * FROM game_saves WHERE account_id = ?`, [req.userId]);
    if (!row) return res.status(400).json({ error: 'Không có save game' });

    const totalGold = row.total_gold || 0;
    if (totalGold < 1000000) {
      return res.status(400).json({ error: 'Cần ít nhất 1M total gold để prestige' });
    }

    const newPrestigeLevel = (row.prestige_level || 0) + 1;
    const newPrestigeMul = 1 + newPrestigeLevel * 0.25;

    dbRun(`
      UPDATE game_saves SET
        gold = 10, gems = 0, total_gold = 0, total_clicks = 0,
        click_power = 1, idle_mine = 0, depth_level = 0, depth_mul = 1,
        hatch_speed_level = 0, gem_chance = 0.02, breed_luck = 0,
        dragons_json = '{}', custom_dragons_json = '{}', upgrade_levels_json = '{}',
        breeding_parent1 = NULL, breeding_parent2 = NULL, breed_start_time = 0,
        prestige_level = ?, prestige_mul = ?,
        last_tick = datetime('now'), updated_at = datetime('now')
      WHERE account_id = ?
    `, [newPrestigeLevel, newPrestigeMul, req.userId]);

    // Keep leaderboard
    dbRun(
      `INSERT OR REPLACE INTO leaderboard_snapshots (account_id, total_gold, total_dragons, total_species, total_clicks) VALUES (?, 0, 0, 0, 0)`,
      [req.userId]
    );

    saveDbToDisk();
    res.json({
      success: true,
      message: `Prestige thành công! Cấp ${newPrestigeLevel} — Nhân x${newPrestigeMul.toFixed(2)}`,
      prestige_level: newPrestigeLevel,
      prestige_mul: newPrestigeMul
    });
  } catch (err) {
    console.error('Prestige error:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─── CLEANUP EXPIRED TOKENS ───
setInterval(() => {
  try {
    dbRun(`DELETE FROM password_resets WHERE datetime(expires_at) < datetime('now')`);
    // Cleanup old rate limit entries
    const now = Date.now();
    for (const [key, hits] of rateLimits.entries()) {
      const filtered = hits.filter(t => now - t < RATE_WINDOW);
      if (filtered.length === 0) rateLimits.delete(key);
      else rateLimits.set(key, filtered);
    }
  } catch (e) { /* ignore */ }
}, 5 * 60 * 1000);

// ─── START SERVER ───
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🐉 Idle Dragon Mining Empire Server`);
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`📊 Database: ${DB_PATH}`);
    if (process.env.JWT_SECRET) {
      console.log(`🔐 JWT: from environment`);
    } else {
      console.log(`⚠️  JWT: generated (set JWT_SECRET in .env for persistence)`);
    }
    console.log();
  });
}).catch(err => {
  console.error('Failed to init database:', err);
  process.exit(1);
});
