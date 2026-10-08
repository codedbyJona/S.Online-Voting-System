const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const dbPath = path.join(__dirname, 'data', 'voting.db');

function ensureDataFolder() {
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
}

function openDatabase() {
  ensureDataFolder();
  const db = new sqlite3.Database(dbPath);
  return db;
}

function initializeDatabase() {
  const db = openDatabase();
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      city TEXT NOT NULL,
      citizen_id TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      has_voted INTEGER DEFAULT 0,
      failed_attempts INTEGER DEFAULT 0,
      locked_until INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS candidates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      photo TEXT NOT NULL,
      vote_count INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS votes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      candidate_id INTEGER NOT NULL,
      timestamp INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(candidate_id) REFERENCES candidates(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      failed_attempts INTEGER DEFAULT 0,
      locked_until INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      description TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      ip_address TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )`);

    db.all(`SELECT key, value FROM settings WHERE key IN ('election_start','election_end')`, (err, rows) => {
      if (err) {
        console.error('Error checking election settings', err);
        return;
      }
      const settings = {};
      rows.forEach(row => { settings[row.key] = Number(row.value); });
      const now = Date.now();
      if (!settings.election_start || !settings.election_end || now >= settings.election_end) {
        const startTime = now;
        const endTime = startTime + 24 * 60 * 60 * 1000;
        if (!settings.election_start) {
          db.run(`INSERT INTO settings (key, value) VALUES (?, ?)`, ['election_start', String(startTime)]);
        } else {
          db.run(`UPDATE settings SET value = ? WHERE key = ?`, [String(startTime), 'election_start']);
        }
        if (!settings.election_end) {
          db.run(`INSERT INTO settings (key, value) VALUES (?, ?)`, ['election_end', String(endTime)]);
        } else {
          db.run(`UPDATE settings SET value = ? WHERE key = ?`, [String(endTime), 'election_end']);
        }
      }
    });

    db.get(`SELECT COUNT(*) as count FROM candidates`, (err, row) => {
      if (err) return console.error(err);
      if (!row || row.count === 0) {
        const candidates = [
          { name: 'Samira Patel', description: 'Experienced public policy leader with a focus on community safety.', photo: '/images/candidate1.svg' },
          { name: 'Miguel Alvarez', description: 'Technology-driven candidate advocating transparent governance.', photo: '/images/candidate2.svg' },
          { name: 'Priya Singh', description: 'Education reform champion committed to youth empowerment.', photo: '/images/candidate3.svg' },
          { name: 'Ethan Brooks', description: 'Veteran administrator with a strong integrity record.', photo: '/images/candidate4.svg' },
          { name: 'Amina Hassan', description: 'Healthcare strategist focused on efficient, secure services.', photo: '/images/candidate5.svg' },
          { name: 'Oliver Chen', description: 'Economic policy expert empowering local business growth.', photo: '/images/candidate6.svg' },
          { name: 'Lena Rossi', description: 'Environmental advocate promoting resilient, secure cities.', photo: '/images/candidate7.svg' },
          { name: 'Noah Johnson', description: 'Civil rights defender with a transparent accountability platform.', photo: '/images/candidate8.svg' },
          { name: 'Jade Kim', description: 'Smart governance innovator focused on citizen security.', photo: '/images/candidate9.svg' },
          { name: 'Daniela Costa', description: 'Experienced negotiator committed to fair institutional oversight.', photo: '/images/candidate10.svg' }
        ];
        const stmt = db.prepare(`INSERT INTO candidates (name, description, photo) VALUES (?, ?, ?)`);
        candidates.forEach(c => stmt.run(c.name, c.description, c.photo));
        stmt.finalize();
      }
    });

    db.get(`SELECT COUNT(*) as count FROM admins`, (err, row) => {
      if (err) return console.error(err);
      if (!row || row.count === 0) {
        const bcrypt = require('bcrypt');
        const password = 'Admin@2026!';
        bcrypt.hash(password, 12, (hashErr, password_hash) => {
          if (hashErr) return console.error(hashErr);
          db.run(`INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)`, ['admin', password_hash, Date.now()]);
          console.log('Admin user initialized with username: admin');
        });
      }
    });
  });
  return db;
}

module.exports = {
  openDatabase,
  initializeDatabase
};
