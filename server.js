const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const { openDatabase, initializeDatabase } = require('./db');
const { createToken, verifyToken, citizenAuth, adminAuth, loadElectionStatus } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 4000;

initializeDatabase();
const db = openDatabase();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cookieParser());
app.use((req, res, next) => {
  const token = req.cookies['voting_auth'];
  const payload = token ? verifyToken(token) : null;
  req.user = payload && payload.role === 'citizen' ? payload : null;
  res.locals.user = req.user;
  next();
});
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const csrfProtection = csrf({ cookie: true });

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many login attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
}

function logEvent(event_type, description, ip_address) {
  const timestamp = Date.now();
  const stmt = db.prepare(`INSERT INTO logs (event_type, description, timestamp, ip_address) VALUES (?, ?, ?, ?)`);
  stmt.run(event_type, description, timestamp, ip_address);
  stmt.finalize();
}

async function getElectionTiming() {
  const settings = await loadElectionStatus();
  const now = Date.now();
  const electionStart = settings.election_start || now;
  const electionEnd = settings.election_end || now + 24 * 60 * 60 * 1000;
  return {
    electionStart,
    electionEnd,
    remainingMs: Math.max(0, electionEnd - now),
    isClosed: now >= electionEnd
  };
}

function sanitizeString(value) {
  if (typeof value !== 'string') return '';
  return value.trim();
}

function cityOptions() {
  return ['Capital City', 'Harbor Town', 'Mountain Ridge', 'Desert Vale', 'Riverbend'];
}

app.get('/', async (req, res) => {
  const timing = await getElectionTiming();
  res.render('home', { timing, errors: [], success: null });
});

app.get('/register', csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  res.render('register', { csrfToken: req.csrfToken(), timing, errors: [], values: {}, cities: cityOptions(), success: null });
});

app.post('/register', csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  const firstName = sanitizeString(req.body.firstName);
  const lastName = sanitizeString(req.body.lastName);
  const city = sanitizeString(req.body.city);
  const citizenId = sanitizeString(req.body.citizenId).toUpperCase();
  const secretCode = sanitizeString(req.body.secretCode || '');
  const errors = [];

  if (!/^[A-Za-z]+$/.test(firstName)) errors.push('First name must contain only letters.');
  if (!/^[A-Za-z]+$/.test(lastName)) errors.push('Last name must contain only letters.');
  if (!cityOptions().includes(city)) errors.push('Please select a valid city.');
  if (!citizenId) errors.push('Citizen ID number is required.');
  if (secretCode.length < 8) errors.push('Secret code must be at least 8 characters long.');
  if (!/[A-Z]/.test(secretCode) || !/[a-z]/.test(secretCode) || !/[0-9]/.test(secretCode) || !/[!@#$%^&*()_+\-=\[\]{};:\\|,.<>\/?]+/.test(secretCode)) {
    errors.push('Secret code must include uppercase, lowercase, number, and special character.');
  }

  if (errors.length > 0) {
    return res.render('register', { csrfToken: req.csrfToken(), timing, errors, values: { firstName, lastName, city, citizenId }, cities: cityOptions(), success: null });
  }

  const now = Date.now();
  bcrypt.hash(secretCode, 12, (hashErr, password_hash) => {
    if (hashErr) {
      logEvent('registration_error', `Hash error for ${citizenId}`, getClientIp(req));
      return res.status(500).render('register', { csrfToken: req.csrfToken(), timing, errors: ['Internal error. Please try later.'], values: { firstName, lastName, city, citizenId }, cities: cityOptions(), success: null });
    }
    const stmt = db.prepare(`INSERT INTO users (first_name, last_name, city, citizen_id, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`);
    stmt.run(firstName, lastName, city, citizenId, password_hash, now, function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.render('register', { csrfToken: req.csrfToken(), timing, errors: ['Citizen ID must be unique.'], values: { firstName, lastName, city, citizenId }, cities: cityOptions(), success: null });
        }
        logEvent('registration_error', `Database error: ${err.message}`, getClientIp(req));
        return res.status(500).render('register', { csrfToken: req.csrfToken(), timing, errors: ['Internal error. Please try later.'], values: { firstName, lastName, city, citizenId }, cities: cityOptions(), success: null });
      }
      logEvent('registration', `New citizen registered: ${citizenId}`, getClientIp(req));
      res.render('register', { csrfToken: req.csrfToken(), timing, errors: [], values: {}, cities: cityOptions(), success: 'Registration completed. You may now log in.' });
    });
    stmt.finalize();
  });
});

app.get('/login', csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  const token = req.cookies['voting_auth'];
  const payload = token ? verifyToken(token) : null;
  if (payload && payload.role === 'citizen') {
    return res.redirect(timing.isClosed ? '/results' : '/vote');
  }
  res.render('login', { csrfToken: req.csrfToken(), timing, error: null, showCaptcha: false, values: { firstName: '', lastName: '', citizenId: '' } });
});

app.post('/login', loginLimiter, csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  const firstName = sanitizeString(req.body.firstName);
  const lastName = sanitizeString(req.body.lastName);
  const citizenId = sanitizeString(req.body.citizenId).toUpperCase();
  const secretCode = sanitizeString(req.body.secretCode || '');
  const captcha = sanitizeString(req.body.captcha || '');
  const values = { firstName, lastName, citizenId };

  db.get(`SELECT * FROM users WHERE UPPER(citizen_id) = ?`, [citizenId], (err, user) => {
    const now = Date.now();
    if (err) {
      logEvent('login_error', `DB error for login`, getClientIp(req));
      return res.render('login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials', showCaptcha: false, values });
    }
    if (!user || user.first_name.toLowerCase() !== firstName.toLowerCase() || user.last_name.toLowerCase() !== lastName.toLowerCase()) {
      logEvent('login_failure', `Failed login attempt for citizen_id: ${citizenId}`, getClientIp(req));
      return res.render('login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials', showCaptcha: false, values });
    }
    if (user.locked_until && now < user.locked_until) {
      return res.render('login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials', showCaptcha: false, values });
    }
    const requireCaptcha = user.failed_attempts >= 2;
    if (requireCaptcha && captcha.toLowerCase() !== 'secure') {
      return res.render('login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials', showCaptcha: true, values });
    }
    bcrypt.compare(secretCode, user.password_hash, (compareErr, isMatch) => {
      if (compareErr || !isMatch) {
        const failedAttempts = user.failed_attempts + 1;
        const lockedUntil = failedAttempts >= 3 ? now + 30 * 60 * 1000 : 0;
        db.run(`UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`, [failedAttempts, lockedUntil, user.id]);
        logEvent('login_failure', `Invalid credentials for citizen_id: ${citizenId}`, getClientIp(req));
        return res.render('login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials', showCaptcha: failedAttempts >= 2, values });
      }
      db.run(`UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?`, [user.id]);
      const token = createToken({
        id: user.id,
        citizen_id: user.citizen_id,
        first_name: user.first_name,
        last_name: user.last_name,
        role: 'citizen'
      });
      res.cookie('voting_auth', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 2 * 60 * 60 * 1000
      });
      logEvent('login', `Citizen login succeeded for ${citizenId}`, getClientIp(req));
      res.redirect('/vote');
    });
  });
});

app.post('/logout', citizenAuth, (req, res) => {
  res.clearCookie('voting_auth');
  logEvent('logout', `Citizen logged out: ${req.user.citizen_id}`, getClientIp(req));
  res.redirect('/');
});

app.get('/logout', citizenAuth, (req, res) => {
  res.clearCookie('voting_auth');
  logEvent('logout', `Citizen logged out: ${req.user.citizen_id}`, getClientIp(req));
  res.redirect('/login');
});

app.get('/vote', citizenAuth, csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  const now = Date.now();
  db.get(`SELECT has_voted FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.redirect('/login');
    db.all(`SELECT * FROM candidates ORDER BY id`, [], (candErr, candidates) => {
      if (candErr) return res.status(500).send('Server error');
      if (timing.isClosed) {
        return res.redirect('/results');
      }
      res.render('voting', { csrfToken: req.csrfToken(), timing, candidates, hasVoted: user.has_voted });
    });
  });
});

app.post('/vote', citizenAuth, csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  const candidateId = Number(req.body.candidateId);
  const ip = getClientIp(req);
  if (timing.isClosed) {
    return res.redirect('/results');
  }
  db.get(`SELECT has_voted FROM users WHERE id = ?`, [req.user.id], (userErr, user) => {
    if (userErr || !user) return res.redirect('/login');
    if (user.has_voted) {
      return res.render('vote-result', { timing, message: 'You have already voted.' });
    }
    db.get(`SELECT id FROM candidates WHERE id = ?`, [candidateId], (candErr, candidate) => {
      if (candErr || !candidate) {
        return res.status(400).render('vote-result', { timing, message: 'Invalid candidate selection.' });
      }
      const now = Date.now();
      const voteStmt = db.prepare(`INSERT INTO votes (user_id, candidate_id, timestamp) VALUES (?, ?, ?)`);
      voteStmt.run(req.user.id, candidateId, now, function(insertErr) {
        if (insertErr) return res.status(500).send('Unable to record vote.');
        db.run(`UPDATE candidates SET vote_count = vote_count + 1 WHERE id = ?`, [candidateId]);
        db.run(`UPDATE users SET has_voted = 1 WHERE id = ?`, [req.user.id]);
        logEvent('vote', `Citizen ${req.user.citizen_id} voted for candidate ${candidateId}`, ip);
        res.render('vote-result', { timing, message: 'Your vote has been successfully recorded.' });
      });
      voteStmt.finalize();
    });
  });
});

app.get('/results', async (req, res) => {
  const timing = await getElectionTiming();
  db.all(`SELECT * FROM candidates ORDER BY vote_count DESC, id`, [], (err, candidates) => {
    if (err) return res.status(500).send('Server error');
    const totalVotes = candidates.reduce((sum, c) => sum + c.vote_count, 0);
    const winner = candidates[0] || null;
    const rankings = candidates.map((candidate, index) => ({
      rank: index + 1,
      ...candidate,
      percentage: totalVotes ? ((candidate.vote_count / totalVotes) * 100).toFixed(1) : '0.0'
    }));
    res.render('results', { timing, rankings, winner, totalVotes });
  });
});

app.get('/admin/login', csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  res.render('admin-login', { csrfToken: req.csrfToken(), timing, error: null });
});

app.post('/admin/login', loginLimiter, csrfProtection, async (req, res) => {
  const timing = await getElectionTiming();
  const username = sanitizeString(req.body.username);
  const password = req.body.password || '';
  db.get(`SELECT * FROM admins WHERE username = ?`, [username], (err, admin) => {
    if (err) {
      logEvent('admin_login_error', `DB error`, getClientIp(req));
      return res.render('admin-login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials' });
    }
    if (!admin) {
      logEvent('admin_login_failure', `Invalid admin credentials`, getClientIp(req));
      return res.render('admin-login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials' });
    }
    const now = Date.now();
    if (admin.locked_until && now < admin.locked_until) {
      return res.render('admin-login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials' });
    }
    bcrypt.compare(password, admin.password_hash, (compareErr, isMatch) => {
      if (compareErr || !isMatch) {
        const failedAttempts = admin.failed_attempts + 1;
        const lockedUntil = failedAttempts >= 3 ? now + 30 * 60 * 1000 : 0;
        db.run(`UPDATE admins SET failed_attempts = ?, locked_until = ? WHERE id = ?`, [failedAttempts, lockedUntil, admin.id]);
        logEvent('admin_login_failure', `Invalid admin credentials for ${username}`, getClientIp(req));
        return res.render('admin-login', { csrfToken: req.csrfToken(), timing, error: 'Invalid credentials' });
      }
      db.run(`UPDATE admins SET failed_attempts = 0, locked_until = 0 WHERE id = ?`, [admin.id]);
      const token = createToken({ id: admin.id, username: admin.username, role: 'admin' });
      res.cookie('admin_auth', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 2 * 60 * 60 * 1000
      });
      logEvent('admin_login', `Admin ${username} logged in`, getClientIp(req));
      res.redirect('/admin/dashboard');
    });
  });
});

app.post('/admin/logout', adminAuth, (req, res) => {
  res.clearCookie('admin_auth');
  logEvent('admin_logout', `Admin ${req.admin.username} logged out`, getClientIp(req));
  res.redirect('/admin/login');
});

app.get('/admin/dashboard', adminAuth, async (req, res) => {
  const timing = await getElectionTiming();
  db.get(`SELECT COUNT(*) AS totalCitizens FROM users`, [], (err, citizenRow) => {
    if (err) return res.status(500).send('Server error');
    db.get(`SELECT COUNT(*) AS totalVotes FROM votes`, [], (voteErr, voteRow) => {
      if (voteErr) return res.status(500).send('Server error');
      db.all(`SELECT * FROM candidates ORDER BY vote_count DESC`, [], (candErr, candidates) => {
        if (candErr) return res.status(500).send('Server error');
        db.get(`SELECT COUNT(*) AS lockedAccounts FROM users WHERE failed_attempts >= 3`, [], (lockErr, lockedRow) => {
          if (lockErr) return res.status(500).send('Server error');
          res.render('admin-dashboard', {
            timing,
            stats: {
              totalCitizens: citizenRow.totalCitizens,
              totalVotes: voteRow.totalVotes,
              lockedAccounts: lockedRow.lockedAccounts
            },
            candidates
          });
        });
      });
    });
  });
});

app.get('/admin/logs', adminAuth, async (req, res) => {
  const timing = await getElectionTiming();
  db.all(`SELECT * FROM logs ORDER BY timestamp DESC LIMIT 200`, [], (err, logs) => {
    if (err) return res.status(500).send('Server error');
    const formattedLogs = logs.map(log => ({
      ...log,
      when: new Date(log.timestamp).toLocaleString()
    }));
    res.render('security-logs', { timing, logs: formattedLogs });
  });
});

app.get('/admin/export', adminAuth, (req, res) => {
  db.all(`SELECT u.first_name,u.last_name,u.city,u.citizen_id,c.name as candidate,v.timestamp FROM votes v JOIN users u ON v.user_id = u.id JOIN candidates c ON v.candidate_id = c.id ORDER BY v.timestamp`, [], (err, rows) => {
    if (err) return res.status(500).send('Server error');
    const csvHeaders = 'First Name,Last Name,City,Citizen ID,Candidate,Timestamp\n';
    const csv = rows.map(r => `${r.first_name},${r.last_name},${r.city},${r.citizen_id},${r.candidate},${new Date(r.timestamp).toISOString()}`).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="election-results.csv"');
    res.send(csvHeaders + csv);
  });
});

app.use((req, res) => {
  res.status(404).send('Page not found');
});

app.listen(PORT, () => {
  console.log(`Secure online voting system running on http://localhost:${PORT}`);
});
