const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { rateLimit } = require('express-rate-limit');
require('dotenv').config({ quiet: true });

function createApp({
  databasePath = process.env.DB_PATH || 'auth.db',
  jwtSecret = process.env.JWT_SECRET,
  allowedOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:3000',
  rateLimitMax = 30,
} = {}) {
  if (typeof jwtSecret !== 'string' || Buffer.byteLength(jwtSecret) < 32) {
    throw new Error('JWT_SECRET debe contener al menos 32 bytes aleatorios');
  }
  const app = express();
  const db = new Database(databasePath);
  app.locals.db = db;
  app.disable('x-powered-by');
  app.use(cors({ origin: (origin, callback) => callback(null, origin === allowedOrigin) }));
  app.use(express.json({ limit: '16kb' }));
  app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: rateLimitMax,
    standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: 'Demasiados intentos. Intenta de nuevo más tarde.' } });
  app.use(['/api/auth/register', '/api/auth/login'], limiter);
  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  const publicUser = user => ({ id: user.id, username: user.username, email: user.email, role: user.role });
  const sign = user => jwt.sign(publicUser(user), jwtSecret, { algorithm: 'HS256', expiresIn: '1h' });
  const validEmail = value => typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  const validPassword = (value, minimum) => typeof value === 'string' && value.length >= minimum && Buffer.byteLength(value, 'utf8') <= 72;
  // Equal bcrypt work for unknown users limits the obvious account-enumeration timing difference.
  const dummyHash = bcrypt.hashSync('not-a-real-account-password', 12);

  app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body || {};
    if (typeof username !== 'string' || username.trim().length < 2 || username.length > 80 ||
        !validEmail(email) || !validPassword(password, 8)) {
      return res.status(400).json({ error: 'Nombre de 2–80 caracteres, email válido y contraseña de al menos 8 caracteres (máximo 72 bytes) requeridos' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    try {
      const result = db.prepare('INSERT INTO users(username,email,password,role) VALUES(?,?,?,?)')
        .run(username.trim(), email, hashedPassword, 'user');
      const user = { id: Number(result.lastInsertRowid), username: username.trim(), email, role: 'user' };
      res.status(201).json({ message: 'Usuario registrado exitosamente', token: sign(user), user });
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'El usuario o email ya existe' });
      }
      throw error;
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body || {};
    if (!validEmail(email) || !validPassword(password, 1)) {
      return res.status(400).json({ error: 'Email y contraseña válidos requeridos' });
    }
    // Exact email matching preserves accounts created by the original version.
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    const matches = await bcrypt.compare(password, user ? user.password : dummyHash);
    if (!user || !matches) return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    res.json({ message: 'Login exitoso', token: sign(user), user: publicUser(user) });
  });

  function authenticate(req, res, next) {
    const match = /^Bearer ([^\s]+)$/i.exec(req.headers.authorization || '');
    if (!match) return res.status(401).json({ error: 'Token requerido' });
    let decoded;
    try {
      decoded = jwt.verify(match[1], jwtSecret, { algorithms: ['HS256'] });
    } catch {
      return res.status(401).json({ error: 'Token inválido o expirado' });
    }
    if (!Number.isSafeInteger(decoded.id)) return res.status(401).json({ error: 'Token inválido' });
    const user = db.prepare('SELECT id,username,email,role,created_at FROM users WHERE id=?').get(decoded.id);
    if (!user) return res.status(401).json({ error: 'Token inválido' });
    req.user = user;
    next();
  }
  app.get('/api/auth/me', authenticate, (req, res) => res.json({ user: publicUser(req.user) }));
  app.get('/api/auth/profile', authenticate, (req, res) => res.json({ user: req.user }));
  app.post('/api/auth/logout', (req, res) => res.json({ message: 'Logout exitoso. Token eliminado del cliente.' }));
  app.use((error, req, res, next) => {
    if (error.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
    if (error.type === 'entity.too.large') return res.status(413).json({ error: 'Solicitud demasiado grande' });
    res.status(500).json({ error: 'Error interno del servidor' });
  });
  return app;
}

if (require.main === module) {
  const app = createApp();
  const port = process.env.PORT || 5001;
  const server = app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
    server.close(() => { app.locals.db.close(); });
  });
}
module.exports = { createApp };
