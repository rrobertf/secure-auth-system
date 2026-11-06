const { test } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { createApp } = require('../server');
const secret = 'test-only-secret-'.repeat(4);
function setup(t, options = {}) {
  const app = createApp({ databasePath: ':memory:', jwtSecret: secret, ...options });
  t.after(() => app.locals.db.close());
  return app;
}
const user = { username: 'Roberto', email: 'roberto@example.com', password: 'a secure passphrase' };

test('refuses to start without a strong signing secret', () => {
  for (const value of [undefined, '', 'short']) {
    assert.throws(() => createApp({ databasePath: ':memory:', jwtSecret: value }), /JWT_SECRET/);
  }
});
test('validates types, email, username and bcrypt byte limit before registration', async t => {
  const app = setup(t);
  for (const body of [{}, { ...user, email: {} }, { ...user, email: 'invalid' },
    { ...user, username: ' ' }, { ...user, password: 12345678 },
    { ...user, password: 'short' }, { ...user, password: 'é'.repeat(37) },
    { ...user, username: 'a'.repeat(81) }]) {
    const res = await request(app).post('/api/auth/register').send(body);
    assert.equal(res.status, 400, JSON.stringify(body));
  }
  assert.equal(app.locals.db.prepare('SELECT count(*) AS n FROM users').get().n, 0);
});
test('register/login/profile preserve response shape and never expose hash', async t => {
  const app = setup(t);
  const registered = await request(app).post('/api/auth/register').send(user);
  assert.equal(registered.status, 201);
  assert.equal(registered.body.user.role, 'user');
  assert.equal(registered.body.user.password, undefined);
  const row = app.locals.db.prepare('SELECT * FROM users').get();
  assert.notEqual(row.password, user.password);
  assert.ok(await bcrypt.compare(user.password, row.password));
  assert.equal((await request(app).post('/api/auth/register').send(user)).status, 409);
  const logged = await request(app).post('/api/auth/login').send(user);
  assert.equal(logged.status, 200);
  for (const path of ['me', 'profile']) {
    const res = await request(app).get(`/api/auth/${path}`).auth(logged.body.token, { type: 'bearer' });
    assert.equal(res.status, 200);
    assert.equal(res.body.user.email, user.email);
    assert.equal(res.body.user.password, undefined);
  }
});
test('bad credentials, malformed/expired tokens, and deleted users cannot authenticate', async t => {
  const app = setup(t);
  const registered = await request(app).post('/api/auth/register').send(user);
  for (const body of [{ email: user.email, password: 'wrong' }, { email: 'none@example.com', password: 'wrong' }]) {
    const res = await request(app).post('/api/auth/login').send(body);
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'Email o contraseña incorrectos');
  }
  const expired = jwt.sign({ id: 1 }, secret, { expiresIn: -1 });
  for (const header of ['', 'Basic abc', 'Bearer invalid', `Bearer ${expired}`]) {
    assert.equal((await request(app).get('/api/auth/me').set('Authorization', header)).status, 401);
  }
  app.locals.db.prepare('DELETE FROM users').run();
  assert.equal((await request(app).get('/api/auth/me').auth(registered.body.token, { type: 'bearer' })).status, 401);
});
test('legacy 6-character passwords still login without resetting users', async t => {
  const app = setup(t);
  app.locals.db.prepare('INSERT INTO users(username,email,password) VALUES(?,?,?)')
    .run('legacy', 'Legacy@Example.com', bcrypt.hashSync('old123', 10));
  const res = await request(app).post('/api/auth/login').send({ email: 'Legacy@Example.com', password: 'old123' });
  assert.equal(res.status, 200);
});
test('malformed JSON is a JSON 400; SQL errors are not leaked', async t => {
  const app = setup(t);
  const malformed = await request(app).post('/api/auth/login').set('Content-Type', 'application/json').send('{');
  assert.equal(malformed.status, 400);
  assert.match(malformed.headers['content-type'], /json/);
  app.locals.db.exec('DROP TABLE users');
  const res = await request(app).post('/api/auth/login').send(user);
  assert.equal(res.status, 500);
  assert.equal(res.body.error, 'Error interno del servidor');
});
test('restricts browser origins and throttles repeated auth attempts', async t => {
  const app = setup(t, { rateLimitMax: 2 });
  const cross = await request(app).get('/api/auth/me').set('Origin', 'https://untrusted.example');
  assert.equal(cross.headers['access-control-allow-origin'], undefined);
  const allowed = await request(app).get('/api/auth/me').set('Origin', 'http://localhost:3000');
  assert.equal(allowed.headers['access-control-allow-origin'], 'http://localhost:3000');
  for (let i = 0; i < 2; i++) await request(app).post('/api/auth/login').send({});
  assert.equal((await request(app).post('/api/auth/login').send({})).status, 429);
});
