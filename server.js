
'use strict';
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false }, maxHttpBufferSize: 1e5 });
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!TOKEN_SECRET || TOKEN_SECRET.length < 32) console.warn('WARNING: Set TOKEN_SECRET to a random secret of at least 32 characters.');
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) console.warn('WARNING: Set ADMIN_USERNAME and ADMIN_PASSWORD in deployment environment variables. Admin login will remain disabled.');
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadDB() {
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return { nextId: Number(d.nextId) || 100001, users: Array.isArray(d.users) ? d.users : [], transactions: Array.isArray(d.transactions) ? d.transactions : [] };
  } catch { return { nextId: 100001, users: [], transactions: [] }; }
}
let db = loadDB();
let saveChain = Promise.resolve();
function saveDB() {
  const snapshot = JSON.stringify(db, null, 2);
  saveChain = saveChain.then(async () => {
    const tmp = DB_FILE + '.tmp';
    await fs.promises.writeFile(tmp, snapshot, { mode: 0o600 });
    await fs.promises.rename(tmp, DB_FILE);
  });
  return saveChain;
}
const safeUser = u => ({ id: u.id, username: u.username, coins: u.coins, createdAt: u.createdAt });
const cleanName = n => String(n || '').trim().replace(/\s+/g, ' ').slice(0, 16);
const usernameOK = n => n.length >= 2 && n.length <= 16 && /^[\p{L}\p{N}_ ]+$/u.test(n);
const passwordHash = (p, salt) => new Promise((resolve, reject) => crypto.scrypt(p, salt, 64, (e, key) => e ? reject(e) : resolve(key.toString('hex'))));
function sign(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 864e5 })).toString('base64url');
  const secret = TOKEN_SECRET || crypto.createHash('sha256').update(__filename).digest('hex');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + sig;
}
function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.'); if (!body || !sig) return null;
  const secret = TOKEN_SECRET || crypto.createHash('sha256').update(__filename).digest('hex');
  const expected = crypto.createHmac('sha256', secret).update(body).digest();
  let actual; try { actual = Buffer.from(sig, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}
function bearer(req) { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? h.slice(7) : ''; }
function auth(req, res, next) {
  const p = verify(bearer(req)); if (!p || p.role !== 'user') return res.status(401).json({ error: 'نشست معتبر نیست؛ دوباره وارد حساب شو.' });
  const user = db.users.find(u => u.id === p.id); if (!user) return res.status(401).json({ error: 'حساب پیدا نشد.' });
  req.user = user; next();
}
function adminAuth(req, res, next) {
  const p = verify(bearer(req)); if (!p || p.role !== 'admin') return res.status(401).json({ error: 'ورود مدیر لازم است.' });
  next();
}
app.disable('x-powered-by'); app.use(express.json({ limit: '30kb' }));
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); next(); });
app.get('/health', (_req, res) => res.json({ ok: true }));
app.post('/api/register', async (req, res) => {
  try {
    const username = cleanName(req.body.username), password = String(req.body.password || '');
    if (!usernameOK(username)) return res.status(400).json({ error: 'نام کاربری باید ۲ تا ۱۶ حرف، عدد، فاصله یا زیرخط باشد.' });
    if (password.length < 6 || password.length > 128) return res.status(400).json({ error: 'رمز عبور باید بین ۶ تا ۱۲۸ نویسه باشد.' });
    if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'این نام کاربری قبلاً ثبت شده است.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHashHex = await passwordHash(password, salt);
    const user = { id: db.nextId++, username, salt, passwordHash: passwordHashHex, coins: 0, createdAt: new Date().toISOString() };
    db.users.push(user); await saveDB();
    res.status(201).json({ user: safeUser(user), token: sign({ role: 'user', id: user.id }) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ساخت حساب ناموفق بود.' }); }
});
app.post('/api/login', async (req, res) => {
  try {
    const username = cleanName(req.body.username), password = String(req.body.password || '');
    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user || !crypto.timingSafeEqual(Buffer.from(await passwordHash(password, user.salt), 'hex'), Buffer.from(user.passwordHash, 'hex'))) return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
    res.json({ user: safeUser(user), token: sign({ role: 'user', id: user.id }) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ورود ناموفق بود.' }); }
});
app.get('/api/me', auth, (req, res) => res.json({ user: safeUser(req.user) }));
app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) return res.status(503).json({ error: 'مدیر تنظیم نشده است؛ متغیرهای محیطی ADMIN_USERNAME و ADMIN_PASSWORD را تنظیم کن.' });
  const u = String(req.body.username || ''), p = String(req.body.password || '');
  const ok = u === ADMIN_USERNAME && p === ADMIN_PASSWORD;
  if (!ok) return res.status(401).json({ error: 'اطلاعات مدیر اشتباه است.' });
  res.json({ token: sign({ role: 'admin' }) });
});
app.get('/api/admin/users', adminAuth, (_req, res) => res.json({ users: db.users.map(safeUser) }));
app.get('/api/admin/transactions', adminAuth, (_req, res) => res.json({ transactions: db.transactions.slice(-500).reverse() }));
app.post('/api/admin/coins', adminAuth, async (req, res) => {
  try {
    const id = Number(req.body.userId), delta = Number(req.body.delta), note = String(req.body.note || '').trim().slice(0, 160);
    if (!Number.isSafeInteger(id) || !Number.isSafeInteger(delta) || delta === 0 || Math.abs(delta) > 1e9) return res.status(400).json({ error: 'شناسه و مقدار سکه معتبر نیست.' });
    const user = db.users.find(u => u.id === id); if (!user) return res.status(404).json({ error: 'بازیکن پیدا نشد.' });
    if (user.coins + delta < 0) return res.status(400).json({ error: 'موجودی بازیکن برای این کسر کافی نیست.' });
    const before = user.coins; user.coins += delta;
    const tx = { id: crypto.randomUUID(), userId: user.id, username: user.username, delta, before, after: user.coins, note: note || (delta > 0 ? 'افزایش سکه توسط مدیر' : 'کاهش سکه توسط مدیر'), createdAt: new Date().toISOString() };
    db.transactions.push(tx); await saveDB(); io.to('user:' + user.id).emit('account:coins', { coins: user.coins });
    res.json({ user: safeUser(user), transaction: tx });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ثبت تراکنش ناموفق بود.' }); }
});
app.use(express.static(__dirname, { extensions: ['html'] }));

// Lightweight realtime rooms: syncs player positions/avatars, not authoritative weapon damage.
const rooms = new Map();
function emitRoom(code) { const r = rooms.get(code); if (r) io.to(code).emit('room:players', { code, players: [...r.values()] }); }
io.use((socket, next) => { const p = verify(socket.handshake.auth && socket.handshake.auth.token); if (!p || p.role !== 'user') return next(new Error('لطفاً دوباره وارد حساب شو.')); const user = db.users.find(u => u.id === p.id); if (!user) return next(new Error('حساب پیدا نشد.')); socket.user = safeUser(user); next(); });
io.on('connection', socket => {
  socket.join('user:' + socket.user.id);
  const leave = () => { const code = socket.data.room; if (!code) return; const r = rooms.get(code); if (r) { r.delete(socket.id); if (!r.size) rooms.delete(code); else emitRoom(code); } socket.leave(code); socket.data.room = null; socket.emit('room:left'); };
  socket.on('room:create', data => {
    leave(); let code; do { code = crypto.randomBytes(3).toString('hex').toUpperCase(); } while (rooms.has(code));
    rooms.set(code, new Map([[socket.id, { id: socket.id, userId: socket.user.id, name: socket.user.username, x: 0, y: 1.6, z: 6, yaw: 0, pitch: 0, playing: false }]]));
    socket.data.room = code; socket.join(code); socket.emit('room:joined', { code, players: 1 }); emitRoom(code);
  });
  socket.on('room:join', data => {
    const code = String(data && data.code || '').toUpperCase(); const r = rooms.get(code);
    if (!r) return socket.emit('room:error', { message: 'این اتاق پیدا نشد؛ کد را بررسی کن.' });
    if (r.size >= 8) return socket.emit('room:error', { message: 'این اتاق پر است (حداکثر ۸ بازیکن).' });
    leave(); r.set(socket.id, { id: socket.id, userId: socket.user.id, name: socket.user.username, x: 0, y: 1.6, z: 6, yaw: 0, pitch: 0, playing: false });
    socket.data.room = code; socket.join(code); socket.emit('room:joined', { code, players: r.size }); emitRoom(code);
  });
  socket.on('player:update', d => {
    const code = socket.data.room, r = code && rooms.get(code), p = r && r.get(socket.id); if (!p || !d) return;
    const num = (v, fallback=0) => Number.isFinite(Number(v)) ? Math.max(-1000, Math.min(1000, Number(v))) : fallback;
    p.x = num(d.x); p.y = num(d.y, 1.6); p.z = num(d.z); p.yaw = num(d.yaw); p.pitch = Math.max(-1.5, Math.min(1.5, num(d.pitch))); p.playing = !!d.playing;
    emitRoom(code);
  });
  socket.on('disconnect', leave);
});
server.listen(PORT, '0.0.0.0', () => console.log(`Operation Night server listening on ${PORT}`));
