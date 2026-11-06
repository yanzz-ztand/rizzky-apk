// Rizky Database — server token untuk Rizzxy Store (Vercel Serverless + Upstash Redis)
//   POST /api?op=verify  {token, device}      -> dipanggil oleh APK
//   POST /api?op=admin   header x-admin-key   -> dipakai halaman admin (index.html)
const crypto = require('crypto');

const DB_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const DB_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const HASH = 'rzx:tokens';
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const DAY = 86400000;

async function db(cmd) {
  if (!DB_URL || !DB_TOKEN) throw new Error('Database belum tersambung (Storage > Upstash Redis)');
  const r = await fetch(DB_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + DB_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const norm = (s) => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const int = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };
const clamp = (n, a, b) => Math.min(b, Math.max(a, n));

function genCode() {
  let s = '';
  for (const x of crypto.randomBytes(12)) s += ALPHA[x % 32];
  return 'RZX-' + s.match(/.{4}/g).join('-');
}

function ipOf(req) {
  return String(req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || 'ip')
    .split(',')[0].trim();
}

// batas permintaan per menit per IP
async function overLimit(req, bucket, max) {
  const key = 'rzx:rl:' + bucket + ':' + ipOf(req);
  const n = await db(['INCR', key]);
  if (n === 1) await db(['EXPIRE', key, 60]);
  return n > max;
}

function statusOf(t, now) {
  if (t.revoked) return 'nonaktif';
  if (t.exp && now > t.exp) return 'kedaluwarsa';
  return 'aktif';
}

// ===== dipanggil APK =====
async function verify(req, res, body) {
  if (await overLimit(req, 'v', 30)) {
    return res.status(429).json({ ok: false, temp: true, reason: 'Terlalu banyak percobaan, coba lagi 1 menit lagi' });
  }
  const key = norm(body.token);
  const dev = String(body.device || '').slice(0, 40);
  if (!key || key.length > 64 || !dev) return res.status(200).json({ ok: false, reason: 'Token salah' });

  const raw = await db(['HGET', HASH, key]);
  if (!raw) return res.status(200).json({ ok: false, reason: 'Token salah' });
  const t = JSON.parse(raw);
  const now = Date.now();
  if (t.revoked) return res.status(200).json({ ok: false, reason: 'Token dinonaktifkan' });
  if (t.exp && now > t.exp) return res.status(200).json({ ok: false, reason: 'Token kedaluwarsa' });

  t.devices = t.devices || [];
  if (!t.devices.includes(dev)) {
    if (t.maxDevices > 0 && t.devices.length >= t.maxDevices) {
      return res.status(200).json({
        ok: false,
        reason: 'Token sudah dipakai di perangkat lain (batas ' + t.maxDevices + ' perangkat)',
      });
    }
    t.devices.push(dev);
  }
  t.uses = (t.uses || 0) + 1;
  t.lastUsed = now;
  await db(['HSET', HASH, key, JSON.stringify(t)]);
  return res.status(200).json({ ok: true, exp: t.exp || 0, now });
}

// ===== dipakai halaman admin =====
function authed(req) {
  const want = String(process.env.ADMIN_KEY || '');
  if (!want) return null;
  const a = crypto.createHash('sha256').update(String(req.headers['x-admin-key'] || '')).digest();
  const b = crypto.createHash('sha256').update(want).digest();
  return crypto.timingSafeEqual(a, b);
}

async function admin(req, res, body) {
  if (!process.env.ADMIN_KEY) {
    return res.status(500).json({ ok: false, reason: 'ADMIN_KEY belum diisi di Environment Variables Vercel' });
  }
  const failKey = 'rzx:rl:af:' + ipOf(req);
  const fails = int(await db(['GET', failKey]), 0);
  if (fails >= 10) return res.status(429).json({ ok: false, reason: 'Terlalu banyak salah, tunggu 10 menit' });
  if (!authed(req)) {
    const n = await db(['INCR', failKey]);
    if (n === 1) await db(['EXPIRE', failKey, 600]);
    return res.status(401).json({ ok: false, reason: 'Admin key salah' });
  }

  const now = Date.now();
  const action = String(body.action || '');
  const load = async (code) => {
    const raw = await db(['HGET', HASH, norm(code)]);
    return raw ? JSON.parse(raw) : null;
  };
  const save = (t) => db(['HSET', HASH, norm(t.code), JSON.stringify(t)]);
  const view = (t) => Object.assign({}, t, { status: statusOf(t, now) });

  if (action === 'list') {
    const arr = (await db(['HGETALL', HASH])) || [];
    const out = [];
    for (let i = 1; i < arr.length; i += 2) {
      try { out.push(view(JSON.parse(arr[i]))); } catch (e) { /* abaikan data rusak */ }
    }
    out.sort((a, b) => b.created - a.created);
    return res.status(200).json({ ok: true, now, tokens: out });
  }

  if (action === 'create') {
    const count = clamp(int(body.count, 1), 1, 100);
    const days = clamp(int(body.days, 0), 0, 3650);
    const maxDevices = clamp(int(body.maxDevices, 1), 0, 1000);
    const note = String(body.note || '').slice(0, 80);
    const exp = days > 0 ? now + days * DAY : 0;
    const base = { note, created: now, exp, maxDevices, devices: [], revoked: false, uses: 0, lastUsed: 0 };
    const made = [];
    const custom = norm(body.custom);
    if (String(body.custom || '').trim()) {
      if (custom.length < 4 || custom.length > 40) {
        return res.status(400).json({ ok: false, reason: 'Kode custom 4-40 huruf/angka' });
      }
      if (await db(['HEXISTS', HASH, custom])) {
        return res.status(400).json({ ok: false, reason: 'Kode itu sudah ada' });
      }
      const t = Object.assign({ code: String(body.custom).trim().toUpperCase().slice(0, 40) }, base);
      await save(t);
      made.push(t.code);
    } else {
      for (let i = 0; i < count; i++) {
        let code;
        do { code = genCode(); } while (await db(['HEXISTS', HASH, norm(code)]));
        await save(Object.assign({ code }, base));
        made.push(code);
      }
    }
    return res.status(200).json({ ok: true, made, exp });
  }

  if (action === 'update') {
    const t = await load(body.code);
    if (!t) return res.status(404).json({ ok: false, reason: 'Token tidak ada' });
    if (typeof body.revoked === 'boolean') t.revoked = body.revoked;
    if (body.permanent === true) t.exp = 0;
    if (body.extendDays !== undefined) {
      const d = clamp(int(body.extendDays, 0), 1, 3650);
      const from = t.exp && t.exp > now ? t.exp : now;
      t.exp = from + d * DAY;
    }
    if (body.maxDevices !== undefined) t.maxDevices = clamp(int(body.maxDevices, 1), 0, 1000);
    if (body.resetDevices === true) t.devices = [];
    if (body.note !== undefined) t.note = String(body.note).slice(0, 80);
    await save(t);
    return res.status(200).json({ ok: true, token: view(t) });
  }

  if (action === 'delete') {
    await db(['HDEL', HASH, norm(body.code)]);
    return res.status(200).json({ ok: true });
  }

  return res.status(400).json({ ok: false, reason: 'action tidak dikenal' });
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const op = String((req.query && req.query.op) || '');
  try {
    if (req.method !== 'POST') return res.status(200).json({ ok: true, service: 'rizky-database' });
    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = {}; } }
    body = body || {};
    if (op === 'verify') return await verify(req, res, body);
    if (op === 'admin') return await admin(req, res, body);
    return res.status(400).json({ ok: false, reason: 'op tidak dikenal' });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      temp: true,
      reason: op === 'admin' ? String((e && e.message) || e) : 'Server bermasalah, coba lagi',
    });
  }
};
