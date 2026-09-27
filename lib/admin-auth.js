const crypto = require('node:crypto');

const COOKIE_NAME = 'hj_admin_session';
const SESSION_SECONDS = 8 * 60 * 60;

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function originIsSameSite(req) {
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (!origin || !host) return false;
  try {
    const parsed = new URL(origin);
    return parsed.host.toLowerCase() === host.toLowerCase() &&
      (parsed.protocol === 'https:' || parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');
  } catch (_) {
    return false;
  }
}

function sign(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET).update(encoded).digest('base64url');
  return encoded + '.' + signature;
}

function readSession(req) {
  const raw = req.headers.cookie || '';
  const pair = raw.split(';').map((part) => part.trim()).find((part) => part.startsWith(COOKIE_NAME + '='));
  if (!pair || !process.env.ADMIN_SESSION_SECRET) return null;
  const token = decodeURIComponent(pair.slice(COOKIE_NAME.length + 1));
  const [encoded, supplied] = token.split('.');
  if (!encoded || !supplied) return null;
  const expected = crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET).update(encoded).digest('base64url');
  if (!safeEqual(supplied, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!payload.email || payload.exp < Math.floor(Date.now() / 1000)) return null;
    if (payload.email !== String(process.env.ADMIN_EMAIL || '').toLowerCase()) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function setSession(res, email) {
  const token = sign({ email, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS });
  const secure = process.env.VERCEL ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly;${secure} SameSite=Strict; Path=/api/admin; Max-Age=${SESSION_SECONDS}`);
}

function clearSession(res) {
  const secure = process.env.VERCEL ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly;${secure} SameSite=Strict; Path=/api/admin; Max-Age=0`);
}

function requireSession(req, res) {
  const session = readSession(req);
  if (!session) {
    res.status(401).json({ error: '로그인이 필요합니다.' });
    return null;
  }
  return session;
}

function noStore(res) {
  res.setHeader('Cache-Control', 'no-store, private');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

module.exports = { COOKIE_NAME, SESSION_SECONDS, safeEqual, originIsSameSite, setSession, clearSession, readSession, requireSession, noStore };
