const crypto = require('node:crypto');
const { safeEqual, originIsSameSite, setSession, clearSession, readSession, noStore } = require('../../lib/admin-auth');

const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 8;

function allowed(ip) {
  const now = Date.now();
  const current = attempts.get(ip);
  if (!current || current.until <= now) {
    attempts.set(ip, { count: 0, until: now + WINDOW_MS });
    return true;
  }
  return current.count < MAX_ATTEMPTS;
}

module.exports = async function handler(req, res) {
  noStore(res);

  if (req.method === 'GET') {
    return res.status(readSession(req) ? 200 : 401).json({ authenticated: !!readSession(req) });
  }

  if (req.method === 'DELETE') {
    if (!originIsSameSite(req)) return res.status(403).json({ error: '요청 출처를 확인할 수 없습니다.' });
    clearSession(res);
    return res.status(200).json({ ok: true });
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST, DELETE');
    return res.status(405).json({ error: '허용되지 않은 요청입니다.' });
  }
  if (!originIsSameSite(req)) return res.status(403).json({ error: '요청 출처를 확인할 수 없습니다.' });
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_SESSION_SECRET) {
    return res.status(503).json({ error: '관리자 로그인 환경 변수가 설정되지 않았습니다.' });
  }

  const ip = String(req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
  if (!allowed(ip)) return res.status(429).json({ error: '로그인 시도가 많습니다. 잠시 후 다시 시도해주세요.' });

  const body = req.body || {};
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const expectedEmail = String(process.env.ADMIN_EMAIL).trim().toLowerCase();
  const credentialsMatch = safeEqual(email, expectedEmail) && safeEqual(password, process.env.ADMIN_PASSWORD);

  if (!credentialsMatch) {
    const current = attempts.get(ip) || { count: 0, until: Date.now() + WINDOW_MS };
    current.count += 1;
    attempts.set(ip, current);
    await new Promise((resolve) => setTimeout(resolve, 350));
    return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
  }

  attempts.delete(ip);
  setSession(res, expectedEmail);
  return res.status(200).json({ ok: true });
};
