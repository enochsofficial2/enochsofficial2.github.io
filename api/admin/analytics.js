const crypto = require('node:crypto');
const { requireSession, noStore } = require('../../lib/admin-auth');

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

async function accessToken(credentials) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = base64url(JSON.stringify({
    iss: credentials.client_email,
    scope: 'https://www.googleapis.com/auth/analytics.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  }));
  const unsigned = `${header}.${claim}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const assertion = `${unsigned}.${signer.sign(credentials.private_key, 'base64url')}`;
  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion })
  });
  const tokenBody = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenBody.access_token) throw new Error('GA4_TOKEN_ERROR');
  return tokenBody.access_token;
}

async function runReport(token, propertyId, request) {
  const response = await fetch(`https://analyticsdata.googleapis.com/v1beta/properties/${encodeURIComponent(propertyId)}:runReport`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error('GA4_REPORT_ERROR');
  return body || {};
}

module.exports = async function handler(req, res) {
  noStore(res);
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: '허용되지 않은 요청입니다.' });
  }
  if (!requireSession(req, res)) return;

  let credentials;
  try { credentials = JSON.parse(process.env.GA4_SERVICE_ACCOUNT_JSON || ''); } catch (_) {}
  const propertyId = process.env.GA4_PROPERTY_ID;
  if (!propertyId || !credentials?.client_email || !credentials?.private_key) {
    return res.status(503).json({ connected: false, error: 'GA4 API 서비스 계정 자격증명이 설정되지 않았습니다.' });
  }

  try {
    const token = await accessToken(credentials);
    const common = { dateRanges: [{ startDate: '7daysAgo', endDate: 'today' }] };
    const [overview, days, sources, events] = await Promise.all([
      runReport(token, propertyId, { ...common, metrics: [
        { name: 'totalUsers' }, { name: 'sessions' }, { name: 'screenPageViews' },
        { name: 'averageEngagementTime' }, { name: 'engagementRate' }, { name: 'bounceRate' }
      ] }),
      runReport(token, propertyId, { ...common, dimensions: [{ name: 'date' }], metrics: [{ name: 'totalUsers' }, { name: 'sessions' }, { name: 'screenPageViews' }] }),
      runReport(token, propertyId, { ...common, dimensions: [{ name: 'sessionSourceMedium' }], metrics: [{ name: 'sessions' }, { name: 'totalUsers' }], limit: 10 }),
      runReport(token, propertyId, { ...common, dimensions: [{ name: 'eventName' }], metrics: [{ name: 'eventCount' }, { name: 'totalUsers' }], limit: 20 })
    ]);
    return res.status(200).json({ connected: true, overview, days, sources, events });
  } catch (_) {
    return res.status(502).json({ connected: false, error: 'GA4 보고서를 가져오지 못했습니다. API 권한과 속성 접근 권한을 확인해주세요.' });
  }
};
