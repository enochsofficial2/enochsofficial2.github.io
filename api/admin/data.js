const { requireSession, originIsSameSite, noStore } = require('../../lib/admin-auth');

function supabaseHeaders() {
  const key = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  // Supabase's new sb_secret_* API keys are not JWTs. Send the key only in
  // `apikey`; putting it in Authorization makes Supabase reject it as invalid.
  return { apikey: key, 'Content-Type': 'application/json' };
}

async function readTable(table, query) {
  const base = process.env.SUPABASE_URL;
  if (!base || !(process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY)) throw new Error('SUPABASE_ADMIN_ENV_MISSING');
  const response = await fetch(`${base}/rest/v1/${table}?${query}`, { headers: supabaseHeaders() });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error((body && body.message) || `SUPABASE_${table}_ERROR`);
  return body || [];
}

module.exports = async function handler(req, res) {
  noStore(res);
  if (!requireSession(req, res)) return;

  if (req.method === 'GET') {
    try {
      const [reservations, stats, referrers] = await Promise.all([
        readTable('reservations', 'select=*&order=created_at.desc&limit=500'),
        readTable('stats', 'select=date,uniq,pv,mobile_pv,pc_pv&order=date.desc&limit=31'),
        readTable('referrer_stats', 'select=date,source,pv&order=date.desc&limit=1000')
      ]);
      return res.status(200).json({ reservations, stats, referrers });
    } catch (error) {
      console.error('Admin data read failed:', error.message);
      return res.status(503).json({ error: '예약/방문 통계 DB를 읽지 못했습니다.', code: error.message === 'SUPABASE_ADMIN_ENV_MISSING' ? error.message : 'SUPABASE_QUERY_FAILED' });
    }
  }

  if (req.method === 'PATCH') {
    if (!originIsSameSite(req)) return res.status(403).json({ error: '요청 출처를 확인할 수 없습니다.' });
    const { id, status } = req.body || {};
    if (!/^[0-9a-f-]{36}$/i.test(String(id || '')) || !['접수대기', '예약완료'].includes(status)) {
      return res.status(400).json({ error: '잘못된 예약 상태 변경 요청입니다.' });
    }
    try {
      const base = process.env.SUPABASE_URL;
      if (!base || !(process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY)) throw new Error('SUPABASE_ADMIN_ENV_MISSING');
      const response = await fetch(`${base}/rest/v1/reservations?id=eq.${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { ...supabaseHeaders(), Prefer: 'return=representation' },
        body: JSON.stringify({ status })
      });
      if (!response.ok) throw new Error('SUPABASE_UPDATE_ERROR');
      return res.status(200).json({ ok: true });
    } catch (error) {
      console.error('Admin status update failed:', error.message);
      return res.status(503).json({ error: '예약 상태를 변경하지 못했습니다.', code: error.message === 'SUPABASE_ADMIN_ENV_MISSING' ? error.message : 'SUPABASE_UPDATE_FAILED' });
    }
  }

  res.setHeader('Allow', 'GET, PATCH');
  return res.status(405).json({ error: '허용되지 않은 요청입니다.' });
};
