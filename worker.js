// Etcetera /10 : comptes et classement (Cloudflare Pages Functions + D1)
// Liaison D1 attendue : DB
const ITER = 20000;          // itérations PBKDF2 (le plan gratuit limite le temps de calcul)
const CAP_DAY = 3000;        // XP maximale créditée au classement par jour
const FIRST_MAX = 30000;     // XP initiale acceptée à la première synchronisation
const TOP = 50;              // taille du classement affiché
const SESSION_DAYS = 90;

const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const now = () => Math.floor(Date.now() / 1000);
const sha = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const safeEq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
async function pbk(pw, salt, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: iter }, key, 256));
}
async function mkHash(pw) { const salt = rnd(16); return { salt, hash: 'pbkdf2$' + ITER + '$' + await pbk(pw, salt, ITER) }; }
async function check(pw, salt, stored) { const p = String(stored).split('$'); return safeEq(await pbk(pw, salt, +p[1] || ITER), p[2] || ''); }
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const err = (m, s = 400) => json({ error: m }, s);
const parisDay = () => new Intl.DateTimeFormat('fr-CA', { timeZone: 'Europe/Paris' }).format(new Date());
const weekKey = () => { const d = new Date(parisDay() + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() - (d.getUTCDay() + 6) % 7); return d.toISOString().slice(0, 10); };
const lvlOf = xp => Math.floor((1 + Math.sqrt(1 + xp / 12.5)) / 2);
const NAME_RE = /^[\p{L}\p{N}_.\-]{3,16}$/u;
const normRec = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
function newRecovery() {
  const al = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789', b = crypto.getRandomValues(new Uint8Array(12));
  const c = [...b].map(x => al[x % al.length]).join('');
  return c.slice(0, 4) + '-' + c.slice(4, 8) + '-' + c.slice(8, 12);
}
async function limited(db, key, max, win) {
  const r = await db.prepare('SELECT n, t FROM attempts WHERE key = ?').bind(key).first();
  return !!r && now() - r.t < win && r.n >= max;
}
async function bump(db, key, win) {
  const t = now();
  await db.prepare('INSERT INTO attempts (key, n, t) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET n = CASE WHEN ? - t >= ? THEN 1 ELSE n + 1 END, t = CASE WHEN ? - t >= ? THEN ? ELSE t END')
    .bind(key, t, t, win, t, win, t).run();
}
const clear = (db, key) => db.prepare('DELETE FROM attempts WHERE key = ?').bind(key).run();
async function newSession(db, uid) {
  const tok = rnd(32), t = now();
  await db.prepare('INSERT INTO sessions (token_hash, user_id, created) VALUES (?, ?, ?)').bind(await sha(tok), uid, t).run();
  if (Math.random() < .1) await db.prepare('DELETE FROM sessions WHERE created < ?').bind(t - SESSION_DAYS * 86400).run();
  return tok;
}
function tokenOf(req) { const h = req.headers.get('authorization') || ''; return h.startsWith('Bearer ') ? h.slice(7) : ''; }
async function auth(db, req) {
  const t = tokenOf(req); if (t.length < 20) return null;
  const s = await db.prepare('SELECT user_id, created FROM sessions WHERE token_hash = ?').bind(await sha(t)).first();
  if (!s || now() - s.created > SESSION_DAYS * 86400) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').bind(s.user_id).first();
}
const pub = u => ({ username: u.display, xp: u.xp, level: u.level, show: !!u.show_rank });
const ipOf = req => req.headers.get('cf-connecting-ip') || 'x';

async function scoreOf(db, u, week) {
  const wk = weekKey();
  const score = week ? (u.week_key === wk ? u.week_xp : 0) : u.xp;
  if (!u.show_rank) return { name: u.display, score, rank: null, hidden: true };
  let q, args;
  if (week) { q = 'SELECT COUNT(*) AS c FROM users WHERE show_rank = 1 AND week_key = ? AND week_xp > ?'; args = [wk, score]; }
  else { q = 'SELECT COUNT(*) AS c FROM users WHERE show_rank = 1 AND xp > ?'; args = [score]; }
  const r = await db.prepare(q).bind(...args).first();
  return { name: u.display, score, rank: score > 0 ? r.c + 1 : null, hidden: false };
}

async function onRequest({ request, env, params }) {
  const db = env.DB;
  if (!db) return err('Base de données non reliée (liaison D1 « DB » manquante).', 500);
  const route = [].concat(params.route || []).join('/');
  const url = new URL(request.url), method = request.method;
  let body = {};
  if (method === 'POST') {
    const txt = await request.text();
    if (txt.length > 400000) return err('Requête trop volumineuse.', 413);
    try { body = JSON.parse(txt || '{}'); } catch (e) { return err('Requête invalide.'); }
  }
  try {
    if (route === 'register' && method === 'POST') {
      const username = String(body.username || '').trim(), pw = String(body.password || '');
      if (!NAME_RE.test(username)) return err('Identifiant : 3 à 16 caractères (lettres, chiffres, _ - .).');
      if (pw.length < 6 || pw.length > 100) return err('Mot de passe : au moins 6 caractères.');
      const ipk = 'reg:' + ipOf(request);
      if (await limited(db, ipk, 8, 3600)) return err('Trop de créations de compte depuis cet appareil, réessaie plus tard.', 429);
      if (await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()) return err('Cet identifiant est déjà pris.', 409);
      const p = await mkHash(pw), rec = newRecovery(), r = await mkHash(normRec(rec));
      const res = await db.prepare('INSERT INTO users (username, display, salt, hash, rsalt, rhash, created) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(username, username, p.salt, p.hash, r.salt, r.hash, now()).run();
      await bump(db, ipk, 3600);
      const u = await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      return json({ token: await newSession(db, u.id), user: pub(u), recovery: rec });
    }
    if (route === 'login' && method === 'POST') {
      const username = String(body.username || '').trim(), pw = String(body.password || '');
      const k1 = 'login:' + username.toLowerCase(), k2 = 'ip:' + ipOf(request);
      if (await limited(db, k1, 8, 600) || await limited(db, k2, 40, 600)) return err('Trop d’essais, réessaie dans quelques minutes.', 429);
      const u = username ? await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first() : null;
      const ok = u ? await check(pw, u.salt, u.hash) : (await pbk(pw, 'x', ITER), false);
      if (!ok) { await bump(db, k1, 600); await bump(db, k2, 600); return err('Identifiant ou mot de passe incorrect.', 401); }
      await clear(db, k1);
      return json({ token: await newSession(db, u.id), user: pub(u), data: u.data || null });
    }
    if (route === 'recover' && method === 'POST') {
      const username = String(body.username || '').trim(), pw = String(body.password || '');
      if (pw.length < 6 || pw.length > 100) return err('Nouveau mot de passe : au moins 6 caractères.');
      const k = 'rec:' + username.toLowerCase();
      if (await limited(db, k, 5, 3600)) return err('Trop d’essais, réessaie plus tard.', 429);
      const u = username ? await db.prepare('SELECT * FROM users WHERE username = ?').bind(username).first() : null;
      const ok = u ? await check(normRec(body.recovery), u.rsalt, u.rhash) : (await pbk('x', 'x', ITER), false);
      if (!ok) { await bump(db, k, 3600); return err('Identifiant ou code de récupération incorrect.', 401); }
      const p = await mkHash(pw), rec = newRecovery(), r = await mkHash(normRec(rec));
      await db.prepare('UPDATE users SET salt = ?, hash = ?, rsalt = ?, rhash = ? WHERE id = ?').bind(p.salt, p.hash, r.salt, r.hash, u.id).run();
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(u.id).run();
      await clear(db, k);
      return json({ token: await newSession(db, u.id), user: pub(u), data: u.data || null, recovery: rec });
    }
    if (route === 'leaderboard' && method === 'GET') {
      const week = url.searchParams.get('scope') === 'week', wk = weekKey(), u = await auth(db, request);
      const q = week
        ? 'SELECT display, level, week_xp AS score FROM users WHERE show_rank = 1 AND week_key = ? AND week_xp > 0 ORDER BY week_xp DESC, id ASC LIMIT ?'
        : 'SELECT display, level, xp AS score FROM users WHERE show_rank = 1 AND xp > 0 ORDER BY xp DESC, id ASC LIMIT ?';
      const rs = await (week ? db.prepare(q).bind(wk, TOP) : db.prepare(q).bind(TOP)).all();
      const rows = (rs.results || []).map((r, i) => ({ rank: i + 1, name: r.display, level: r.level, score: r.score }));
      const tot = await (week ? db.prepare('SELECT COUNT(*) AS c FROM users WHERE show_rank = 1 AND week_key = ? AND week_xp > 0').bind(wk) : db.prepare('SELECT COUNT(*) AS c FROM users WHERE show_rank = 1 AND xp > 0')).first();
      return json({ rows, total: tot.c, me: u ? await scoreOf(db, u, week) : null });
    }
    // routes qui demandent d'être connecté
    const u = await auth(db, request);
    if (!u) return err('Session expirée, reconnecte-toi.', 401);
    if (route === 'sync' && method === 'POST') {
      const xp = Math.max(0, Math.min(1e6, Math.floor(+body.xp || 0)));
      const today = parisDay(), wk = weekKey();
      let day = u.day_key === today ? u.day_xp : 0, week = u.week_key === wk ? u.week_xp : 0, total = u.xp, synced = u.synced;
      if (!u.synced) { total = Math.min(xp, FIRST_MAX); synced = 1; }
      else if (xp > total) { const add = Math.min(xp - total, Math.max(0, CAP_DAY - day)); total += add; day += add; week += add; }
      const data = typeof body.data === 'string' && body.data.length < 300000 ? body.data : u.data;
      const show = body.show === undefined ? u.show_rank : (body.show ? 1 : 0);
      await db.prepare('UPDATE users SET xp = ?, level = ?, day_key = ?, day_xp = ?, week_key = ?, week_xp = ?, synced = ?, show_rank = ?, data = ? WHERE id = ?')
        .bind(total, lvlOf(total), today, day, wk, week, synced, show, data, u.id).run();
      const nu = await db.prepare('SELECT * FROM users WHERE id = ?').bind(u.id).first();
      return json({ user: pub(nu), week_xp: week });
    }
    if (route === 'logout' && method === 'POST') {
      await db.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha(tokenOf(request))).run();
      return json({ ok: true });
    }
    if (route === 'delete' && method === 'POST') {
      if (!(await check(String(body.password || ''), u.salt, u.hash))) return err('Mot de passe incorrect.', 401);
      await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(u.id).run();
      await db.prepare('DELETE FROM users WHERE id = ?').bind(u.id).run();
      return json({ ok: true });
    }
    if (route === 'me' && method === 'GET') return json({ user: pub(u) });
    return err('Route inconnue.', 404);
  } catch (e) {
    return err('Erreur serveur.', 500);
  }
}

// Point d'entrée du Worker : /api/* -> comptes et classement, le reste -> le site (fichiers statiques)
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return onRequest({ request, env, params: { route: url.pathname.slice(5).split('/').filter(Boolean) } });
    }
    return env.ASSETS.fetch(request);
  }
};
