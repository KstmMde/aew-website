// aew-forms: sign-ups (D1 + alerts), Google/LinkedIn sign-in, and the orb's task line to Twin on the Mac Mini
// The website Worker (aew-website) passes aiemployeeworkflow.com/api/* and /auth/* here over a service binding,
// so the sign-in cookie stays same-origin. The Mac Mini bridge keeps using aew-forms.aew-workflow.workers.dev/api/agent/*.
import { EmailMessage } from 'cloudflare:email';
const ALLOWED = ['https://aiemployeeworkflow.com', 'https://www.aiemployeeworkflow.com'];
const SITE = ALLOWED[0];
const SITE_HOSTS = ALLOWED.map(a => new URL(a).hostname);
const NOTIFY_TO = 'aew.workflow@gmail.com';
const NOTIFY_FROM = 'signups@aiemployeeworkflow.com';
const FILE_TYPES = ['pdf', 'docx', 'txt', 'csv', 'md'];
const FILE_MAX = 1500000;
const OFFLINE_MIN = 5;
const STUCK_MIN = 6;
const STUCK_MSG = 'This one took too long, so I stopped it. Please try again.';
const OFFLINE_MSG = 'Your AI Employee is offline right now. Please try again a little later.';
// Sign-up flood guards (audit fix Oct 27 2026): same email max per day, and a site-wide cap per hour
const SIGNUP_PER_EMAIL_DAY = 3;
const SIGNUP_PER_HOUR = 40;
// Signed-in visitors (Oct 30 2026): per-account daily task cap, on top of the per-visitor cap (DAILY_LIMIT)
const USER_DAILY = 10;
const TASK_KEEP_DAYS = 90;
const SESSION_DAYS = 30;
const SESSION_COOKIE = '__Host-aew_s';
const STATE_COOKIE = '__Host-aew_oauth';
const STATE_MIN = 10;
const CARD_PREFIX = 'AEW_CARD:';
const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
// OpenID Connect, scopes openid email profile only. Each provider switches on once its client ID and secret are set.
const PROVIDERS = {
google: { label: 'Google', auth: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', iss: ['https://accounts.google.com', 'accounts.google.com'], id: 'GOOGLE_CLIENT_ID', secret: 'GOOGLE_CLIENT_SECRET', pkce: true, extra: { prompt: 'select_account' } },
linkedin: { label: 'LinkedIn', auth: 'https://www.linkedin.com/oauth/v2/authorization', token: 'https://www.linkedin.com/oauth/v2/accessToken', iss: ['https://www.linkedin.com/oauth'], id: 'LINKEDIN_CLIENT_ID', secret: 'LINKEDIN_CLIENT_SECRET', pkce: false, extra: {} }
};
const cors = o => ({ 'Access-Control-Allow-Origin': ALLOWED.includes(o) ? o : ALLOWED[0], 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Vary': 'Origin' });
const json = (o, body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...cors(o) } });
const clip = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
const b64 = s => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const rid = () => [...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(x => x.toString(16).padStart(2, '0')).join('');
// Constant-time string compare (compares SHA-256 digests so length doesn't leak either)
async function safeEqual(a, b) {
const [x, y] = await Promise.all([sha(a), sha(b)]);
let r = 0;
for (let i = 0; i < x.length; i++) r |= x.charCodeAt(i) ^ y.charCodeAt(i);
return r === 0;
}
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64url = s => { const t = atob(s.replace(/-/g, '+').replace(/_/g, '/')); return new TextDecoder().decode(Uint8Array.from(t, c => c.charCodeAt(0))); };
const randUrl = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
const now = () => Math.floor(Date.now() / 1000);
async function hmac(env, data) {
const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.SESSION_SECRET.trim()), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
return b64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))));
}
// value.signature, checked in constant time
const signed = async (env, value) => value + '.' + (await hmac(env, value));
async function unsign(env, s) {
const i = (s || '').lastIndexOf('.');
if (i < 1 || !env.SESSION_SECRET) return null;
const value = s.slice(0, i);
return (await safeEqual(s.slice(i + 1), await hmac(env, value))) ? value : null;
}
function readCookie(req, name) {
for (const part of (req.headers.get('Cookie') || '').split(';')) {
const j = part.indexOf('=');
if (j > 0 && part.slice(0, j).trim() === name) return part.slice(j + 1).trim();
}
return '';
}
const setCookie = (name, value, maxAge) => name + '=' + value + '; Path=/; Max-Age=' + maxAge + '; HttpOnly; Secure; SameSite=Lax';
const authOn = env => !!(env.SESSION_SECRET && env.SESSION_SECRET.trim().length >= 32);
const providerOn = (env, p) => authOn(env) && !!(env[PROVIDERS[p].id] && env[PROVIDERS[p].secret]);
// Session cookie holds "userId.expiry", signed with SESSION_SECRET
async function currentUser(req, env) {
if (!authOn(env)) return null;
const v = await unsign(env, readCookie(req, SESSION_COOKIE));
if (!v) return null;
const [uid, exp] = v.split('.');
if (!/^[a-f0-9]{32}$/.test(uid || '') || !(+exp > now())) return null;
return env.DB.prepare('SELECT id, provider, email, name FROM users WHERE id = ?').bind(uid).first();
}
// Turnstile: the token from the page must pass siteverify before a sign-up or task is accepted
async function human(req, env, token) {
token = clip(token, 2048);
if (!env.TURNSTILE_SECRET || !token) return false;
const body = new FormData();
body.append('secret', env.TURNSTILE_SECRET.trim());
body.append('response', token);
const ip = req.headers.get('CF-Connecting-IP');
if (ip) body.append('remoteip', ip);
try {
const r = await fetch(SITEVERIFY, { method: 'POST', body });
const d = await r.json();
if (!d.success) console.log('turnstile fail ' + JSON.stringify(d['error-codes'] || []));
return !!d.success && SITE_HOSTS.includes(d.hostname);
} catch (e) { console.error('turnstile error=' + String(e)); return false; }
}
const NOT_HUMAN = 'I couldn’t confirm you’re a person. Please try again.';
async function post(label, url, body) {
try {
const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const t = (await r.text()).slice(0, 300);
console.log('notify ' + label + ' status=' + r.status + ' body=' + t);
} catch (e) { console.error('notify ' + label + ' error=' + String(e)); }
}
function chat(env, text) {
const jobs = [];
if (env.TG_BOT_TOKEN) jobs.push(post('telegram', 'https://api.telegram.org/bot' + env.TG_BOT_TOKEN.trim() + '/sendMessage', { chat_id: (env.TG_CHAT_ID || '8405368080').trim(), text }));
if (env.SLACK_WEBHOOK_URL) jobs.push(post('slack', env.SLACK_WEBHOOK_URL.trim(), { text }));
return jobs;
}
async function notify(env, s) {
const title = s.kind === 'claim' ? 'New founding spot claim' : 'New waiting list sign-up';
const lines = [title, 'Name: ' + (s.name || '-'), 'Email: ' + s.email];
if (s.kind === 'claim') lines.push('What they do: ' + (s.business || '-'), 'Phone: ' + (s.phone || '-'), 'First task: ' + (s.task || '-'));
const text = lines.join('\n');
const jobs = chat(env, text);
if (env.NOTIFY_EMAIL) {
const raw = ['From: AEW Sign-ups <' + NOTIFY_FROM + '>', 'To: ' + NOTIFY_TO, 'Subject: =?UTF-8?B?' + b64(title + ': ' + (s.name || s.email)) + '?=', 'Message-ID: <' + crypto.randomUUID() + '@aiemployeeworkflow.com>', 'Date: ' + new Date().toUTCString(), 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', b64(text)].join('\r\n');
jobs.push(env.NOTIFY_EMAIL.send(new EmailMessage(NOTIFY_FROM, NOTIFY_TO, raw)).then(() => console.log('notify email sent'), e => console.error('notify email error=' + String(e))));
}
await Promise.allSettled(jobs);
}
async function orbAlert(env, head, task, fileName, body) {
const lines = ['Orb task: ' + head, 'Task: ' + clip(task || '', 300)];
if (fileName) lines.push('File: ' + fileName);
if (body) lines.push('Answer: ' + clip(body, 400));
await Promise.allSettled(chat(env, lines.join('\n')));
}
async function signup(req, env, ctx, o) {
let d;
try { d = await req.json(); } catch { return json(o, { ok: false, error: 'bad request' }, 400); }
if (d.website) return json(o, { ok: true });
if (!(await human(req, env, d.turnstile))) return json(o, { ok: false, error: NOT_HUMAN }, 403);
const kind = d.kind === 'claim' ? 'claim' : d.kind === 'waitlist' ? 'waitlist' : '';
const email = clip(d.email, 200);
if (!kind || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(o, { ok: false, error: 'Please enter a valid email.' }, 400);
const name = clip(d.name, 120);
if (kind === 'claim' && !name) return json(o, { ok: false, error: 'Please enter your name.' }, 400);
const sameEmail = await env.DB.prepare("SELECT COUNT(*) AS n FROM signups WHERE lower(email) = lower(?) AND created_at > datetime('now','-1 day')").bind(email).first();
if (sameEmail && sameEmail.n >= SIGNUP_PER_EMAIL_DAY) return json(o, { ok: true });
const lastHour = await env.DB.prepare("SELECT COUNT(*) AS n FROM signups WHERE created_at > datetime('now','-1 hour')").first();
if (lastHour && lastHour.n >= SIGNUP_PER_HOUR) return json(o, { ok: false, error: 'Lots of people are signing up right now. Please try again in a little while, or email aew.workflow@gmail.com.' }, 429);
const s = { kind, name, email, business: clip(d.business, 200), phone: clip(d.phone, 40), task: clip(d.task, 2000), page: clip(d.page, 200) };
await env.DB.prepare('INSERT INTO signups (kind, name, email, business, phone, task, page) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(s.kind, s.name, s.email, s.business, s.phone, s.task, s.page).run();
ctx.waitUntil(notify(env, s));
return json(o, { ok: true });
}
async function newTask(req, env, ctx, o) {
const user = await currentUser(req, env);
if (!user) return json(o, { error: 'Please sign in first.', signin: true }, 401);
let text = '', up = [], visitor = null, ts = '', replyTo = '';
try { const f = await req.formData(); text = clip(f.get('text'), 4000); up = f.getAll('files').filter(x => x && typeof x === 'object' && x.name); const v = clip(f.get('visitor'), 64); if (/^[a-f0-9]{32}$/.test(v)) visitor = v; ts = f.get('turnstile'); const r = clip(f.get('reply_to'), 64); if (/^[a-f0-9]{32}$/.test(r)) replyTo = r; } catch { return json(o, { error: 'bad request' }, 400); }
if (!(await human(req, env, ts))) return json(o, { error: NOT_HUMAN }, 403);
if (!text) return json(o, { error: 'Tell me the task first.' }, 400);
if (up.length > 1) return json(o, { error: 'While you’re trying it out, it’s one file per task.' }, 400);
let file = null;
if (up.length) {
const x = up[0];
const ext = (x.name.split('.').pop() || '').toLowerCase();
if (!FILE_TYPES.includes(ext)) return json(o, { error: 'For now I can read PDF, Word (.docx), TXT, CSV or MD files.' }, 400);
if (x.size > FILE_MAX) return json(o, { error: 'That file is over 1.5 MB. Try a smaller one.' }, 400);
file = { name: clip(x.name, 120), ext, size: x.size, data: await x.arrayBuffer() };
}
const ip = await sha((req.headers.get('CF-Connecting-IP') || 'unknown') + (env.IP_SALT || 'aew'));
// One answer to a question or playback card the AI Employee sent this same account is part of that task, so it doesn't use up a daily task
let parent = null;
if (replyTo && !file && /^(ANSWER|CONFIRM): /.test(text)) {
const p = await env.DB.prepare("SELECT id FROM tasks WHERE id = ? AND user_id = ? AND status = 'done' AND substr(result, 1, ?) = ? AND NOT EXISTS (SELECT 1 FROM tasks c WHERE c.parent_id = tasks.id)").bind(replyTo, user.id, CARD_PREFIX.length, CARD_PREFIX).first();
if (p) parent = p.id;
}
if (!parent) {
const limit = parseInt(env.DAILY_LIMIT || '3', 10);
const used = await env.DB.prepare("SELECT COUNT(*) AS n FROM tasks WHERE ip = ? AND parent_id IS NULL AND created_at > datetime('now','-1 day')").bind(ip).first();
if (used && used.n >= limit) return json(o, { error: 'You’ve used today’s ' + limit + ' free tasks. Claim a founding spot for more, or come back tomorrow.' }, 429);
const mine = await env.DB.prepare("SELECT COUNT(*) AS n FROM tasks WHERE user_id = ? AND parent_id IS NULL AND created_at > datetime('now','-1 day')").bind(user.id).first();
if (mine && mine.n >= USER_DAILY) return json(o, { error: 'You’ve used today’s ' + USER_DAILY + ' tasks on your account. Come back tomorrow, or email aew.workflow@gmail.com.' }, 429);
}
const id = rid(), token = rid();
let seq = 0;
if (visitor) { const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM tasks WHERE visitor = ? AND status = 'done'").bind(visitor).first(); seq = c ? c.n : 0; }
try { await env.DB.prepare('INSERT INTO tasks (id, token, text, ip, file_name, visitor, seq, user_id, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(id, token, text, ip, file ? file.name : null, visitor, seq, user.id, parent).run(); }
catch (e) { if (parent && /UNIQUE/i.test(String(e))) return json(o, { error: 'You already answered that one.' }, 409); throw e; }
if (file) await env.DB.prepare('INSERT INTO task_files (task_id, name, ext, size, data) VALUES (?, ?, ?, ?, ?)').bind(id, file.name, file.ext, file.size, file.data).run();
ctx.waitUntil(env.DB.prepare("DELETE FROM tasks WHERE created_at < datetime('now', ?)").bind('-' + TASK_KEEP_DAYS + ' days').run().catch(e => console.error('cleanup error=' + String(e))));
return json(o, { id, token });
}
async function getTask(req, env, ctx, o, id) {
const auth = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
const t = await env.DB.prepare('SELECT status, result, error, token, created_at, claimed_at, text, file_name, user_id FROM tasks WHERE id = ?').bind(id).first();
if (!t || !auth || !(await safeEqual(t.token, auth))) return json(o, { error: 'not found' }, 404);
if (t.user_id) { const u = await currentUser(req, env); if (!u || u.id !== t.user_id) return json(o, { error: 'not found' }, 404); }
if (t.status === 'queued') {
const age = await env.DB.prepare("SELECT (julianday('now') - julianday(?)) * 1440 AS m").bind(t.created_at).first();
if (age && age.m > OFFLINE_MIN) {
await env.DB.prepare("UPDATE tasks SET status = 'error', error = ? WHERE id = ? AND status = 'queued'").bind(OFFLINE_MSG, id).run();
await env.DB.prepare('DELETE FROM task_files WHERE task_id = ?').bind(id).run();
ctx.waitUntil(orbAlert(env, 'MISSED (Mac Mini offline)', t.text, t.file_name));
return json(o, { status: 'error', error: OFFLINE_MSG });
}
}
if (t.status === 'working' && t.claimed_at) {
const age = await env.DB.prepare("SELECT (julianday('now') - julianday(?)) * 1440 AS m").bind(t.claimed_at).first();
if (age && age.m > STUCK_MIN) {
await env.DB.prepare("UPDATE tasks SET status = 'error', error = ? WHERE id = ? AND status = 'working'").bind(STUCK_MSG, id).run();
await env.DB.prepare('DELETE FROM task_files WHERE task_id = ?').bind(id).run();
ctx.waitUntil(orbAlert(env, 'STUCK (Mac Mini stopped mid-task)', t.text, t.file_name));
return json(o, { status: 'error', error: STUCK_MSG });
}
}
return json(o, { status: t.status, result: t.result || undefined, error: t.error || undefined });
}
function redirect(to, cookies = []) {
const h = new Headers({ Location: SITE + to, 'Cache-Control': 'no-store' });
cookies.forEach(c => h.append('Set-Cookie', c));
return new Response(null, { status: 302, headers: h });
}
const safeReturn = r => (typeof r === 'string' && r.length < 200 && /^\/(?![\/\\])[^\s\\]*$/.test(r) ? r : '/');
async function authStart(env, p, url) {
// One callback address per provider, on the main domain, so the state and session cookies always land there
if (url.hostname !== SITE_HOSTS[0]) return new Response(null, { status: 302, headers: { Location: SITE + url.pathname + url.search } });
if (!providerOn(env, p)) return redirect('/?signin=unavailable');
const P = PROVIDERS[p];
const st = { p, s: randUrl(), n: randUrl(), v: randUrl(), r: safeReturn(url.searchParams.get('return')), t: now() };
const q = new URLSearchParams({ response_type: 'code', client_id: env[P.id].trim(), redirect_uri: SITE + '/auth/' + p + '/callback', scope: 'openid email profile', state: st.s, nonce: st.n, ...P.extra });
if (P.pkce) { q.set('code_challenge', b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(st.v))))); q.set('code_challenge_method', 'S256'); }
const cookie = await signed(env, b64url(new TextEncoder().encode(JSON.stringify(st))));
return new Response(null, { status: 302, headers: { Location: P.auth + '?' + q, 'Set-Cookie': setCookie(STATE_COOKIE, cookie, STATE_MIN * 60), 'Cache-Control': 'no-store' } });
}
async function authCallback(req, env, p, url) {
const clear = setCookie(STATE_COOKIE, '', 0);
const fail = (why, to = '/?signin=failed') => { console.log('signin ' + p + ' failed: ' + why); return redirect(to, [clear]); };
if (!providerOn(env, p)) return fail('provider off', '/?signin=unavailable');
let st = null;
try { const v = await unsign(env, readCookie(req, STATE_COOKIE)); if (v) st = JSON.parse(unb64url(v)); } catch { st = null; }
if (!st || st.p !== p || !(now() - st.t < STATE_MIN * 60)) return fail('missing or expired state');
if (url.searchParams.get('error')) return fail('provider said ' + clip(url.searchParams.get('error'), 60), '/?signin=cancelled');
const code = url.searchParams.get('code') || '', state = url.searchParams.get('state') || '';
if (!code || !state || !(await safeEqual(state, st.s))) return fail('state mismatch');
const P = PROVIDERS[p], clientId = env[P.id].trim();
const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: SITE + '/auth/' + p + '/callback', client_id: clientId, client_secret: env[P.secret].trim() });
if (P.pkce) form.set('code_verifier', st.v);
let claims;
try {
const r = await fetch(P.token, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form });
const d = await r.json();
if (!r.ok || !d.id_token) return fail('token endpoint ' + r.status + ' ' + clip(d.error || '', 60));
// The ID token came straight from the provider's token endpoint over TLS, so its claims are checked rather than its signature
claims = JSON.parse(unb64url(d.id_token.split('.')[1] || ''));
} catch (e) { return fail('token exchange ' + String(e)); }
const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
if (!P.iss.includes(claims.iss) || !aud.includes(clientId) || !(claims.exp > now()) || typeof claims.sub !== 'string' || !claims.sub) return fail('bad id token claims');
if ((P.pkce || claims.nonce !== undefined) && !(typeof claims.nonce === 'string' && (await safeEqual(claims.nonce, st.n)))) return fail('nonce mismatch');
const email = clip(claims.email, 200), name = clip(claims.name || [claims.given_name, claims.family_name].filter(Boolean).join(' '), 120);
const u = await env.DB.prepare("INSERT INTO users (id, provider, provider_sub, email, name) VALUES (?, ?, ?, ?, ?) ON CONFLICT (provider, provider_sub) DO UPDATE SET email = excluded.email, name = excluded.name, last_login_at = datetime('now') RETURNING id").bind(rid(), p, clip(claims.sub, 255), email, name).first();
const session = await signed(env, u.id + '.' + (now() + SESSION_DAYS * 86400));
return redirect(st.r, [clear, setCookie(SESSION_COOKIE, session, SESSION_DAYS * 86400)]);
}
async function authMe(req, env) {
const u = await currentUser(req, env);
return new Response(JSON.stringify({
user: u ? { name: u.name || '', email: u.email || '', provider: PROVIDERS[u.provider] ? PROVIDERS[u.provider].label : u.provider } : null,
providers: { google: providerOn(env, 'google'), linkedin: providerOn(env, 'linkedin') },
turnstile: (env.TURNSTILE_SITEKEY || '').trim()
}), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
const authLogout = () => new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Set-Cookie': setCookie(SESSION_COOKIE, '', 0) } });
async function agentOk(req, env) {
const auth = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
return !!env.AGENT_KEY && !!auth && (await safeEqual(auth, env.AGENT_KEY.trim()));
}
async function agentNext(req, env) {
if (!(await agentOk(req, env))) return new Response('unauthorized', { status: 401 });
const t = await env.DB.prepare("UPDATE tasks SET status = 'working', claimed_at = datetime('now') WHERE id = (SELECT id FROM tasks WHERE status = 'queued' ORDER BY created_at LIMIT 1) RETURNING id, text, file_name, visitor, seq").first();
return new Response(JSON.stringify(t || {}), { headers: { 'Content-Type': 'application/json' } });
}
async function agentFile(req, env, id) {
if (!(await agentOk(req, env))) return new Response('unauthorized', { status: 401 });
const f = await env.DB.prepare('SELECT name, ext, data FROM task_files WHERE task_id = ?').bind(id).first();
if (!f) return new Response('not found', { status: 404 });
return new Response(new Uint8Array(f.data), { headers: { 'Content-Type': 'application/octet-stream', 'X-File-Name': encodeURIComponent(f.name), 'X-File-Ext': f.ext } });
}
async function agentDone(req, env, ctx) {
if (!(await agentOk(req, env))) return new Response('unauthorized', { status: 401 });
let d;
try { d = await req.json(); } catch { return new Response('bad request', { status: 400 }); }
const id = clip(d.id, 64);
if (!id) return new Response('bad request', { status: 400 });
const t = await env.DB.prepare('SELECT text, file_name FROM tasks WHERE id = ?').bind(id).first();
if (d.error) await env.DB.prepare("UPDATE tasks SET status = 'error', error = ?, done_at = datetime('now') WHERE id = ?").bind(clip(d.error, 500), id).run();
else await env.DB.prepare("UPDATE tasks SET status = 'done', result = ?, done_at = datetime('now') WHERE id = ?").bind(typeof d.result === 'string' ? d.result.slice(0, 20000) : '', id).run();
await env.DB.prepare('DELETE FROM task_files WHERE task_id = ?').bind(id).run();
if (t) ctx.waitUntil(orbAlert(env, d.error ? 'had a problem' : 'done', t.text, t.file_name, d.error ? clip(d.error, 300) : d.result));
return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
}
export default {
async fetch(req, env, ctx) {
const o = req.headers.get('Origin') || '';
const url = new URL(req.url);
const p = url.pathname;
if (p.startsWith('/api/agent/')) {
if (req.method === 'GET' && p === '/api/agent/next') return agentNext(req, env);
if (req.method === 'POST' && p === '/api/agent/done') return agentDone(req, env, ctx);
const fm = p.match(/^\/api\/agent\/file\/([a-f0-9]{32})$/);
if (req.method === 'GET' && fm) return agentFile(req, env, fm[1]);
return new Response('not found', { status: 404 });
}
if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(o) });
// Requests from the site itself arrive through the aew-website service binding, with the site's own address.
// Browsers leave Origin off same-origin GETs and page navigations, so only those may come without one.
const viaSite = SITE_HOSTS.includes(url.hostname);
if (o ? !ALLOWED.includes(o) : !(viaSite && req.method === 'GET')) return json(o, { ok: false, error: 'forbidden' }, 403);
const am = p.match(/^\/auth\/(google|linkedin)\/(start|callback)$/);
if (viaSite && req.method === 'GET' && am) return am[2] === 'start' ? authStart(env, am[1], url) : authCallback(req, env, am[1], url);
if (viaSite && req.method === 'GET' && p === '/auth/me') return authMe(req, env);
if (viaSite && req.method === 'POST' && p === '/auth/logout') return authLogout();
if (req.method === 'POST' && (p === '/signup' || p === '/api/signup')) return signup(req, env, ctx, o);
if (req.method === 'POST' && p === '/api/tasks') return newTask(req, env, ctx, o);
const m = p.match(/^\/api\/tasks\/([a-f0-9]{32})$/);
if (req.method === 'GET' && m) return getTask(req, env, ctx, o, m[1]);
return json(o, { ok: false, error: 'not found' }, 404);
}
};
