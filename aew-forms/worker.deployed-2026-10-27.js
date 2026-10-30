// aew-forms: sign-ups (D1 + alerts) and the orb's task line to Twin on the Mac Mini
import { EmailMessage } from 'cloudflare:email';
const ALLOWED = ['https://aiemployeeworkflow.com', 'https://www.aiemployeeworkflow.com'];
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
async function newTask(req, env, o) {
let text = '', up = [], visitor = null;
try { const f = await req.formData(); text = clip(f.get('text'), 4000); up = f.getAll('files').filter(x => x && typeof x === 'object' && x.name); const v = clip(f.get('visitor'), 64); if (/^[a-f0-9]{32}$/.test(v)) visitor = v; } catch { return json(o, { error: 'bad request' }, 400); }
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
const limit = parseInt(env.DAILY_LIMIT || '3', 10);
const used = await env.DB.prepare("SELECT COUNT(*) AS n FROM tasks WHERE ip = ? AND created_at > datetime('now','-1 day')").bind(ip).first();
if (used && used.n >= limit) return json(o, { error: 'You’ve used today’s ' + limit + ' free tasks. Claim a founding spot for more, or come back tomorrow.' }, 429);
const id = rid(), token = rid();
let seq = 0;
if (visitor) { const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM tasks WHERE visitor = ? AND status = 'done'").bind(visitor).first(); seq = c ? c.n : 0; }
await env.DB.prepare('INSERT INTO tasks (id, token, text, ip, file_name, visitor, seq) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, token, text, ip, file ? file.name : null, visitor, seq).run();
if (file) await env.DB.prepare('INSERT INTO task_files (task_id, name, ext, size, data) VALUES (?, ?, ?, ?, ?)').bind(id, file.name, file.ext, file.size, file.data).run();
return json(o, { id, token });
}
async function getTask(req, env, ctx, o, id) {
const auth = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
const t = await env.DB.prepare('SELECT status, result, error, token, created_at, claimed_at, text, file_name FROM tasks WHERE id = ?').bind(id).first();
if (!t || !auth || !(await safeEqual(t.token, auth))) return json(o, { error: 'not found' }, 404);
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
if (!ALLOWED.includes(o)) return json(o, { ok: false, error: 'forbidden' }, 403);
if (req.method === 'POST' && p === '/signup') return signup(req, env, ctx, o);
if (req.method === 'POST' && p === '/api/tasks') return newTask(req, env, o);
const m = p.match(/^\/api\/tasks\/([a-f0-9]{32})$/);
if (req.method === 'GET' && m) return getTask(req, env, ctx, o, m[1]);
return json(o, { ok: false, error: 'not found' }, 404);
}
};
