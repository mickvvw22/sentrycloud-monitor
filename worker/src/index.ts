import { connect } from 'cloudflare:sockets';

export interface Env {
  DB: D1Database;
  SESSION_SECRET: string;
  BOOTSTRAP_KEY: string;
  AGENT_TOKEN: string;
  APP_ORIGIN: string;
  NOTIFY_WEBHOOK_URL?: string;
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_CHAT_ID?: string;
  CERT_EXPIRY_ALERT_DAYS?: string;
}

type Ctx = { req: Request; env: Env; user?: User };
type User = {
  id: number;
  username: string;
  password_hash: string;
  totp_secret: string | null;
  totp_enabled: number;
};

type CertificateAlertState = 'ok' | 'warning' | 'expired' | 'missing';

const json = (data: unknown, status = 200, extra: HeadersInit = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extra },
  });
const now = () => new Date().toISOString();
const text = (s: string) => new TextEncoder().encode(s);
const b64u = (x: ArrayBuffer | Uint8Array) => {
  const bytes = x instanceof Uint8Array ? x : new Uint8Array(x);
  const s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const unb64u = (s: string) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const raw = atob(s);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

async function hmac(key: string, data: string, alg = 'SHA-256') {
  const k = await crypto.subtle.importKey('raw', text(key), { name: 'HMAC', hash: alg }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, text(data)));
}

async function passwordHash(password: string, salt?: Uint8Array) {
  salt ??= crypto.getRandomValues(new Uint8Array(16));
  const iterations = 100000;
  const k = await crypto.subtle.importKey('raw', text(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    k,
    256,
  );
  return `pbkdf2$${iterations}$${b64u(salt)}$${b64u(bits)}`;
}

async function passwordVerify(password: string, stored: string) {
  try {
    const [, it, salt, expected] = stored.split('$');
    if (!it || !salt || !expected) return false;
    const k = await crypto.subtle.importKey('raw', text(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: unb64u(salt), iterations: Number(it), hash: 'SHA-256' },
      k,
      256,
    ));
    const a = unb64u(expected);
    return a.length === bits.length && a.every((v, i) => v === bits[i]);
  } catch {
    return false;
  }
}

async function sessionToken(env: Env, id: number) {
  const p = b64u(text(JSON.stringify({ sub: id, exp: Math.floor(Date.now() / 1000) + 86400 })));
  return `${p}.${b64u(await hmac(env.SESSION_SECRET, p))}`;
}

async function auth(req: Request, env: Env): Promise<User | null> {
  try {
    const m = (req.headers.get('cookie') || '').match(/(?:^|;\s*)sc_session=([^;]+)/);
    if (!m) return null;
    const [p, s] = m[1].split('.');
    if (!p || !s) return null;
    const sig = await hmac(env.SESSION_SECRET, p);
    const given = unb64u(s);
    if (given.length !== sig.length || !given.every((v, i) => v === sig[i])) return null;
    const x = JSON.parse(new TextDecoder().decode(unb64u(p)));
    if (x.exp < Date.now() / 1000) return null;
    return await env.DB.prepare(
      'SELECT id,username,password_hash,totp_secret,totp_enabled FROM users WHERE id=?',
    ).bind(x.sub).first<User>();
  } catch {
    return null;
  }
}

function cookie(value: string, maxAge = 86400) {
  return `sc_session=${value}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

function certificateAlertThreshold(env: Env) {
  const days = Number(env.CERT_EXPIRY_ALERT_DAYS ?? 30);
  return Number.isInteger(days) && days >= 1 && days <= 365 ? days : 30;
}

function configError(env: Env) {
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) throw new Error('invalid SESSION_SECRET configuration');
  if (!env.BOOTSTRAP_KEY || env.BOOTSTRAP_KEY.length < 32) throw new Error('invalid BOOTSTRAP_KEY configuration');
  if (!env.AGENT_TOKEN || env.AGENT_TOKEN.length < 32) throw new Error('invalid AGENT_TOKEN configuration');
  if (!env.APP_ORIGIN) throw new Error('invalid APP_ORIGIN configuration');
  try {
    new URL(env.APP_ORIGIN);
  } catch {
    throw new Error('invalid APP_ORIGIN configuration');
  }
}

function cors(req: Request, env: Env) {
  const origin = req.headers.get('Origin');
  const h: Record<string, string> = {
    'access-control-allow-headers': 'content-type, authorization',
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'vary': 'Origin',
  };
  if (origin === env.APP_ORIGIN) {
    h['access-control-allow-origin'] = origin;
    h['access-control-allow-credentials'] = 'true';
  }
  return h;
}

function sameOrigin(req: Request, env: Env) {
  const origin = req.headers.get('Origin');
  return !!origin && origin === env.APP_ORIGIN;
}

function requireString(v: any, n: string, max = 2048) {
  if (typeof v !== 'string' || !v || v.length > max) throw new Error(`invalid ${n}`);
  return v;
}

async function body(req: Request) {
  try {
    return await req.json() as Record<string, any>;
  } catch {
    throw new Error('invalid JSON');
  }
}

export function certificateExpiryState(expiresAt: string, nowMs = Date.now(), thresholdDays = 30) {
  const expiryMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiryMs)) return null;
  const remainingMs = expiryMs - nowMs;
  const daysRemaining = Math.ceil(remainingMs / 86400000);
  const state: CertificateAlertState = remainingMs <= 0
    ? 'expired'
    : daysRemaining <= thresholdDays
      ? 'warning'
      : 'ok';
  return { state, days_remaining: daysRemaining };
}

export function base32(s: string) {
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.toUpperCase().replace(/=+$/, '')) {
    const i = alpha.indexOf(c);
    if (i < 0) throw new Error('invalid secret');
    bits += i.toString(2).padStart(5, '0');
  }
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}

export function randomSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < 160; i += 5) out += alpha[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

export async function totp(secret: string, at = Date.now()) {
  const counter = Math.floor(at / 30000);
  const b = new ArrayBuffer(8);
  const v = new DataView(b);
  v.setUint32(0, Math.floor(counter / 4294967296));
  v.setUint32(4, counter >>> 0);
  const k = await crypto.subtle.importKey('raw', base32(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, b));
  const off = h[19] & 15;
  const n = ((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(n % 1000000).padStart(6, '0');
}

async function verifyTotp(secret: string, code: string) {
  if (!/^\d{6}$/.test(code)) return false;
  for (let i = -1; i <= 1; i++) {
    if (await totp(secret, Date.now() + i * 30000) === code) return true;
  }
  return false;
}

function isIpLiteral(host: string) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h.includes(':')) return true;
  return /^[0-9.]+$/.test(h) || /^(?:0x[0-9a-f]+|[0-9a-f]+)$/i.test(h);
}

function isDisallowedHost(host: string) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return !h || h === 'localhost' || h.endsWith('.localhost') || h === 'local' || h.endsWith('.local') ||
    h === 'internal' || h.endsWith('.internal') || isIpLiteral(h);
}

export function safeEndpoint(raw: string, kind: string) {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('invalid endpoint');
  }
  if (!['http', 'https'].includes(kind) || u.protocol !== `${kind}:`) throw new Error('protocol mismatch');
  if (u.username || u.password || (u.port && !['80', '443'].includes(u.port))) throw new Error('unsafe endpoint');
  const host = u.hostname.toLowerCase();
  if (isDisallowedHost(host)) throw new Error('private or IP-literal host is not allowed');
  return u;
}

export function validateTcpTarget(rawHost: string, rawPort: unknown) {
  const host = requireString(rawHost, 'host', 255);
  if (/[\s/@:#?%\[\]\\]/.test(host) || isDisallowedHost(host)) {
    throw new Error('private or IP-literal host is not allowed');
  }
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 25) {
    throw new Error('invalid or forbidden port');
  }
  return { host, port };
}

function tcpError(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

export async function tcpConnectProbe(host: string, port: number, timeout: number) {
  const started = Date.now();
  let socket: Socket | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    socket = connect({ hostname: host, port }, { allowHalfOpen: false });
    const opened = socket.opened.catch((e: unknown) => { throw e; });
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('TCP connect timeout')), Math.min(Math.max(1, timeout), 15000));
    });
    await Promise.race([opened, timeoutPromise]);
    return { ok: true, latency_ms: Date.now() - started, error: null };
  } catch (e) {
    return { ok: false, latency_ms: Date.now() - started, error: tcpError(e) };
  } finally {
    if (timer) clearTimeout(timer);
    if (socket) {
      try { await socket.close(); } catch { /* best effort close */ }
    }
  }
}

async function fetchChecked(url: string, timeout: number) {
  let current = safeEndpoint(url, new URL(url).protocol.slice(0, -1));
  for (let i = 0; i < 4; i++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), Math.min(timeout, 15000));
    try {
      const r = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: ac.signal,
        headers: { 'user-agent': 'sentrycloud-monitor/1.0' },
      });
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers.get('location');
        if (!loc) return r;
        const next = new URL(loc, current);
        current = safeEndpoint(next.toString(), next.protocol.slice(0, -1));
        continue;
      }
      return r;
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error('too many redirects');
}

function bearer(req: Request, env: Env) {
  const m = (req.headers.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
  return !!m && m[1] === env.AGENT_TOKEN;
}

async function loginAllowed(env: Env, ip: string, user: string) {
  const key = `${ip}|${user}`;
  const r = await env.DB.prepare('SELECT attempts,expires_at FROM login_rate_limits WHERE rate_key=?')
    .bind(key).first<{ attempts: number; expires_at: number }>();
  const t = Math.floor(Date.now() / 1000);
  if (!r || r.expires_at <= t) {
    await env.DB.prepare('INSERT OR REPLACE INTO login_rate_limits(rate_key,attempts,expires_at) VALUES(?,?,?)')
      .bind(key, 0, t + 900).run();
    return true;
  }
  return r.attempts < 10;
}

async function failedLogin(env: Env, ip: string, user: string) {
  const key = `${ip}|${user}`;
  const t = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    'INSERT INTO login_rate_limits(rate_key,attempts,expires_at) VALUES(?,?,?) ' +
    'ON CONFLICT(rate_key) DO UPDATE SET attempts=attempts+1,expires_at=excluded.expires_at',
  ).bind(key, 1, t + 900).run();
}

async function notify(env: Env, event: any) {
  if (env.NOTIFY_WEBHOOK_URL) {
    try {
      await fetch(env.NOTIFY_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(event),
      });
    } catch { /* notifications are best effort */ }
  }
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
    let message: string;
    if (event.type === 'certificate_expiring') {
      message = `Certificate expiring: ${event.hostname} on ${event.agent_id} (${event.days_remaining} days remaining)`;
    } else if (event.type === 'certificate_expired') {
      message = `Certificate expired: ${event.hostname} on ${event.agent_id}`;
    } else if (event.type === 'certificate_recovered') {
      message = `Certificate renewed: ${event.hostname} on ${event.agent_id} (${event.days_remaining} days remaining)`;
    } else {
      message = `${event.type}: ${event.name || event.check_id} ${event.ok ? 'recovered' : 'failed'}`;
    }
    try {
      await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: message }),
      });
    } catch { /* notifications are best effort */ }
  }
}

export async function monitorCertificates(env: Env) {
  const threshold = certificateAlertThreshold(env);
  const rows = await env.DB.prepare(
    'SELECT agent_id,certificates FROM agent_heartbeats WHERE certificates IS NOT NULL',
  ).all<{ agent_id: string; certificates: string | unknown }>();
  let alerts = 0;
  for (const agent of rows.results || []) {
    let certificates: unknown;
    try {
      certificates = typeof agent.certificates === 'string'
        ? JSON.parse(agent.certificates)
        : agent.certificates;
    } catch {
      continue;
    }
    if (!Array.isArray(certificates)) continue;
    const expiries = new Map<string, string>();
    for (const certificate of certificates) {
      if (!certificate || typeof certificate.hostname !== 'string' || typeof certificate.expires_at !== 'string') continue;
      const hostname = certificate.hostname.trim().toLowerCase();
      if (!hostname) continue;
      const expiryMs = Date.parse(certificate.expires_at);
      if (!Number.isFinite(expiryMs)) continue;
      const currentExpiry = expiries.get(hostname);
      if (!currentExpiry || expiryMs < Date.parse(currentExpiry)) expiries.set(hostname, certificate.expires_at);
    }

    for (const [hostname, expiresAt] of expiries) {
      const expiry = certificateExpiryState(expiresAt, Date.now(), threshold);
      if (!expiry) continue;
      const previous = await env.DB.prepare(
        'SELECT state FROM certificate_alert_states WHERE agent_id=? AND hostname=?',
      ).bind(agent.agent_id, hostname).first<{ state: CertificateAlertState }>();
      if (!previous) {
        const inserted = await env.DB.prepare(
          'INSERT OR IGNORE INTO certificate_alert_states(agent_id,hostname,state,days_remaining,changed_at) VALUES(?,?,?,?,?)',
        ).bind(agent.agent_id, hostname, expiry.state, expiry.days_remaining, now()).run();
        if ((inserted.meta?.changes ?? 0) === 0) continue;
        if (expiry.state !== 'ok') {
          alerts++;
          await notify(env, {
            type: expiry.state === 'expired' ? 'certificate_expired' : 'certificate_expiring',
            agent_id: agent.agent_id,
            hostname,
            state: expiry.state,
            days_remaining: expiry.days_remaining,
            threshold_days: threshold,
          });
        }
      } else if (previous.state !== expiry.state) {
        const updated = await env.DB.prepare(
          'UPDATE certificate_alert_states SET state=?,days_remaining=?,changed_at=? WHERE agent_id=? AND hostname=? AND state=?',
        ).bind(expiry.state, expiry.days_remaining, now(), agent.agent_id, hostname, previous.state).run();
        if ((updated.meta?.changes ?? 0) === 0) continue;
        if (previous.state === 'missing' && expiry.state === 'ok') continue;
        alerts++;
        const type = expiry.state === 'ok'
          ? 'certificate_recovered'
          : expiry.state === 'expired'
            ? 'certificate_expired'
            : 'certificate_expiring';
        await notify(env, {
          type,
          agent_id: agent.agent_id,
          hostname,
          state: expiry.state,
          days_remaining: expiry.days_remaining,
          threshold_days: threshold,
        });
      }
    }

    const currentStates = await env.DB.prepare(
      'SELECT hostname,state FROM certificate_alert_states WHERE agent_id=?',
    ).bind(agent.agent_id).all<{ hostname: string; state: CertificateAlertState }>();
    const seen = new Set(expiries.keys());
    for (const state of currentStates.results || []) {
      if (seen.has(state.hostname) || state.state === 'missing') continue;
      await env.DB.prepare(
        "UPDATE certificate_alert_states SET state='missing',days_remaining=NULL,changed_at=? WHERE agent_id=? AND hostname=? AND state=?",
      ).bind(now(), agent.agent_id, state.hostname, state.state).run();
    }
  }
  return alerts;
}

async function monitor(env: Env) {
  const rows = await env.DB.prepare(
    'SELECT c.*,t.name FROM checks c JOIN targets t ON t.id=c.target_id WHERE c.enabled=1',
  ).all<any>();
  let checked = 0;
  for (const c of rows.results || []) {
    const prev = await env.DB.prepare(
      'SELECT ok,checked_at FROM check_results WHERE check_id=? ORDER BY checked_at DESC LIMIT 1',
    ).bind(c.id).first<any>();
    if (prev && Date.now() - Date.parse(prev.checked_at) < Number(c.interval_seconds) * 1000) continue;
    let result: { ok: boolean; latency_ms: number; error: string | null };
    if (c.kind === 'tcp') {
      try {
        const target = validateTcpTarget(c.host, c.port);
        result = await tcpConnectProbe(target.host, target.port, c.timeout_ms);
      } catch (e) {
        result = { ok: false, latency_ms: 0, error: tcpError(e) };
      }
    } else {
      let ok = false;
      let latency_ms = 0;
      let error: string | null = null;
      const started = Date.now();
      try {
        const r = await fetchChecked(c.url, c.timeout_ms);
        ok = r.ok && (c.expected_status == null || r.status === c.expected_status);
      } catch (e) {
        error = String(e);
      }
      latency_ms = Date.now() - started;
      result = { ok, latency_ms, error };
    }
    await env.DB.prepare(
      'INSERT INTO check_results(check_id,ok,latency_ms,error,checked_at) VALUES(?,?,?,?,?)',
    ).bind(c.id, result.ok ? 1 : 0, result.latency_ms, result.error, now()).run();
    checked++;
    if ((prev && Number(prev.ok) !== Number(result.ok)) || (!prev && !result.ok)) {
      await notify(env, { type: 'check_state_changed', check_id: c.id, name: c.name, ok: result.ok });
    }
  }
  const certificate_alerts = await monitorCertificates(env);
  return { checked, certificate_alerts };
}

async function route(ctx: Ctx) {
  const { req, env } = ctx;
  const url = new URL(req.url);
  const p = url.pathname;
  if (p === '/health') return json({ ok: true, time: now() });

  if (p === '/api/agent/heartbeat' && req.method === 'POST') {
    if (!bearer(req, env)) throw new Error('invalid agent token');
    const x = await body(req);
    const agent = requireString(x.agent_id, 'agent_id', 128);
    const certificates = x.certificates === undefined ? null : JSON.stringify(x.certificates);
    await env.DB.prepare(
      'INSERT INTO agent_heartbeats(agent_id,ip,metrics,certificates,received_at) VALUES(?,?,?,?,?) ' +
      'ON CONFLICT(agent_id) DO UPDATE SET ip=excluded.ip,metrics=excluded.metrics,' +
      'certificates=excluded.certificates,received_at=excluded.received_at',
    ).bind(agent, req.headers.get('CF-Connecting-IP'), JSON.stringify(x.metrics || {}), certificates, now()).run();
    return json({ ok: true });
  }

  if (p === '/api/bootstrap' && req.method === 'POST') {
    if (!sameOrigin(req, env)) throw new Error('CSRF origin rejected');
    const x = await body(req);
    if (x.key !== env.BOOTSTRAP_KEY) throw new Error('invalid bootstrap key');
    const n = await env.DB.prepare('SELECT COUNT(*) n FROM users').first<{ n: number }>();
    if (n?.n) throw new Error('already initialized');
    const username = requireString(x.username, 'username', 128);
    const password = requireString(x.password, 'password', 128);
    if (password.length < 12) throw new Error('password too short');
    await env.DB.prepare('INSERT INTO users(username,password_hash) VALUES(?,?)')
      .bind(username, await passwordHash(password)).run();
    return json({ ok: true }, 201);
  }

  if (p === '/api/login' && req.method === 'POST') {
    if (!sameOrigin(req, env)) throw new Error('CSRF origin rejected');
    const x = await body(req);
    const username = requireString(x.username, 'username', 128);
    const password = typeof x.password === 'string' && x.password.length <= 128 ? x.password : '';
    const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
    if (!(await loginAllowed(env, ip, username))) throw new Error('login rate limit exceeded');
    const u = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first<User>();
    if (!u || !password || !(await passwordVerify(password, u.password_hash))) {
      await failedLogin(env, ip, username);
      throw new Error('invalid credentials');
    }
    if (u.totp_enabled && !(typeof x.totp === 'string' && await verifyTotp(u.totp_secret!, x.totp))) {
      await failedLogin(env, ip, username);
      throw new Error('invalid credentials');
    }
    return new Response(JSON.stringify({ ok: true, user: { id: u.id, username: u.username } }), {
      headers: {
        'content-type': 'application/json',
        'set-cookie': cookie(await sessionToken(env, u.id)),
        ...cors(req, env),
      },
    });
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && p !== '/api/agent/heartbeat' && !sameOrigin(req, env)) {
    throw new Error('CSRF origin rejected');
  }

  if (p === '/api/agents' && req.method === 'GET') {
    if (!ctx.user) throw new Error('authentication required');
    return json(await env.DB.prepare(
      'SELECT agent_id,ip,metrics,certificates,received_at FROM agent_heartbeats ORDER BY received_at DESC',
    ).all());
  }

  if (p === '/api/logout' && req.method === 'POST') {
    return new Response(JSON.stringify({ ok: true }), {
      headers: { 'content-type': 'application/json', 'set-cookie': cookie('', 0), ...cors(req, env) },
    });
  }
  if (!ctx.user) throw new Error('authentication required');

  if (p === '/api/me') return json({ user: { id: ctx.user.id, username: ctx.user.username, totp_enabled: !!ctx.user.totp_enabled } });
  if (p === '/api/totp/setup' && req.method === 'POST') {
    if (ctx.user.totp_enabled) throw new Error('totp already enabled');
    const secret = randomSecret();
    await env.DB.prepare('UPDATE users SET totp_secret=?,totp_enabled=0 WHERE id=?').bind(secret, ctx.user.id).run();
    const issuer = encodeURIComponent('SentryCloud Monitor');
    const label = encodeURIComponent(ctx.user.username);
    return json({ secret, otpauth_uri: `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30` });
  }
  if (p === '/api/totp/enable' && req.method === 'POST') {
    const x = await body(req);
    if (!ctx.user.totp_secret || !(await verifyTotp(ctx.user.totp_secret, String(x.code || '')))) throw new Error('invalid totp');
    await env.DB.prepare('UPDATE users SET totp_enabled=1 WHERE id=?').bind(ctx.user.id).run();
    return json({ ok: true });
  }
  if (p === '/api/totp/disable' && req.method === 'POST') {
    const x = await body(req);
    if (!await passwordVerify(String(x.password || ''), ctx.user.password_hash) ||
        !await verifyTotp(ctx.user.totp_secret || '', String(x.code || x.totp || ''))) {
      throw new Error('reauthentication required');
    }
    await env.DB.prepare('UPDATE users SET totp_enabled=0,totp_secret=NULL WHERE id=?').bind(ctx.user.id).run();
    return json({ ok: true });
  }

  if (p === '/api/targets' && req.method === 'GET') {
    return json(await env.DB.prepare('SELECT * FROM targets ORDER BY id DESC').all());
  }
  if (p === '/api/targets' && req.method === 'POST') {
    const x = await body(req);
    const name = requireString(x.name, 'name', 128);
    const host = requireString(x.host, 'host', 255);
    if (/\s/.test(host)) throw new Error('invalid host');
    const r = await env.DB.prepare(
      'INSERT INTO targets(name,host,metadata,created_at) VALUES(?,?,?,?) RETURNING *',
    ).bind(name, host, JSON.stringify(x.metadata || {}), now()).first();
    return json(r, 201);
  }

  const tm = p.match(/^\/api\/targets\/(\d+)$/);
  if (tm && req.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM targets WHERE id=?').bind(tm[1]).run();
    return json({ ok: true });
  }

  const cm = p.match(/^\/api\/targets\/(\d+)\/checks$/);
  if (cm && req.method === 'GET') {
    return json(await env.DB.prepare('SELECT * FROM checks WHERE target_id=? ORDER BY id DESC').bind(cm[1]).all());
  }
  if (cm && req.method === 'POST') {
    const x = await body(req);
    const kind = String(x.kind || '');
    let url: string | null = null;
    let host: string | null = null;
    let port: number | null = null;
    if (['http', 'https'].includes(kind)) {
      url = safeEndpoint(requireString(x.url, 'url'), kind).toString();
    } else if (kind === 'tcp') {
      const target = validateTcpTarget(x.host, x.port);
      host = target.host;
      port = target.port;
    } else {
      throw new Error('invalid kind');
    }
    const interval = x.interval_seconds == null ? 60 : Number(x.interval_seconds);
    if (!Number.isInteger(interval) || interval < 60 || interval > 31536000) throw new Error('invalid interval_seconds');
    const r = await env.DB.prepare(
      'INSERT INTO checks(target_id,kind,url,host,port,interval_seconds,timeout_ms,expected_status,enabled,created_at) ' +
      'VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING *',
    ).bind(
      cm[1], kind, url, host, port, interval,
      Math.min(15000, Math.max(1000, Number(x.timeout_ms) || 5000)),
      x.expected_status == null ? null : Number(x.expected_status),
      x.enabled === false ? 0 : 1,
      now(),
    ).first();
    return json(r, 201);
  }

  const cr = p.match(/^\/api\/checks\/(\d+)$/);
  if (cr && req.method === 'PATCH') {
    const x = await body(req);
    if (x.interval_seconds != null && (!Number.isInteger(Number(x.interval_seconds)) || Number(x.interval_seconds) < 60 || Number(x.interval_seconds) > 31536000)) {
      throw new Error('invalid interval_seconds');
    }
    await env.DB.prepare(
      'UPDATE checks SET enabled=COALESCE(?,enabled),interval_seconds=COALESCE(?,interval_seconds),' +
      'timeout_ms=COALESCE(?,timeout_ms) WHERE id=?',
    ).bind(
      x.enabled == null ? null : (x.enabled ? 1 : 0),
      x.interval_seconds == null ? null : Number(x.interval_seconds),
      x.timeout_ms == null ? null : Math.min(15000, Math.max(1000, Number(x.timeout_ms))),
      cr[1],
    ).run();
    return json({ ok: true });
  }
  if (cr && req.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM checks WHERE id=?').bind(cr[1]).run();
    return json({ ok: true });
  }

  const lm = p.match(/^\/api\/checks\/(\d+)\/(latest|history)$/);
  if (lm && req.method === 'GET') {
    const sql = lm[2] === 'latest'
      ? 'SELECT * FROM check_results WHERE check_id=? ORDER BY checked_at DESC LIMIT 1'
      : 'SELECT * FROM check_results WHERE check_id=? ORDER BY checked_at DESC LIMIT 100';
    return json(await env.DB.prepare(sql).bind(lm[1]).all());
  }

  if (p === '/api/cron/monitor' && req.method === 'POST') {
    if (req.headers.get('x-cron-key') !== env.BOOTSTRAP_KEY) throw new Error('invalid cron key');
    return json(await monitor(env));
  }
  throw new Error('not found');
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (new URL(req.url).pathname !== '/health') {
      try { configError(env); } catch (e) {
        return json({ error: String(e instanceof Error ? e.message : e) }, 503);
      }
    }
    const h = cors(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
    try {
      const r = await route({ req, env, user: await auth(req, env) || undefined });
      for (const [k, v] of Object.entries(h)) r.headers.set(k, v);
      return r;
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e);
      const status = msg === 'authentication required' ? 401
        : msg === 'not found' ? 404
          : msg.includes('rate limit') ? 429
            : (msg.includes('credentials') || msg.includes('token') || msg.includes('bootstrap') || msg.includes('cron')) ? 403
              : 400;
      return json({ error: msg }, status, h);
    }
  },
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    configError(env);
    ctx.waitUntil(monitor(env));
  },
};
