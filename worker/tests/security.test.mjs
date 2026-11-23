import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { build } from 'esbuild';

// Bundle the actual Worker code and replace only the Cloudflare socket transport.
// This avoids pretending that a second, reimplemented TOTP is the production code.
const built = await build({
  entryPoints: [new URL('../src/index.ts', import.meta.url).pathname],
  bundle: true, format: 'esm', platform: 'neutral', write: false,
  plugins: [{
    name: 'test-socket-stub',
    setup(builder) {
      builder.onResolve({ filter: /^cloudflare:sockets$/ }, () => ({ path: 'socket', namespace: 'test' }));
      builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export function connect() { throw new Error("socket unavailable in offline unit test"); }', loader: 'js' }));
    }
  }]
});
const worker = await import('data:text/javascript;base64,' + Buffer.from(built.outputFiles[0].text).toString('base64'));
const env = {
  SESSION_SECRET: 's'.repeat(40), BOOTSTRAP_KEY: 'b'.repeat(40),
  APP_ORIGIN: 'https://monitor.example', DB: { prepare() { throw new Error('unexpected database call'); } }
};

test('production TOTP matches RFC 6238 SHA-1 six-digit vectors', async () => {
  const s = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  for (const [seconds, expected] of [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037']]) {
    assert.equal(await worker.totp(s, seconds * 1000), expected);
  }
  assert.match(worker.randomSecret(), /^[A-Z2-7]{32}$/);
});

test('certificate expiry warnings use the configured threshold and classify expired dates', () => {
  const now = Date.parse('2030-01-01T00:00:00Z');
  assert.deepEqual(worker.certificateExpiryState('2030-02-01T00:00:00Z', now, 30), { state: 'ok', days_remaining: 31 });
  assert.deepEqual(worker.certificateExpiryState('2030-01-31T00:00:00Z', now, 30), { state: 'warning', days_remaining: 30 });
  assert.deepEqual(worker.certificateExpiryState('2029-12-31T00:00:00Z', now, 30), { state: 'expired', days_remaining: -1 });
  assert.equal(worker.certificateExpiryState('not-a-date', now, 30), null);
});

test('HTTP endpoint parser rejects local addresses and invalid ports', () => {
  for (const s of ['http://127.0.0.1/', 'http://0x7f000001/', 'http://[::1]/', 'https://localhost/', 'https://example.com:8443/', 'https://user:pass@example.com/']) {
    assert.throws(() => worker.safeEndpoint(s, new URL(s).protocol.slice(0, -1)), s);
  }
  assert.equal(worker.safeEndpoint('https://example.com/', 'https').hostname, 'example.com');
});

test('TCP validation rejects local destinations and forbidden port', () => {
  for (const host of ['127.0.0.1', '0x7f000001', '::1', 'localhost', 'user@example.com', 'test.local']) {
    assert.throws(() => worker.validateTcpTarget(host, 443), host);
  }
  assert.throws(() => worker.validateTcpTarget('example.com', 25));
  assert.deepEqual(worker.validateTcpTarget('example.com', 443), { host: 'example.com', port: 443 });
});

test('missing secrets fail closed while health endpoint remains available', async () => {
  assert.equal((await worker.default.fetch(new Request('https://monitor.example/health'), {})).status, 200);
  assert.equal((await worker.default.fetch(new Request('https://monitor.example/api/me'), {})).status, 503);
});

test('target and check configuration reads require an administrator session', async () => {
  const targets = await worker.default.fetch(new Request('https://monitor.example/api/targets'), env);
  const checks = await worker.default.fetch(new Request('https://monitor.example/api/targets/1/checks'), env);
  assert.equal(targets.status, 401);
  assert.equal(checks.status, 401);
});

test('CSRF origin and agent bearer token are enforced', async () => {
  const csrf = await worker.default.fetch(new Request('https://monitor.example/api/bootstrap', {
    method: 'POST', headers: { Origin: 'https://wrong.example', 'Content-Type': 'application/json' }, body: '{}'
  }), env);
  assert.equal(csrf.status, 400);
  const unauthorized = await worker.default.fetch(new Request('https://monitor.example/api/agent/heartbeat', {
    method: 'POST', headers: { Authorization: 'Bearer wrong', 'Content-Type': 'application/json' }, body: '{}'
  }), { ...env, DB: { prepare(sql) {
    const statement = { bind() { return statement; }, async first() { return null; } };
    return statement;
  } } });
  assert.equal(unauthorized.status, 403);
});

test('probe credentials are individually authenticated and heartbeat identity cannot be spoofed', async () => {
  const token = 'individual-probe-token-' + 'x'.repeat(32);
  const digest = createHash('sha256').update(token).digest('base64url');
  let heartbeatValues;
  const db = {
    prepare(sql) {
      let values = [];
      const statement = {
        bind(...args) { values = args; return statement; },
        async first() { return sql.startsWith('SELECT id FROM probes') && values[0] === digest ? { id: 'probe-owned' } : null; },
        async run() {
          if (sql.startsWith('INSERT INTO agent_heartbeats')) heartbeatValues = values;
          return { meta: { changes: 1 } };
        },
      };
      return statement;
    },
  };
  const response = await worker.default.fetch(new Request('https://monitor.example/api/agent/heartbeat', {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ agent_id: 'spoofed-id', metrics: { cpu: 1 }, certificates: [] }),
  }), { ...env, DB: db });
  assert.equal(response.status, 200);
  assert.equal(heartbeatValues[0], 'probe-owned');
  const wrong = await worker.default.fetch(new Request('https://monitor.example/api/agent/heartbeat', {
    method: 'POST', headers: { Authorization: 'Bearer ' + 'y'.repeat(56), 'Content-Type': 'application/json' }, body: '{}'
  }), { ...env, DB: db });
  assert.equal(wrong.status, 403);
});

test('probe task lease can be consumed once and results are stored through the narrow API', async () => {
  const token = 'individual-probe-token-' + 'q'.repeat(32);
  const digest = createHash('sha256').update(token).digest('base64url');
  const otherToken = 'individual-probe-token-' + 'r'.repeat(32);
  const otherDigest = createHash('sha256').update(otherToken).digest('base64url');
  const check = { id: 9, kind: 'https', url: 'https://status.example/', host: null, port: null, timeout_ms: 5000, expected_status: 200 };
  let lease = null;
  let completed = false;
  const results = [];
  const db = {
    prepare(sql) {
      let values = [];
      const statement = {
        bind(...args) { values = args; return statement; },
        async all() {
          if (sql.startsWith('SELECT c.id,c.kind,c.url,c.host,c.port,c.timeout_ms,c.expected_status')) return { results: [check] };
          throw new Error(`unexpected all query: ${sql}`);
        },
        async first() {
          if (sql.startsWith('SELECT id FROM probes')) return values[0] === digest ? { id: 'probe-a' } : values[0] === otherDigest ? { id: 'probe-b' } : null;
          if (sql.startsWith('INSERT INTO probe_task_leases')) { lease = { check_id: values[0], probe_id: values[1], task_token: values[2], lease_until: values[3] }; completed = false; return { check_id: values[0] }; }
          if (sql.startsWith('SELECT c.id,c.enabled,t.name,l.task_token')) {
            return lease && !completed && values[0] === lease.check_id && values[1] === lease.probe_id && values[2] === lease.task_token
              ? { id: check.id, enabled: 1, name: 'site', task_token: lease.task_token } : null;
          }
          if (sql.startsWith('SELECT ok FROM check_results')) return results.length ? { ok: results.at(-1)[1] } : null;
          throw new Error(`unexpected first query: ${sql}`);
        },
        async run() {
          if (sql.startsWith('UPDATE probe_task_leases SET completed_at')) {
            if (!lease || completed || values[1] !== lease.check_id || values[2] !== lease.probe_id || values[3] !== lease.task_token) return { meta: { changes: 0 } };
            completed = true;
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('INSERT INTO check_results')) results.push(values);
          return { meta: { changes: 1 } };
        },
      };
      return statement;
    },
  };
  const probeEnv = { ...env, DB: db };
  const tasksResponse = await worker.default.fetch(new Request('https://monitor.example/api/probe/tasks?limit=10', {
    headers: { Authorization: `Bearer ${token}` }
  }), probeEnv);
  assert.equal(tasksResponse.status, 200);
  const tasks = (await tasksResponse.json()).tasks;
  assert.equal(tasks.length, 1);
  assert.equal(tasks[0].check.url, check.url);
  assert.ok(tasks[0].task_token);

  const submit = (authToken = token) => worker.default.fetch(new Request('https://monitor.example/api/probe/results', {
    method: 'POST', headers: { Authorization: `Bearer ${authToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ check_id: check.id, task_token: tasks[0].task_token, ok: true, latency_ms: 34, error: null }),
  }), probeEnv);
  const otherProbe = await submit(otherToken);
  assert.equal(otherProbe.status, 400);
  assert.equal(completed, false);
  const accepted = await submit();
  assert.equal(accepted.status, 200);
  assert.equal(results.length, 1);
  assert.equal(results[0][1], 1);
  assert.equal(results[0][2], 34);
  const duplicate = await submit();
  assert.equal(duplicate.status, 400);
});

test('malformed passwords consume the per-IP-and-username login limit', async () => {
  let rateRow = null;
  const db = {
    prepare(sql) {
      let values = [];
      const statement = {
        bind(...args) { values = args; return statement; },
        async first() {
          if (sql.startsWith('SELECT attempts,expires_at FROM login_rate_limits')) return rateRow;
          if (sql.startsWith('SELECT * FROM users')) {
            return { id: 1, username: 'admin', password_hash: 'unused', totp_secret: null, totp_enabled: 0 };
          }
          throw new Error(`unexpected first query: ${sql}`);
        },
        async run() {
          if (sql.startsWith('INSERT OR REPLACE INTO login_rate_limits')) {
            rateRow = { attempts: 0, expires_at: values[2] };
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('INSERT INTO login_rate_limits')) {
            rateRow = { attempts: (rateRow?.attempts || 0) + 1, expires_at: values[2] };
            return { meta: { changes: 1 } };
          }
          throw new Error(`unexpected run query: ${sql}`);
        },
      };
      return statement;
    },
  };
  const loginEnv = { ...env, DB: db };
  const login = password => worker.default.fetch(new Request('https://monitor.example/api/login', {
    method: 'POST',
    headers: { Origin: 'https://monitor.example', 'Content-Type': 'application/json' },
    body: JSON.stringify(password === undefined ? { username: 'admin' } : { username: 'admin', password }),
  }), loginEnv);

  for (let i = 0; i < 10; i++) {
    const response = await login(i % 2 ? { malformed: true } : undefined);
    assert.equal(response.status, 403);
  }
  const limited = await login('another attempt');
  assert.equal(limited.status, 429);
  assert.equal((await limited.json()).error, 'login rate limit exceeded');
  assert.equal(rateRow.attempts, 10);
});

function certificateTestEnv(certificates) {
  const agentId = 'agent-test';
  const states = new Map();
  const probeStates = new Map();
  let reported = certificates;
  const stateKey = (agent, hostname) => `${agent}\u0000${hostname}`;
  const db = {
    prepare(sql) {
      let values = [];
      const statement = {
        bind(...args) { values = args; return statement; },
        async all() {
          if (sql.startsWith('SELECT agent_id,certificates FROM agent_heartbeats')) {
            return { results: [{ agent_id: agentId, certificates: JSON.stringify(reported) }] };
          }
          if (sql.startsWith('SELECT hostname,state FROM certificate_alert_states')) {
            return { results: [...states.values()]
              .filter(row => row.agent_id === values[0])
              .map(({ hostname, state }) => ({ hostname, state })) };
          }
          if (sql.startsWith('SELECT hostname,state FROM certificate_probe_states')) {
            return { results: [...probeStates.values()]
              .filter(row => row.agent_id === values[0])
              .map(({ hostname, state }) => ({ hostname, state })) };
          }
          throw new Error(`unexpected all query: ${sql}`);
        },
        async first() {
          if (sql.startsWith('SELECT state FROM certificate_alert_states')) {
            const row = states.get(stateKey(values[0], values[1]));
            return row ? { state: row.state } : null;
          }
          if (sql.startsWith('SELECT state FROM certificate_probe_states')) {
            const row = probeStates.get(stateKey(values[0], values[1]));
            return row ? { state: row.state } : null;
          }
          throw new Error(`unexpected first query: ${sql}`);
        },
        async run() {
          if (sql.startsWith('INSERT OR IGNORE INTO certificate_alert_states')) {
            const [agent_id, hostname, state, days_remaining, changed_at] = values;
            const key = stateKey(agent_id, hostname);
            if (states.has(key)) return { meta: { changes: 0 } };
            states.set(key, { agent_id, hostname, state, days_remaining, changed_at });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('INSERT OR IGNORE INTO certificate_probe_states')) {
            const [agent_id, hostname, state, changed_at] = values;
            const key = stateKey(agent_id, hostname);
            if (probeStates.has(key)) return { meta: { changes: 0 } };
            probeStates.set(key, { agent_id, hostname, state, changed_at });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith("UPDATE certificate_alert_states SET state='missing'")) {
            const [changed_at, agent_id, hostname, expectedState] = values;
            const key = stateKey(agent_id, hostname);
            const row = states.get(key);
            if (!row || row.state !== expectedState) return { meta: { changes: 0 } };
            states.set(key, { ...row, state: 'missing', days_remaining: null, changed_at });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith("UPDATE certificate_probe_states SET state='missing'")) {
            const [changed_at, agent_id, hostname, expectedState] = values;
            const key = stateKey(agent_id, hostname);
            const row = probeStates.get(key);
            if (!row || row.state !== expectedState) return { meta: { changes: 0 } };
            probeStates.set(key, { ...row, state: 'missing', changed_at });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('UPDATE certificate_alert_states SET state=?')) {
            const [state, days_remaining, changed_at, agent_id, hostname, expectedState] = values;
            const key = stateKey(agent_id, hostname);
            const row = states.get(key);
            if (!row || row.state !== expectedState) return { meta: { changes: 0 } };
            states.set(key, { ...row, state, days_remaining, changed_at });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith('UPDATE certificate_probe_states SET state=?')) {
            const [state, changed_at, agent_id, hostname, expectedState] = values;
            const key = stateKey(agent_id, hostname);
            const row = probeStates.get(key);
            if (!row || row.state !== expectedState) return { meta: { changes: 0 } };
            probeStates.set(key, { ...row, state, changed_at });
            return { meta: { changes: 1 } };
          }
          throw new Error(`unexpected run query: ${sql}`);
        },
      };
      return statement;
    },
  };
  return {
    env: { ...env, DB: db, NOTIFY_WEBHOOK_URL: 'https://webhook.example/alerts', CERT_EXPIRY_ALERT_DAYS: '30' },
    states,
    probeStates,
    setCertificates(next) { reported = next; },
    stateKey,
    agentId,
  };
}

async function withFakeWebhook(callback) {
  const sent = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    sent.push(JSON.parse(init.body));
    return new Response(null, { status: 204 });
  };
  try {
    return await callback(sent);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const certificate = (hostname, days) => ({
  hostname,
  expires_at: new Date(Date.now() + days * 86400000).toISOString(),
});

test('certificate alerts dedupe, reconcile missing hosts, and notify on status transitions', async () => {
  await withFakeWebhook(async sent => {
    const testData = certificateTestEnv([certificate('example.com', 15), certificate('EXAMPLE.COM', 60)]);
    const { env: certEnv, states, stateKey, agentId, setCertificates } = testData;
    assert.equal(await worker.monitorCertificates(certEnv), 1);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].type, 'certificate_expiring');
    assert.equal(await worker.monitorCertificates(certEnv), 0);
    assert.equal(sent.length, 1);

    setCertificates([certificate('example.com', -1)]);
    assert.equal(await worker.monitorCertificates(certEnv), 1);
    assert.equal(sent.at(-1).type, 'certificate_expired');
    assert.equal(await worker.monitorCertificates(certEnv), 0);

    setCertificates([]);
    assert.equal(await worker.monitorCertificates(certEnv), 0);
    assert.equal(states.get(stateKey(agentId, 'example.com')).state, 'missing');
    assert.equal(sent.length, 2);

    setCertificates([certificate('example.com', 15)]);
    assert.equal(await worker.monitorCertificates(certEnv), 1);
    assert.equal(sent.at(-1).type, 'certificate_expiring');
    setCertificates([certificate('example.com', 90)]);
    assert.equal(await worker.monitorCertificates(certEnv), 1);
    assert.equal(sent.at(-1).type, 'certificate_recovered');
  });
});

test('concurrent certificate monitors emit only one alert per atomic state change', async () => {
  await withFakeWebhook(async sent => {
    const testData = certificateTestEnv([certificate('example.com', 15)]);
    const { env: certEnv, setCertificates } = testData;
    const initial = await Promise.all([
      worker.monitorCertificates(certEnv),
      worker.monitorCertificates(certEnv),
    ]);
    assert.equal(initial.reduce((sum, count) => sum + count, 0), 1);
    assert.equal(sent.filter(event => event.type === 'certificate_expiring').length, 1);

    setCertificates([certificate('example.com', 90)]);
    const recovery = await Promise.all([
      worker.monitorCertificates(certEnv),
      worker.monitorCertificates(certEnv),
    ]);
    assert.equal(recovery.reduce((sum, count) => sum + count, 0), 1);
    assert.equal(sent.filter(event => event.type === 'certificate_recovered').length, 1);
  });
});

test('failed certificate webhook is best-effort and does not break monitor state writes', async () => {
  const testData = certificateTestEnv([certificate('example.com', 15)]);
  const { env: certEnv, states, stateKey, agentId } = testData;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('simulated webhook outage'); };
  try {
    assert.equal(await worker.monitorCertificates(certEnv), 1);
    assert.equal(states.get(stateKey(agentId, 'example.com')).state, 'warning');
    assert.equal(await worker.monitorCertificates(certEnv), 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('certificate probe validation failures alert once and recover when a valid certificate returns', async () => {
  await withFakeWebhook(async sent => {
    const data = certificateTestEnv([{ hostname: 'example.com', error: 'certificate_verification_failed' }]);
    assert.equal(await worker.monitorCertificates(data.env), 1);
    assert.equal(sent.at(-1).type, 'certificate_probe_failed');
    assert.equal(sent.at(-1).error, 'certificate_verification_failed');
    assert.equal(await worker.monitorCertificates(data.env), 0);
    data.setCertificates([certificate('example.com', 90)]);
    assert.equal(await worker.monitorCertificates(data.env), 1);
    assert.equal(sent.at(-1).type, 'certificate_probe_recovered');
    assert.equal(await worker.monitorCertificates(data.env), 0);
  });
});


test('TOTP setup reuses an existing pending enrollment secret without rewriting it', async () => {
  const pendingSecret = 'ABCDEFGHABCDEFGHABCDEFGHABCDEFGH';
  const user = { id: 1, username: 'admin', password_hash: 'unused', totp_secret: pendingSecret, totp_enabled: 0 };
  let writes = 0;
  const db = {
    prepare(sql) {
      let values = [];
      const statement = {
        bind(...args) { values = args; return statement; },
        async first() {
          assert.match(sql, /^SELECT id,username,password_hash,totp_secret,totp_enabled FROM users WHERE id=/);
          assert.equal(values[0], 1);
          return user;
        },
        async run() { writes += 1; throw new Error('pending setup must not overwrite the database'); },
      };
      return statement;
    },
  };
  const payload = Buffer.from(JSON.stringify({ sub: 1, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
  const signature = createHmac('sha256', env.SESSION_SECRET).update(payload).digest('base64url');
  const response = await worker.default.fetch(new Request('https://monitor.example/api/totp/setup', {
    method: 'POST', headers: { Origin: env.APP_ORIGIN, Cookie: `sc_session=${payload}.${signature}` },
  }), { ...env, DB: db });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.secret, pendingSecret);
  assert.match(body.otpauth_uri, new RegExp(`secret=${pendingSecret}`));
  assert.equal(writes, 0);
});


function adminSessionCookie(userId = 1) {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url');
  const signature = createHmac('sha256', env.SESSION_SECRET).update(payload).digest('base64url');
  return `sc_session=${payload}.${signature}`;
}

function appearanceRequest(path, { method = 'GET', cookie = adminSessionCookie(), body } = {}) {
  const headers = { Cookie: cookie };
  if (method !== 'GET') {
    headers.Origin = env.APP_ORIGIN;
    headers['Content-Type'] = 'application/json';
  }
  return new Request(`https://monitor.example${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

test('appearance settings are administrator-only and reject unauthenticated reads and writes', async () => {
  const noDbCalls = { prepare() { throw new Error('unauthenticated appearance request reached D1'); } };
  const unauthenticatedGet = await worker.default.fetch(appearanceRequest('/api/settings/appearance', { cookie: '' }), { ...env, DB: noDbCalls });
  assert.equal(unauthenticatedGet.status, 401);
  const unauthenticatedPut = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
    method: 'PUT', cookie: '', body: { appearance: worker.DEFAULT_APPEARANCE },
  }), { ...env, DB: noDbCalls });
  assert.equal(unauthenticatedPut.status, 401);
});

test('appearance settings persist in the singleton D1 row and validate URLs and input limits', async () => {
  let stored = null;
  let updatedBy = null;
  const db = {
    prepare(sql) {
      let values = [];
      const statement = {
        bind(...args) { values = args; return statement; },
        async first() {
          if (sql.startsWith('SELECT id,username,password_hash,totp_secret,totp_enabled FROM users WHERE id=')) {
            return { id: 1, username: 'admin', password_hash: 'unchanged', totp_secret: null, totp_enabled: 0 };
          }
          if (sql.startsWith('SELECT config_json FROM appearance_settings WHERE id=1')) {
            return stored ? { config_json: stored } : null;
          }
          throw new Error(`unexpected first query: ${sql}`);
        },
        async run() {
          if (sql.startsWith('INSERT INTO appearance_settings')) {
            stored = values[0];
            updatedBy = values[2];
            return { meta: { changes: 1 } };
          }
          throw new Error(`unexpected run query: ${sql}`);
        },
      };
      return statement;
    },
  };
  const appearanceEnv = { ...env, DB: db };
  const defaultsResponse = await worker.default.fetch(appearanceRequest('/api/settings/appearance'), appearanceEnv);
  assert.equal(defaultsResponse.status, 200);
  assert.deepEqual((await defaultsResponse.json()).appearance, worker.DEFAULT_APPEARANCE);
  assert.equal(stored, null);

  const configured = {
    theme: 'custom',
    backgroundImageUrl: 'https://images.example.test/wallpaper.jpg?size=large',
    panelOpacity: 0.58,
    panelBlurPx: 12,
    customCss: '#app .panel { border-radius: 18px; }',
    customScript: 'console.log("authenticated only");',
  };
  const savedResponse = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
    method: 'PUT', body: { appearance: configured },
  }), appearanceEnv);
  assert.equal(savedResponse.status, 200);
  assert.deepEqual((await savedResponse.json()).appearance, configured);
  assert.equal(updatedBy, 1);
  const reloaded = await worker.default.fetch(appearanceRequest('/api/settings/appearance'), appearanceEnv);
  assert.deepEqual((await reloaded.json()).appearance, configured);

  for (const backgroundImageUrl of [
    'http://images.example.test/wallpaper.jpg',
    'javascript:alert(1)',
    'https://user:password@images.example.test/wallpaper.jpg',
    `https://images.example.test/${'a'.repeat(2050)}`,
  ]) {
    const invalidUrl = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
      method: 'PUT', body: { appearance: { ...configured, backgroundImageUrl } },
    }), appearanceEnv);
    assert.equal(invalidUrl.status, 400, backgroundImageUrl.slice(0, 80));
  }

  const largeCss = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
    method: 'PUT', body: { appearance: { ...configured, customCss: 'x'.repeat(20001) } },
  }), appearanceEnv);
  assert.equal(largeCss.status, 400);
  const largeScript = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
    method: 'PUT', body: { appearance: { ...configured, customScript: 'x'.repeat(12001) } },
  }), appearanceEnv);
  assert.equal(largeScript.status, 400);
  const badOpacity = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
    method: 'PUT', body: { appearance: { ...configured, panelOpacity: 1 } },
  }), appearanceEnv);
  assert.equal(badOpacity.status, 400);
  const badTheme = await worker.default.fetch(appearanceRequest('/api/settings/appearance', {
    method: 'PUT', body: { appearance: { ...configured, theme: 'theme6<script>' } },
  }), appearanceEnv);
  assert.equal(badTheme.status, 400);

  const oversizedRequest = await worker.default.fetch(new Request('https://monitor.example/api/settings/appearance', {
    method: 'PUT',
    headers: { Cookie: adminSessionCookie(), Origin: env.APP_ORIGIN, 'Content-Type': 'application/json', 'Content-Length': '50001' },
    body: '{}',
  }), appearanceEnv);
  assert.equal(oversizedRequest.status, 400);
  assert.deepEqual(JSON.parse(stored), configured, 'invalid updates must not modify the saved row');
});
