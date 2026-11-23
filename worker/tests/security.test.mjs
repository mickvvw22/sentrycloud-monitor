import test from 'node:test';
import assert from 'node:assert/strict';
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
  SESSION_SECRET: 's'.repeat(40), BOOTSTRAP_KEY: 'b'.repeat(40), AGENT_TOKEN: 'a'.repeat(40),
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
  }), env);
  assert.equal(unauthorized.status, 403);
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
          throw new Error(`unexpected all query: ${sql}`);
        },
        async first() {
          if (sql.startsWith('SELECT state FROM certificate_alert_states')) {
            const row = states.get(stateKey(values[0], values[1]));
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
          if (sql.startsWith("UPDATE certificate_alert_states SET state='missing'")) {
            const [changed_at, agent_id, hostname, expectedState] = values;
            const key = stateKey(agent_id, hostname);
            const row = states.get(key);
            if (!row || row.state !== expectedState) return { meta: { changes: 0 } };
            states.set(key, { ...row, state: 'missing', days_remaining: null, changed_at });
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
          throw new Error(`unexpected run query: ${sql}`);
        },
      };
      return statement;
    },
  };
  return {
    env: { ...env, DB: db, NOTIFY_WEBHOOK_URL: 'https://webhook.example/alerts', CERT_EXPIRY_ALERT_DAYS: '30' },
    states,
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

test('TCP connect failure is not reported as up', async () => {
  const result = await worker.tcpConnectProbe('example.com', 443, 1000);
  assert.equal(result.ok, false);
  assert.match(result.error, /unavailable/);
});
