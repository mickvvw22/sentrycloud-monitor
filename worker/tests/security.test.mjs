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

test('TCP connect failure is not reported as up', async () => {
  const result = await worker.tcpConnectProbe('example.com', 443, 1000);
  assert.equal(result.ok, false);
  assert.match(result.error, /unavailable/);
});
