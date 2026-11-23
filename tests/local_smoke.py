#!/usr/bin/env python3
"""Local-only, destructive-to-test-data smoke test for the development database.

Start the Worker with the project .dev.vars and a fresh local D1 database first.
This script creates a disposable administrator, monitoring targets, and heartbeat.
Never run it against a deployed Worker or a database containing real user data.
"""
import base64
import hashlib
import hmac
import http.cookiejar
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
import sqlite3
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:8787'
vars_file = ROOT / '.dev.vars'
values = dict(line.split('=', 1) for line in vars_file.read_text().splitlines() if '=' in line)
assert values.get('APP_ORIGIN') == BASE, 'Only the explicitly configured localhost origin is allowed.'
bootstrap_key = values['BOOTSTRAP_KEY']
agent_token = values['AGENT_TOKEN']
password = secrets.token_urlsafe(24)
username = 'local-test-' + secrets.token_hex(6)
cookie = None
events = []

class AlertReceiver(BaseHTTPRequestHandler):
    def do_POST(self):
        events.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
        self.send_response(204)
        self.end_headers()
    def log_message(self, format, *args):
        pass

receiver = HTTPServer(('127.0.0.1', 8788), AlertReceiver)
threading.Thread(target=receiver.serve_forever, daemon=True).start()

def request(method, path, data=None, headers=None, expected=(200,)):
    global cookie
    h = {'Origin': BASE}
    if cookie:
        h['Cookie'] = cookie
    if headers:
        h.update(headers)
    payload = None if data is None else json.dumps(data).encode()
    if payload is not None:
        h['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE + path, data=payload, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=45)
    except urllib.error.HTTPError as e:
        r = e
    with r:
        status = r.status
        raw = r.read()
        setcookie = r.headers.get('Set-Cookie')
    if setcookie and setcookie.startswith('sc_session='):
        cookie = setcookie.split(';', 1)[0]
    assert status in expected, f'{method} {path}: unexpected HTTP {status}: {raw[:300]!r}'
    return json.loads(raw) if raw and raw[:1] in (b'{', b'[') else raw

def code_for(secret):
    key = base64.b32decode(secret + '=' * ((-len(secret)) % 8))
    counter = int(time.time()) // 30
    dig = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = dig[-1] & 15
    return str((struct.unpack('>I', dig[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)

assert request('GET', '/health')['ok']
assert b'SentryCloud' in request('GET', '/')
request('POST', '/api/bootstrap', {'key': bootstrap_key, 'username': username, 'password': password}, expected=(201,))
request('POST', '/api/login', {'username': username, 'password': password}, headers={'Origin': 'https://invalid.example'}, expected=(400, 403))
request('POST', '/api/login', {'username': username, 'password': password})
assert request('GET', '/api/me')['user']['username'] == username
setup = request('POST', '/api/totp/setup')
assert setup['otpauth_uri'].startswith('otpauth://totp/')
request('POST', '/api/totp/enable', {'code': code_for(setup['secret'])})
request('POST', '/api/totp/setup', expected=(400, 403))
request('POST', '/api/totp/disable', {'password': password, 'code': 'not-valid'}, expected=(400, 403))
request('POST', '/api/logout')
request('POST', '/api/login', {'username': username, 'password': password}, expected=(400, 403))
request('POST', '/api/login', {'username': username, 'password': password, 'totp': code_for(setup['secret'])})
request('POST', '/api/totp/disable', {'password': password, 'code': code_for(setup['secret'])})
assert request('GET', '/api/me')['user']['totp_enabled'] is False
print('PASS: bootstrap, login, origin check, TOTP enable/login/disable')

request('POST', '/api/agent/heartbeat', {'agent_id': 'local-test', 'metrics': {}}, expected=(400, 403))
sys.path.insert(0, str(ROOT / 'agent'))
from agent import Config, collect_metrics, send_heartbeat
metrics, _ = collect_metrics()
send_heartbeat(Config(url=BASE + '/api/agent/heartbeat', token=agent_token,
                      insecure_local=True, agent_id='local-test'), metrics)
rows = request('GET', '/api/agents')['results']
assert any(r['agent_id'] == 'local-test' and 'memory' in json.loads(r['metrics']) for r in rows)
request('POST', '/api/agent/heartbeat', {'agent_id': 'cert-test', 'metrics': {},
    'certificates': [{'hostname': 'example.com', 'expires_at': '2030-01-01T00:00:00Z'}]},
    headers={'Authorization': 'Bearer ' + agent_token})
rows = request('GET', '/api/agents')['results']
assert any(r['agent_id'] == 'cert-test' and json.loads(r['certificates'])[0]['hostname'] == 'example.com' for r in rows)
print('PASS: rejected unauthorized agent, real local metrics heartbeat, certificate payload persisted')

target = request('POST', '/api/targets', {'name': 'Local test target', 'host': 'example.com'}, expected=(201,))
tid = target['id']
request('POST', f'/api/targets/{tid}/checks', {'kind': 'http', 'url': 'http://127.0.0.1/', 'interval_seconds': 60}, expected=(400, 403))
http_check = request('POST', f'/api/targets/{tid}/checks', {'kind': 'https', 'url': 'https://example.com/', 'interval_seconds': 60, 'expected_status': 599}, expected=(201,))
tcp_check = request('POST', f'/api/targets/{tid}/checks', {'kind': 'tcp', 'host': 'example.com', 'port': 443, 'interval_seconds': 60}, expected=(201,))
result = request('POST', '/api/cron/monitor', headers={'x-cron-key': bootstrap_key})
http_history = request('GET', f"/api/checks/{http_check['id']}/history")['results']
tcp_history = request('GET', f"/api/checks/{tcp_check['id']}/history")['results']
assert http_history, 'HTTP cron produced no history'
assert tcp_history, 'TCP cron produced no history'
assert all(item['ok'] in (0, 1) for item in http_history + tcp_history)
print(f"PASS: real scheduled HTTP/TCP check records (HTTP={http_history[0]['ok']}, TCP={tcp_history[0]['ok']}); observed status depends on network")
assert request('POST', '/api/cron/monitor', headers={'x-cron-key': bootstrap_key})['checked'] == 0
assert any(e.get('check_id') == http_check['id'] and e.get('ok') is False for e in events), 'initial failure alert not delivered to local receiver'
databases = list((ROOT / '.wrangler/local-integration/v3/d1').rglob('*.sqlite'))
assert len(databases) == 1, 'Expected exactly one disposable local D1 database'
with sqlite3.connect(databases[0]) as db:
    db.execute('UPDATE checks SET expected_status=200 WHERE id=?', (http_check['id'],))
    db.execute("UPDATE check_results SET checked_at='2000-01-01T00:00:00.000Z' WHERE check_id=?", (http_check['id'],))
request('POST', '/api/cron/monitor', headers={'x-cron-key': bootstrap_key})
http_history = request('GET', f"/api/checks/{http_check['id']}/history")['results']
assert http_history[0]['ok'] == 1, 'example.com did not return expected HTTP status during recovery test'
assert any(e.get('check_id') == http_check['id'] and e.get('ok') is True for e in events), 'recovery alert not delivered to local receiver'
print('PASS: failure and recovery webhooks received locally')
request('DELETE', f'/api/targets/{tid}')
print('PASS: check interval respected and local test target deleted')
receiver.shutdown()
