import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import agent


class FakeResponse:
    status = 204
    headers = {}
    def __enter__(self): return self
    def __exit__(self, *args): pass


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        os.makedirs(os.path.join(root, "net"))
        with open(os.path.join(root, "stat"), "w") as f: f.write("cpu  100 0 100 700 0 0 0 0 0 0\n")
        with open(os.path.join(root, "meminfo"), "w") as f: f.write("MemTotal:       1000 kB\nMemAvailable:    400 kB\n")
        with open(os.path.join(root, "uptime"), "w") as f: f.write("123.4 0.0\n")
        with open(os.path.join(root, "net", "dev"), "w") as f: f.write("Inter-| Receive | Transmit\n eth0: 10 0 0 0 0 0 0 0 20 0 0\n lo: 100 0 0 0 0 0 0 0 200 0 0\n")

    def tearDown(self): self.tmp.cleanup()

    def test_collects_linux_proc_metrics_and_excludes_loopback(self):
        metrics, state = agent.collect_metrics(self.tmp.name, self.tmp.name)
        self.assertIsNone(metrics["cpu_used_percent"])
        self.assertEqual(metrics["memory"]["total_bytes"], 1000 * 1024)
        self.assertEqual(metrics["network"], {"rx_bytes": 10, "tx_bytes": 20})
        self.assertEqual(metrics["uptime_seconds"], 123.4)
        with open(os.path.join(self.tmp.name, "stat"), "w") as f: f.write("cpu  200 0 200 800 0 0 0 0 0 0\n")
        metrics, _ = agent.collect_metrics(self.tmp.name, self.tmp.name, state)
        self.assertEqual(metrics["cpu_used_percent"], 66.67)

    def test_heartbeat_is_bearer_and_json_without_network(self):
        captured = {}
        def opener(request, timeout):
            captured["request"] = request; captured["timeout"] = timeout
            return FakeResponse()
        config = agent.Config("https://monitor.example/api/agent/heartbeat", "secret-token", 1, 7,
                              agent_id="node-1")
        agent.send_heartbeat(config, {"x": 1}, opener)
        self.assertEqual(captured["timeout"], 7)
        self.assertEqual(captured["request"].get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(json.loads(captured["request"].data),
                         {"agent_id": "node-1", "metrics": {"x": 1}, "certificates": []})

    def test_http_requires_explicit_local_opt_in(self):
        config = agent.Config("http://example.invalid/heartbeat", "x", agent_id="node-1")
        with self.assertRaises(ValueError): agent.send_heartbeat(config, {}, lambda *a, **k: FakeResponse())
        config = agent.Config("http://127.0.0.1/heartbeat", "x", insecure_local=True, agent_id="node-1")
        agent.send_heartbeat(config, {}, lambda *a, **k: FakeResponse())

    def test_config_does_not_require_or_print_token(self):
        with patch.dict(os.environ, {"SENTRY_AGENT_URL": "https://x", "AGENT_TOKEN": "top-secret", "AGENT_ID": "node-1"}, clear=True):
            config = agent.Config.from_env()
        self.assertEqual(config.token, "top-secret")
        self.assertEqual(config.agent_id, "node-1")
        self.assertNotIn("top-secret", repr(config))

    def test_agent_id_is_required(self):
        config = agent.Config("https://monitor.example/heartbeat", "x")
        with self.assertRaises(ValueError): agent.send_heartbeat(config, {}, lambda *a, **k: FakeResponse())


if __name__ == "__main__": unittest.main()
