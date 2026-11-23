import socket
import ssl
import unittest
from unittest.mock import patch

import probe_checks
from probe_security import UnsafeTarget


class FakeSocket:
    def __init__(self): self.closed = False
    def close(self): self.closed = True


class FakeTLSContext:
    def __init__(self): self.server_hostname = None; self.raw = None
    def wrap_socket(self, raw, server_hostname):
        self.raw, self.server_hostname = raw, server_hostname
        return FakeSocket()


class ProbeChecksTests(unittest.TestCase):
    def test_https_socket_keeps_hostname_for_sni_and_verification(self):
        context = FakeTLSContext()
        raw = FakeSocket()
        with patch.object(probe_checks, "connect_pinned", return_value=raw) as connect:
            conn = probe_checks.PinnedHTTPSConnection("example.com", 443, 3, context)
            conn.connect()
        connect.assert_called_once_with("example.com", 443, 3)
        self.assertEqual(context.server_hostname, "example.com")
        self.assertIs(context.raw, raw)
        conn.close()

    def test_http_redirect_to_private_or_ip_literal_is_rejected_before_second_request(self):
        with patch.object(probe_checks, "_request_once", return_value=(302, "http://127.0.0.1/admin")) as request:
            result = probe_checks.probe_http("https://example.com/", 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "ip_literal_not_allowed")
        request.assert_called_once()

    def test_redirect_hosts_are_revalidated_and_status_policy_is_preserved(self):
        with patch.object(probe_checks, "_request_once", side_effect=[(302, "https://other.example/path"), (204, None)]) as request:
            result = probe_checks.probe_http("https://example.com/", 1)
        self.assertTrue(result["ok"])
        self.assertIsNone(result["error"])
        self.assertEqual(request.call_count, 2)
        with patch.object(probe_checks, "_request_once", return_value=(403, None)):
            failure = probe_checks.probe_http("http://example.com", 1)
        self.assertFalse(failure["ok"])
        self.assertEqual(failure["error"], "unexpected_status")

    def test_unsafe_url_and_tcp_port_fail_closed(self):
        for url in ["http://user:pass@example.com", "https://example.com:8443", "http://127.0.0.1/"]:
            with self.subTest(url=url):
                result = probe_checks.probe_http(url, 1)
                self.assertFalse(result["ok"])
        self.assertEqual(probe_checks.probe_tcp("example.com", 25)["error"], "unsafe_port")

    def test_dns_policy_error_maps_to_failure_not_up(self):
        with patch.object(probe_checks, "connect_pinned", side_effect=UnsafeTarget("unsafe_dns_address")):
            result = probe_checks.probe_tcp("example.com", 443)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_dns_address")


if __name__ == "__main__": unittest.main()
