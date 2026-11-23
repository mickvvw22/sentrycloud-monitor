import socket
import ssl
import unittest
from unittest.mock import patch

import cert_probe
from probe_security import UnsafeTarget


class FakeTLS:
    def __init__(self, cert=None, error=None): self.cert, self.error = cert, error
    def __enter__(self):
        if self.error: raise self.error
        return self
    def __exit__(self, *args): pass
    def getpeercert(self): return self.cert
    def close(self): pass


class FakeRaw:
    def close(self): pass


class FakeContext:
    def __init__(self, cert=None, error=None): self.cert, self.error, self.server_name = cert, error, None
    def wrap_socket(self, raw, server_hostname):
        self.server_name = server_hostname
        if self.error: raise self.error
        return FakeTLS(self.cert, self.error)


class CertProbeTests(unittest.TestCase):
    def test_sni_and_not_after_are_reported(self):
        context = FakeContext({"notAfter": "Jan  2 03:04:05 2030 GMT"})
        with patch.object(cert_probe, "connect_pinned", return_value=FakeRaw()) as connect, \
             patch.object(cert_probe.ssl, "create_default_context", return_value=context):
            result = cert_probe.probe_certificate("Example.COM", 3)
        self.assertEqual(result, {"hostname": "example.com", "expires_at": "2030-01-02T03:04:05Z"})
        connect.assert_called_once_with("example.com", 443, 3)
        self.assertEqual(context.server_name, "example.com")

    def test_tls_verification_failure_is_distinct_and_not_success(self):
        context = FakeContext(error=ssl.SSLCertVerificationError("bad cert"))
        with patch.object(cert_probe, "connect_pinned", return_value=FakeRaw()), \
             patch.object(cert_probe.ssl, "create_default_context", return_value=context):
            result = cert_probe.probe_certificate("example.com")
        self.assertEqual(result["error"], "certificate_verification_failed")
        self.assertNotIn("expires_at", result)

    def test_dns_security_error_is_reported_without_tls(self):
        with patch.object(cert_probe, "connect_pinned", side_effect=UnsafeTarget("unsafe_dns_address")), \
             patch.object(cert_probe.ssl, "create_default_context") as make_context:
            result = cert_probe.probe_certificate("example.com")
        self.assertEqual(result, {"hostname": "example.com", "error": "unsafe_dns_address"})
        make_context.assert_not_called()

    def test_timeout_and_invalid_hostname_are_not_connected(self):
        with patch.object(cert_probe, "connect_pinned", side_effect=socket.timeout()):
            self.assertEqual(cert_probe.probe_certificate("example.com"),
                             {"hostname": "example.com", "error": "timeout"})
        with patch.object(cert_probe, "connect_pinned") as connect:
            result = cert_probe.probe_certificate("example.com:443")
        self.assertEqual(result["error"], "invalid_hostname")
        connect.assert_not_called()


if __name__ == "__main__": unittest.main()
