import socket
import ssl
import unittest

import cert_probe


class FakeTLS:
    def __init__(self, cert=None, error=None): self.cert, self.error = cert, error
    def __enter__(self):
        if self.error: raise self.error
        return self
    def __exit__(self, *args): pass
    def getpeercert(self): return self.cert


class FakeRaw:
    def __enter__(self): return self
    def __exit__(self, *args): pass


class FakeContext:
    def __init__(self, cert=None, error=None): self.cert, self.error, self.server_name = cert, error, None
    def wrap_socket(self, raw, server_hostname):
        self.server_name = server_hostname
        return FakeTLS(self.cert, self.error)


class CertProbeTests(unittest.TestCase):
    def connector(self, address, timeout):
        self.address, self.timeout = address, timeout
        return FakeRaw()

    def test_sni_and_not_after_are_reported(self):
        context = FakeContext({"notAfter": "Jan  2 03:04:05 2030 GMT"})
        result = cert_probe.probe_certificate("example.com", 3, self.connector, context)
        self.assertEqual(result, {"hostname": "example.com", "expires_at": "2030-01-02T03:04:05Z"})
        self.assertEqual(self.address, ("example.com", 443)); self.assertEqual(self.timeout, 3)
        self.assertEqual(context.server_name, "example.com")

    def test_timeout_and_invalid_certificate_are_not_success(self):
        self.assertEqual(cert_probe.probe_certificate("example.com", connector=lambda *a, **k: (_ for _ in ()).throw(socket.timeout())),
                         {"hostname": "example.com", "error": "timeout"})
        context = FakeContext(error=ssl.SSLCertVerificationError("bad cert"))
        result = cert_probe.probe_certificate("example.com", connector=self.connector, context=context)
        self.assertEqual(result["error"], "certificate_verification_failed")
        self.assertNotIn("expires_at", result)

    def test_invalid_hostname_is_rejected_without_connection(self):
        result = cert_probe.probe_certificate("example.com:443", connector=self.connector)
        self.assertEqual(result["error"], "invalid_hostname")


if __name__ == "__main__": unittest.main()
