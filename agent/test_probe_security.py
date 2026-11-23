import socket
import unittest

from probe_security import UnsafeTarget, connect_pinned, normalize_hostname, resolve_public_addresses


def answer(address, family=None):
    family = family or (socket.AF_INET6 if ":" in address else socket.AF_INET)
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


class FakeSocket:
    def __init__(self, family, socktype, proto): self.args = (family, socktype, proto); self.connected = None; self.timeout = None
    def settimeout(self, timeout): self.timeout = timeout
    def connect(self, sockaddr): self.connected = sockaddr
    def close(self): pass


class ProbeSecurityTests(unittest.TestCase):
    def test_hostname_normalization_and_literal_rejection(self):
        self.assertEqual(normalize_hostname("  ExAmPlE.com. "), "example.com")
        self.assertEqual(normalize_hostname("bücher.example"), "xn--bcher-kva.example")
        for host in ["localhost", "127.0.0.1", "::1", "example.com:443", "example..com", "foo.local", "metadata.google.internal"]:
            with self.subTest(host=host), self.assertRaises(UnsafeTarget):
                normalize_hostname(host)

    def test_every_dns_answer_must_be_public(self):
        blocked = [
            "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254",
            "172.16.0.1", "192.0.0.1", "192.0.0.9", "192.168.1.1", "192.0.2.1", "198.18.0.1", "224.0.0.1",
            "::", "::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2002::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1",
        ]
        for address in blocked:
            with self.subTest(address=address), self.assertRaises(UnsafeTarget):
                resolve_public_addresses("example.com", 443, lambda *_args, a=address: [answer(a)])
        with self.assertRaisesRegex(UnsafeTarget, "unsafe_dns_address"):
            resolve_public_addresses("example.com", 443,
                lambda *_: [answer("93.184.216.34"), answer("10.0.0.1")])

    def test_ip_is_pinned_and_dns_revalidated_before_connect(self):
        lookups = []
        sock = FakeSocket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        def resolver(host, port, *_args):
            lookups.append((host, port))
            return [answer("93.184.216.34")]
        result = connect_pinned("example.com", 443, 2.5, resolver, lambda *args: sock)
        self.assertIs(result, sock)
        self.assertGreaterEqual(len(lookups), 2)
        self.assertEqual(sock.connected, ("93.184.216.34", 443))
        self.assertAlmostEqual(sock.timeout, 2.5, places=3)

    def test_dns_rebinding_to_private_is_rejected_before_socket_creation(self):
        calls = 0
        sockets = []
        def resolver(*_args):
            nonlocal calls
            calls += 1
            return [answer("93.184.216.34" if calls == 1 else "169.254.169.254")]
        with self.assertRaisesRegex(UnsafeTarget, "unsafe_dns_address"):
            connect_pinned("example.com", 443, 1, resolver, lambda *args: sockets.append(args))
        self.assertEqual(calls, 2)
        self.assertEqual(sockets, [])


if __name__ == "__main__": unittest.main()
