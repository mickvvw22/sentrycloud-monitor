#!/usr/bin/env python3
"""HTTP/HTTPS/TCP checks performed outside the Worker control plane."""
from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.parse
from typing import Any

from probe_security import UnsafeTarget, connect_pinned, normalize_hostname


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, port: int, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout)
        self._original_hostname = hostname

    def connect(self):
        self.sock = connect_pinned(self._original_hostname, self.port, self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._original_hostname = hostname

    def connect(self):
        raw = connect_pinned(self._original_hostname, self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self._original_hostname)
        except Exception:
            raw.close()
            raise


def _validated_url(raw: str) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise UnsafeTarget("invalid_endpoint") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise UnsafeTarget("invalid_endpoint")
    expected_port = 80 if parsed.scheme == "http" else 443
    if port not in (None, expected_port):
        raise UnsafeTarget("unsafe_port")
    host = normalize_hostname(parsed.hostname)
    # Accessing .hostname loses the URL's original case, but normalized ASCII is
    # correct for DNS, Host, SNI, and certificate hostname verification.
    netloc = host if port is None else f"{host}:{port}"
    return parsed._replace(netloc=netloc, fragment="")


def _request_once(url: urllib.parse.SplitResult, timeout: float) -> tuple[int, str | None]:
    host = url.hostname
    assert host is not None
    port = url.port or (80 if url.scheme == "http" else 443)
    connection: http.client.HTTPConnection
    if url.scheme == "https":
        connection = PinnedHTTPSConnection(host, port, timeout, ssl.create_default_context())
    else:
        connection = PinnedHTTPConnection(host, port, timeout)
    path = urllib.parse.urlunsplit(("", "", url.path or "/", url.query, ""))
    try:
        connection.request("GET", path, headers={"User-Agent": "sentrycloud-monitor-probe/1.0", "Connection": "close"})
        response = connection.getresponse()
        return response.status, response.getheader("Location")
    finally:
        connection.close()


def probe_http(url: str, timeout: float = 5.0, expected_status: int | None = None,
               max_redirects: int = 5) -> dict[str, Any]:
    started = time.monotonic()
    try:
        current = _validated_url(url)
        for hop in range(max_redirects + 1):
            status, location = _request_once(current, timeout)
            if 300 <= status < 400 and location:
                if hop == max_redirects:
                    return {"ok": False, "latency_ms": _latency(started), "error": "too_many_redirects"}
                next_url = urllib.parse.urljoin(urllib.parse.urlunsplit(current), location)
                current = _validated_url(next_url)
                continue
            ok = 200 <= status < 300 and (expected_status is None or status == expected_status)
            return {"ok": ok, "latency_ms": _latency(started),
                    "error": None if ok else "unexpected_status"}
    except UnsafeTarget as exc:
        return {"ok": False, "latency_ms": _latency(started), "error": str(exc)}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "latency_ms": _latency(started), "error": "timeout"}
    except ssl.SSLCertVerificationError:
        return {"ok": False, "latency_ms": _latency(started), "error": "certificate_verification_failed"}
    except ssl.CertificateError:
        return {"ok": False, "latency_ms": _latency(started), "error": "certificate_verification_failed"}
    except ssl.SSLError:
        return {"ok": False, "latency_ms": _latency(started), "error": "tls_failed"}
    except (OSError, http.client.HTTPException):
        return {"ok": False, "latency_ms": _latency(started), "error": "connection_failed"}
    return {"ok": False, "latency_ms": _latency(started), "error": "connection_failed"}


def probe_tcp(hostname: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    started = time.monotonic()
    sock = None
    try:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or port == 25:
            raise UnsafeTarget("unsafe_port")
        normalize_hostname(hostname)
        sock = connect_pinned(hostname, port, timeout)
        return {"ok": True, "latency_ms": _latency(started), "error": None}
    except UnsafeTarget as exc:
        return {"ok": False, "latency_ms": _latency(started), "error": str(exc)}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "latency_ms": _latency(started), "error": "timeout"}
    except OSError:
        return {"ok": False, "latency_ms": _latency(started), "error": "connection_failed"}
    finally:
        if sock:
            sock.close()


def run_check(check: dict[str, Any]) -> dict[str, Any]:
    timeout = min(15.0, max(1.0, float(check.get("timeout_ms", 5000)) / 1000))
    kind = check.get("kind")
    if kind in {"http", "https"}:
        return probe_http(str(check.get("url", "")), timeout,
                          int(check["expected_status"]) if check.get("expected_status") is not None else None)
    if kind == "tcp":
        return probe_tcp(str(check.get("host", "")), int(check.get("port", 0)), timeout)
    return {"ok": False, "latency_ms": 0, "error": "invalid_check"}


def _latency(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))
