#!/usr/bin/env python3
"""Read-only TLS certificate probe with fail-closed DNS/IP pinning."""
from __future__ import annotations

import argparse
import json
import socket
import ssl
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any, Iterable

from probe_security import UnsafeTarget, connect_pinned, normalize_hostname


def probe_certificate(hostname: str, timeout: float = 10.0) -> dict[str, Any]:
    """Connect only to a checked public IP while validating TLS for the hostname."""
    try:
        host = normalize_hostname(hostname)
    except UnsafeTarget as exc:
        return {"hostname": str(hostname), "error": str(exc)}
    result: dict[str, Any] = {"hostname": host}
    raw_socket = None
    tls_socket = None
    try:
        raw_socket = connect_pinned(host, 443, timeout)
        context = ssl.create_default_context()
        # Keep the original DNS name for SNI and the normal CA/hostname checks.
        tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
        cert = tls_socket.getpeercert()
        not_after = cert.get("notAfter") if cert else None
        if not not_after:
            result["error"] = "certificate_unreadable"
            return result
        try:
            expires = parsedate_to_datetime(not_after).astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            result["error"] = "certificate_unreadable"
            return result
        result["expires_at"] = expires.isoformat().replace("+00:00", "Z")
        return result
    except UnsafeTarget as exc:
        result["error"] = str(exc)
    except ssl.SSLCertVerificationError:
        result["error"] = "certificate_verification_failed"
    except ssl.CertificateError:
        result["error"] = "certificate_verification_failed"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except ssl.SSLError:
        result["error"] = "tls_failed"
    except (ConnectionError, OSError):
        result["error"] = "connection_failed"
    finally:
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket is not None:
            raw_socket.close()
    return result


def probe_certificates(hostnames: Iterable[str], timeout: float = 10.0) -> list[dict[str, Any]]:
    results = []
    for hostname in hostnames:
        host = hostname.strip() if isinstance(hostname, str) else ""
        if host:
            results.append(probe_certificate(host, timeout))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe publicly reachable TLS certificates")
    parser.add_argument("host", nargs="+", help="explicit public DNS hostname(s), port 443")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    print(json.dumps(probe_certificates(args.host, args.timeout), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
