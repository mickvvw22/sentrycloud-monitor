#!/usr/bin/env python3
"""Optional, read-only TLS certificate probe; never disables certificate validation."""
from __future__ import annotations

import argparse
import json
import socket
import ssl
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterable, Optional


def probe_certificate(hostname: str, timeout: float = 10.0,
                      connector: Optional[Callable] = None,
                      context: Optional[ssl.SSLContext] = None) -> dict[str, Any]:
    """Connect with SNI and normal CA/hostname checks, then read notAfter.

    Returned errors are intentionally stable categories. An entry with an error
    never contains expires_at and is not considered a successful certificate.
    """
    result: dict[str, Any] = {"hostname": hostname}
    if not hostname or any(c.isspace() for c in hostname) or ":" in hostname:
        result["error"] = "invalid_hostname"
        return result
    connector = connector or socket.create_connection
    context = context or ssl.create_default_context()
    try:
        with connector((hostname, 443), timeout=timeout) as raw_socket:
            # server_hostname supplies SNI; default context enforces CA and hostname validation.
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
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
    except ssl.SSLCertVerificationError:
        result["error"] = "certificate_verification_failed"
    except ssl.CertificateError:
        result["error"] = "certificate_verification_failed"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (ConnectionError, OSError):
        result["error"] = "connection_failed"
    except ssl.SSLError:
        result["error"] = "tls_failed"
    return result


def probe_certificates(hostnames: Iterable[str], timeout: float = 10.0,
                       connector: Optional[Callable] = None,
                       context: Optional[ssl.SSLContext] = None) -> list[dict[str, Any]]:
    return [probe_certificate(host.strip(), timeout, connector, context)
            for host in hostnames if host.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe publicly reachable TLS certificates")
    parser.add_argument("host", nargs="+", help="explicit DNS hostname(s), port 443")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    print(json.dumps(probe_certificates(args.host, args.timeout), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
