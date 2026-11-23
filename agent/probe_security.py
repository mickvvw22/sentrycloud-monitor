#!/usr/bin/env python3
"""Fail-closed DNS policy and pinned socket connections for probe traffic."""
from __future__ import annotations

import ipaddress
import socket
import time
from typing import Callable, Iterable


_BLOCKED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
))


class UnsafeTarget(ValueError):
    """The target is malformed or resolves to a non-public address."""


def normalize_hostname(hostname: str) -> str:
    if not isinstance(hostname, str):
        raise UnsafeTarget("invalid_hostname")
    value = hostname.strip().rstrip(".")
    if not value or len(value) > 253 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise UnsafeTarget("invalid_hostname")
    if any(c in value for c in "/\\@:#?%[]"):
        raise UnsafeTarget("invalid_hostname")
    try:
        ascii_host = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UnsafeTarget("invalid_hostname") from exc
    if len(ascii_host) > 253:
        raise UnsafeTarget("invalid_hostname")
    if ascii_host in {"localhost", "local", "internal"} or ascii_host.endswith((".localhost", ".local", ".internal")):
        raise UnsafeTarget("invalid_hostname")
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or
                              any(not (ch.isascii() and (ch.isalnum() or ch == "-")) for ch in label)
                              for label in labels):
        raise UnsafeTarget("invalid_hostname")
    try:
        ipaddress.ip_address(ascii_host)
    except ValueError:
        return ascii_host
    raise UnsafeTarget("ip_literal_not_allowed")


def _is_public_address(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return False
    if any(ip.version == network.version and ip in network for network in _BLOCKED_NETWORKS):
        return False
    # is_global excludes RFC1918, loopback, link-local, shared/CGNAT (including
    # Tailscale's 100.64/10), documentation, multicast, reserved and unspecified.
    return ip.is_global and not ip.is_multicast


def resolve_public_addresses(hostname: str, port: int,
                             resolver: Callable = socket.getaddrinfo) -> list[tuple]:
    host = normalize_hostname(hostname)
    try:
        answers = resolver(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise UnsafeTarget("dns_resolution_failed") from exc
    if not answers:
        raise UnsafeTarget("dns_no_addresses")
    addresses: list[tuple] = []
    seen: set[tuple] = set()
    for family, socktype, proto, canonname, sockaddr in answers:
        address = sockaddr[0]
        if family not in (socket.AF_INET, socket.AF_INET6) or not _is_public_address(address):
            raise UnsafeTarget("unsafe_dns_address")
        key = (family, socktype, proto, sockaddr)
        if key not in seen:
            seen.add(key)
            addresses.append((family, socktype, proto, canonname, sockaddr))
    if not addresses:
        raise UnsafeTarget("dns_no_addresses")
    return addresses


def connect_pinned(hostname: str, port: int, timeout: float,
                   resolver: Callable = socket.getaddrinfo,
                   socket_factory: Callable = socket.socket) -> socket.socket:
    """Connect to a validated IP while preserving the caller's hostname for TLS/HTTP.

    DNS is re-resolved and the complete answer set revalidated before each retry.
    A single socket is connected to one numeric sockaddr, never to the hostname.
    """
    deadline = time.monotonic() + max(0.001, timeout)
    initial = resolve_public_addresses(hostname, port, resolver)
    last_error: OSError | None = None
    max_attempts = min(max(1, len(initial)), 4)
    for attempt in range(max_attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("connection timeout") from last_error
        current = resolve_public_addresses(hostname, port, resolver)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("connection timeout") from last_error
        entry = current[attempt % len(current)]
        family, socktype, proto, _canonname, sockaddr = entry
        sock = socket_factory(family, socktype, proto)
        try:
            sock.settimeout(remaining)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("connection failed")
