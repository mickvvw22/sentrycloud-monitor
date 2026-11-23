#!/usr/bin/env python3
"""Outbound-only probe agent for SentryCloud Monitor."""
from __future__ import annotations

import json
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from cert_probe import probe_certificates
from probe_checks import run_check


@dataclass(frozen=True)
class Config:
    url: str
    token: str = field(repr=False)
    interval: float = 60.0
    timeout: float = 10.0
    insecure_local: bool = False
    cert_hosts: tuple[str, ...] = ()
    agent_id: str = ""

    @classmethod
    def from_env(cls) -> "Config":
        url = os.environ.get("SENTRY_AGENT_URL", "").strip()
        # Each registered probe receives its own token; there is no shared
        # project-wide agent secret in the new control-plane protocol.
        token = os.environ.get("AGENT_TOKEN", os.environ.get("SENTRY_AGENT_TOKEN", ""))
        agent_id = os.environ.get("AGENT_ID", "").strip()
        if not url:
            raise ValueError("SENTRY_AGENT_URL is required")
        if not token:
            raise ValueError("AGENT_TOKEN is required")
        if len(token) < 32:
            raise ValueError("AGENT_TOKEN must be at least 32 characters")
        if not agent_id:
            raise ValueError("AGENT_ID is required")
        try:
            interval = float(os.environ.get("SENTRY_AGENT_INTERVAL", "60"))
            timeout = float(os.environ.get("SENTRY_AGENT_TIMEOUT", "10"))
        except ValueError as exc:
            raise ValueError("SENTRY_AGENT_INTERVAL/TIMEOUT must be numbers") from exc
        if interval <= 0 or timeout <= 0:
            raise ValueError("SENTRY_AGENT_INTERVAL/TIMEOUT must be positive")
        cert_hosts = tuple(host.strip() for host in os.environ.get("SENTRY_AGENT_CERT_HOSTS", "").split(",") if host.strip())
        return cls(url, token, interval, timeout,
                   os.environ.get("SENTRY_AGENT_ALLOW_INSECURE_LOCAL", "").lower() in {"1", "true", "yes"},
                   cert_hosts, agent_id)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def cpu_usage(proc_root: str = "/proc", previous: Optional[tuple[int, int]] = None):
    """Return (percent, new_cpu_totals), or (None, totals) on first sample."""
    line = next((x for x in _read(os.path.join(proc_root, "stat")).splitlines()
                 if x.startswith("cpu ")), None)
    if not line:
        return None, previous
    nums = [int(x) for x in line.split()[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    total = sum(nums)
    if previous is None:
        return None, (total, idle)
    old_total, old_idle = previous
    delta_total, delta_idle = total - old_total, idle - old_idle
    percent = 0.0 if delta_total <= 0 else max(0.0, min(100.0, 100.0 * (delta_total - delta_idle) / delta_total))
    return round(percent, 2), (total, idle)


def memory_usage(proc_root: str = "/proc") -> Dict[str, Any]:
    values: Dict[str, int] = {}
    for line in _read(os.path.join(proc_root, "meminfo")).splitlines():
        key, sep, rest = line.partition(":")
        if sep:
            try:
                values[key] = int(rest.strip().split()[0]) * (1024 if "kB" in rest else 1)
            except (ValueError, IndexError):
                pass
    total, available = values.get("MemTotal", 0), values.get("MemAvailable", values.get("MemFree", 0))
    used = max(0, total - available)
    return {"total_bytes": total, "available_bytes": available, "used_bytes": used,
            "used_percent": round(100 * used / total, 2) if total else None}


def network_bytes(proc_root: str = "/proc") -> Dict[str, int]:
    received = sent = 0
    for line in _read(os.path.join(proc_root, "net", "dev")).splitlines():
        if ":" not in line:
            continue
        iface, data = line.split(":", 1)
        if iface.strip() == "lo":
            continue
        fields = data.split()
        if len(fields) >= 9:
            try:
                received += int(fields[0]); sent += int(fields[8])
            except ValueError:
                pass
    return {"rx_bytes": received, "tx_bytes": sent}


def collect_metrics(proc_root: str = "/proc", root: str = "/", previous_cpu=None) -> tuple[Dict[str, Any], Any]:
    cpu, state = cpu_usage(proc_root, previous_cpu)
    try:
        uptime = float(_read(os.path.join(proc_root, "uptime")).split()[0])
    except (OSError, ValueError, IndexError):
        uptime = None
    try:
        disk = os.statvfs(root)
        total = disk.f_blocks * disk.f_frsize
        free = disk.f_bavail * disk.f_frsize
        disk_data = {"total_bytes": total, "free_bytes": free, "used_bytes": max(0, total - free),
                     "used_percent": round(100 * (total - free) / total, 2) if total else None}
    except OSError:
        disk_data = None
    metrics = {"cpu_used_percent": cpu, "memory": memory_usage(proc_root), "disk": disk_data,
               "network": network_bytes(proc_root), "uptime_seconds": uptime}
    return metrics, state


def _is_local(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname
        return host in {"localhost", "127.0.0.1", "::1"}
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _safe_urlopen(request, timeout):
    # A control-plane redirect must not forward a probe's bearer token.
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def _validate_control_url(config: Config) -> urllib.parse.SplitResult:
    try:
        parsed = urllib.parse.urlsplit(config.url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid SENTRY_AGENT_URL") from exc
    if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("invalid SENTRY_AGENT_URL")
    if parsed.scheme == "https":
        if port not in (None, 443):
            raise ValueError("HTTPS control endpoint must use port 443")
    elif not (parsed.scheme == "http" and config.insecure_local and _is_local(config.url)):
        raise ValueError("HTTPS is required (HTTP is permitted only for explicitly enabled local testing)")
    return parsed


def send_heartbeat(config: Config, metrics: Dict[str, Any], opener: Callable = _safe_urlopen) -> None:
    if not config.agent_id:
        raise ValueError("AGENT_ID is required")
    _validate_control_url(config)
    # Keep this shape stable: the Worker heartbeat endpoint consumes exactly
    # these three fields. In particular, certificates is always an array.
    payload = {"agent_id": config.agent_id, "metrics": metrics,
               "certificates": probe_certificates(config.cert_hosts, config.timeout)
               if config.cert_hosts else []}
    request = urllib.request.Request(config.url, data=json.dumps(payload, separators=(",", ":")).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + config.token},
                                     method="POST")
    with opener(request, timeout=config.timeout) as response:
        if not 200 <= response.status < 300:
            raise urllib.error.HTTPError(config.url, response.status, "heartbeat rejected", response.headers, None)


def _api_url(config: Config, path: str) -> str:
    parsed = _validate_control_url(config)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _api_json(config: Config, path: str, method: str = "GET", payload: Optional[Dict[str, Any]] = None,
              opener: Callable = _safe_urlopen) -> Any:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + config.token, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(_api_url(config, path), data=data, headers=headers, method=method)
    with opener(request, timeout=config.timeout) as response:
        if not 200 <= response.status < 300:
            raise urllib.error.HTTPError(request.full_url, response.status, "probe API rejected", response.headers, None)
        raw = response.read()
        return json.loads(raw) if raw else {}


def poll_and_run_tasks(config: Config, opener: Callable = _safe_urlopen,
                       check_runner: Callable[[Dict[str, Any]], Dict[str, Any]] = run_check) -> int:
    response = _api_json(config, "/api/probe/tasks?limit=20", opener=opener)
    tasks = response.get("tasks", []) if isinstance(response, dict) else []
    if not isinstance(tasks, list):
        raise ValueError("invalid task response")
    completed = 0
    for task in tasks:
        if not isinstance(task, dict) or not isinstance(task.get("check"), dict):
            continue
        result = check_runner(task["check"])
        payload = {
            "check_id": task["check"].get("id"),
            "task_token": task.get("task_token"),
            "ok": bool(result.get("ok")),
            "latency_ms": result.get("latency_ms", 0),
            "error": result.get("error"),
        }
        _api_json(config, "/api/probe/results", method="POST", payload=payload, opener=opener)
        completed += 1
    return completed


def run(config: Config, sleep: Callable[[float], None] = time.sleep,
        opener: Callable = _safe_urlopen, proc_root: str = "/proc", root: str = "/") -> None:
    stopping = False
    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    cpu_state = None
    while not stopping:
        try:
            metrics, cpu_state = collect_metrics(proc_root, root, cpu_state)
            send_heartbeat(config, metrics, opener)
        except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            print("heartbeat/collection failed: " + type(exc).__name__, file=sys.stderr)
        try:
            poll_and_run_tasks(config, opener)
        except (OSError, ValueError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            print("probe task cycle failed: " + type(exc).__name__, file=sys.stderr)
        if not stopping:
            sleep(config.interval)


def main() -> int:
    try:
        run(Config.from_env())
    except ValueError as exc:
        print("configuration error: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
