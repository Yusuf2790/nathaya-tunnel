#!/usr/bin/env python3
"""Read-only production checks plus pure policy helpers. Never changes services."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

def required_listeners(ports):
    result = {}
    for port in ports["public"]["haproxy"]: result[port] = ("nathaya-haproxy.service", False)
    result[ports["public"]["tls_download"]] = ("nathaya-nginx.service", False)
    result[ports["public"]["dropbear"]] = ("nathaya-dropbear.service", False)
    for name, unit in (("nginx_ws", "nathaya-nginx"), ("nginx_grpc", "nathaya-nginx"),
                       ("ssh_relay", "nathaya-ws"), ("dropbear", "nathaya-dropbear"),
                       ("sshd_tls", "nathaya-sshd"), ("sshd_plain", "nathaya-sshd")):
        result[ports["internal"][name]] = (unit + ".service", True)
    for proto, route in ports["routes"].items():
        for field in ("ws_port", "grpc_port", "stats_port"):
            result[route[field]] = (proto + "@config.service", True)
    return result

def parse_ss(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5: continue
        address = fields[3]
        host, _, raw_port = address.rpartition(":")
        if raw_port.isdecimal():
            rows.append((host.strip("[]"), int(raw_port), [int(p) for p in re.findall(r"pid=(\d+)", line)]))
    return rows

def pid_in_unit(pid, unit):
    try: return ("/" + unit) in Path(f"/proc/{pid}/cgroup").read_text()
    except OSError: return False

def check_rows(rows, required, verify=False, managed=False, belongs=pid_in_unit):
    found = set()
    for host, port, pids in rows:
        if port not in required: continue
        unit, local = required[port]
        if not managed or not any(belongs(pid, unit) for pid in pids):
            raise ValueError(f"Port conflict: {port}; existing admin/foreign listener will NOT be moved")
        if local and host not in ("127.0.0.1", "::1"):
            raise ValueError(f"Internal listener exposed: {port}")
        found.add(port)
    if verify and found != set(required):
        raise ValueError("Required listeners missing: " + ",".join(map(str, sorted(set(required) - found))))

def main():
    ports = json.loads((ROOT / "config/ports.json").read_text())
    required = required_listeners(ports)
    registry = Path("/etc/nathaya-tunnel/managed-services.json")
    managed = False
    state = {"files": {}}
    if registry.exists():
        if registry.is_symlink() or registry.stat().st_uid != 0 or registry.stat().st_mode & 0o077:
            raise ValueError("Untrusted service registry")
        state = json.loads(registry.read_text())
        managed = state.get("schema") == 1 and state.get("owner") == "Nathaya Tunnel"
        if not managed: raise ValueError("Foreign registry")
    # Fixed global units: never overwrite another app or an edited root unit silently.
    names = {unit for unit, _ in required.values()}
    names |= {p + suffix for p in ("nathaya-ssh-expire", "nathaya-cert-renew", "nathaya-update") for suffix in (".service", ".timer")}
    for name in names:
        path = Path("/etc/systemd/system") / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or str(path) not in state["files"] or hashlib.sha256(path.read_bytes()).hexdigest() != state["files"][str(path)]:
                raise ValueError("Foreign/edited unit conflict: " + name)
    for name in ("nginx.conf", "haproxy.cfg"):
        path = Path("/etc/nathaya-tunnel/services") / name
        if path.exists() and str(path) not in state["files"]: raise ValueError("Unmanaged proxy config")
    result = subprocess.run(["ss", "-H", "-ltnp"], check=True, text=True, capture_output=True)
    check_rows(parse_ss(result.stdout), required, verify=sys.argv[1] == "verify-listeners", managed=managed)

if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("BLOCKED preflight/listener: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
