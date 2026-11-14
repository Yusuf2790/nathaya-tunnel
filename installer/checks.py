#!/usr/bin/env python3
"""Read-only production checks plus pure policy helpers. Never changes services."""
import hashlib
import importlib.util
import grp
import pwd
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

_SSH_LIMIT = 64 * 1024
_SSH_TYPES = frozenset(("Stream", "Datagram", "SequentialPacket"))
_SSH_FIELDS = frozenset(("family", "address", "port", "type"))
_SSH_SPACE = " \t\r\n"
_SSH_ENTRY = re.compile(
    r"(?:Listen=[ \t\r\n]*)?"
    r"(?P<endpoint>\[[^\[\]\s]+\]:[0-9]+|[0-9.]+:[0-9]+)"
    r"[ \t\r\n]*\([ \t\r\n]*(?P<type>Stream|Datagram|SequentialPacket)[ \t\r\n]*\)"
)


def _ssh_invalid():
    # Never interpolate listener data, file paths or JSON parser diagnostics.
    raise ValueError("Invalid SSH listener data") from None


def _ssh_address(address, family):
    if type(address) is not str or not address:
        _ssh_invalid()
    try:
        if family == "IPv4":
            return str(ipaddress.IPv4Address(address))
        base, marker, scope = address.partition("%")
        if marker and (not scope or any(
                ord(c) < 33 or ord(c) > 126 or c in "%[]():/" for c in scope)):
            _ssh_invalid()
        return ipaddress.IPv6Address(base).compressed + (marker + scope if marker else "")
    except (ValueError, TypeError):
        _ssh_invalid()


def _ssh_sorted(records):
    # Set semantics: duplicates are immaterial, but AF and socket type are not.
    keys = {(r["family"], r["address"], r["port"], r["type"]) for r in records}
    return [dict(zip(("family", "address", "port", "type"), key)) for key in sorted(keys)]


def canonical_ssh_listeners(raw, require_nonempty=True):
    """Parse the complete systemctl Listen value, without wildcard/AF guessing.

    ASCII space, tab, CR and LF are separators; other controls are invalid.
    An optional Listen= prefix is accepted per entry (also for an empty value).
    IPv6 scopes are preserved literally, never resolved as interface names.
    """
    if type(raw) is not str or any(
            (ord(c) < 32 and c not in _SSH_SPACE) or 127 <= ord(c) <= 159 for c in raw):
        _ssh_invalid()
    text = raw.strip(_SSH_SPACE)
    if text == "Listen=":
        text = ""
    records = []
    pos = 0
    while pos < len(text):
        match = _SSH_ENTRY.match(text, pos)
        if match is None:
            _ssh_invalid()
        endpoint = match["endpoint"]
        if endpoint.startswith("["):
            address, port = endpoint[1:].split("]:")
            family = "IPv6"
        else:
            address, port = endpoint.split(":")
            family = "IPv4"
        # Bound conversion as well as the numeric value (leading zeroes allowed).
        port = port.lstrip("0") or "0"
        if len(port) > 5 or not 1 <= int(port) <= 65535:
            _ssh_invalid()
        records.append({"family": family, "address": _ssh_address(address, family),
                        "port": int(port), "type": match["type"]})
        pos = match.end()
        if pos < len(text) and text[pos] not in _SSH_SPACE:
            _ssh_invalid()
        while pos < len(text) and text[pos] in _SSH_SPACE:
            pos += 1
    if require_nonempty and not records:
        _ssh_invalid()
    return _ssh_sorted(records)


def validate_ssh_listener_set(value, require_nonempty=True):
    """Validate a canonical JSON-array schema; normalize only order/duplicates.

    Addresses must already have canonical numeric spelling, including a literal
    optional IPv6 zone. bool is not an integer port and extra fields are invalid.
    """
    if type(value) is not list or (require_nonempty and not value):
        _ssh_invalid()
    for record in value:
        if type(record) is not dict or set(record) != _SSH_FIELDS:
            _ssh_invalid()
        family, address, port, kind = (record[k] for k in ("family", "address", "port", "type"))
        if (type(family) is not str or family not in ("IPv4", "IPv6") or
                type(kind) is not str or kind not in _SSH_TYPES or
                type(port) is not int or not 1 <= port <= 65535):
            _ssh_invalid()
        if _ssh_address(address, family) != address:
            _ssh_invalid()
    return _ssh_sorted(value)


def ssh_listener_diff(before, after):
    """Return only the canonical removed/added records, allowing empty sets."""
    before = validate_ssh_listener_set(before, require_nonempty=False)
    after = validate_ssh_listener_set(after, require_nonempty=False)
    return {"removed": [r for r in before if r not in after],
            "added": [r for r in after if r not in before]}


def _ssh_read_json(path):
    # No owner restriction: ordinary regular-file fixtures are intentionally OK.
    # Walk directories by fd so neither ancestors nor the final file may be
    # symlinks. Descriptor checks avoid the usual lstat/open replacement race.
    parts = path.split("/")
    if not parts[-1]:
        _ssh_invalid()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    directory = os.open("/" if path.startswith("/") else ".", flags | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            if part in ("", "."):
                continue
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], flags, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _SSH_LIMIT:
            _ssh_invalid()
        raw = stream.read(_SSH_LIMIT + 1)
    if len(raw) > _SSH_LIMIT:
        _ssh_invalid()

    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _ssh_invalid()
            result[key] = value
        return result

    def invalid_constant(_value):
        _ssh_invalid()

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields,
                      parse_constant=invalid_constant)


def _ssh_cli(args):
    try:
        if args[0] == "canonical-ssh-listeners":
            if args[1:] not in ([], ["--allow-empty"]):
                _ssh_invalid()
            raw = sys.stdin.buffer.read(_SSH_LIMIT + 1)
            if len(raw) > _SSH_LIMIT:
                _ssh_invalid()
            result = canonical_ssh_listeners(raw.decode("utf-8"),
                                             require_nonempty=args[1:] != ["--allow-empty"])
            status = 0
        else:
            if len(args) != 3:
                _ssh_invalid()
            result = ssh_listener_diff(_ssh_read_json(args[1]), _ssh_read_json(args[2]))
            status = int(bool(result["removed"] or result["added"]))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return status
    except (OSError, ValueError, TypeError, RecursionError):
        print("BLOCKED SSH listeners: invalid input", file=sys.stderr)
        return 2


_HAPROXY_UNIT = "/etc/systemd/system/nathaya-haproxy.service"
_HAPROXY_CAPS = 0x4e0  # KILL, SETGID, SETUID, NET_BIND_SERVICE only.
_PROC_LIMIT = 64 * 1024


def _haproxy_invalid():
    raise ValueError("Invalid HAProxy identity") from None


def parse_haproxy_status(raw):
    """Pure /proc status parser: require all identity fields, reject duplicates."""
    wanted = {"Pid", "PPid", "Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapAmb", "NoNewPrivs"}
    if type(raw) is not str or len(raw) > _PROC_LIMIT:
        _haproxy_invalid()
    result = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if key not in wanted:
            continue
        if not separator or key in result:
            _haproxy_invalid()
        fields = value.split()
        count = len(fields) if key == "Groups" else 4 if key in ("Uid", "Gid") else 1
        if count > 1024:
            _haproxy_invalid()
        pattern = r"[0-9a-fA-F]{1,16}" if key.startswith("Cap") else r"[0-9]{1,10}"
        if len(fields) != count or any(not re.fullmatch(pattern, f) for f in fields):
            _haproxy_invalid()
        values = tuple(int(f, 16 if key.startswith("Cap") else 10) for f in fields)
        result[key] = values if key in ("Uid", "Gid", "Groups") else values[0]
    if set(result) != wanted:
        _haproxy_invalid()
    return result


def validate_haproxy_identity(master, workers, uid, gid):
    """Pure policy: root master with exact narrow caps; unprivileged workers only."""
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0 or not workers:
        _haproxy_invalid()
    if (master["Uid"] != (0,) * 4 or master["Gid"] != (0,) * 4 or
            master["CapEff"] != _HAPROXY_CAPS or master["CapPrm"] != _HAPROXY_CAPS or
            master["CapAmb"] != 0 or master["NoNewPrivs"] != 1):
        _haproxy_invalid()
    for worker in workers:
        if (worker["Uid"] != (uid,) * 4 or worker["Gid"] != (gid,) * 4 or
                any(group != gid for group in worker["Groups"]) or
                any(worker[key] != 0 for key in ("CapEff", "CapPrm", "CapAmb")) or
                worker["NoNewPrivs"] != 1 or worker["PPid"] != master["Pid"]):
            _haproxy_invalid()
    return True


def _proc_text(path):
    with path.open("rb") as stream:
        raw = stream.read(_PROC_LIMIT + 1)
    if len(raw) > _PROC_LIMIT:
        _haproxy_invalid()
    return raw.decode("ascii")


def _haproxy_children(pid):
    raw = _proc_text(Path(f"/proc/{pid}/task/{pid}/children"))
    fields = raw.split()
    if (not fields or len(fields) > 1024 or
            any(not re.fullmatch(r"[1-9][0-9]{0,9}", f) for f in fields)):
        _haproxy_invalid()
    result = [int(f) for f in fields]
    if len(set(result)) != len(result) or pid in result:
        _haproxy_invalid()
    return sorted(result)


def _haproxy_process(pid):
    base = Path(f"/proc/{pid}")
    if os.readlink(base / "exe") != "/usr/sbin/haproxy":
        _haproxy_invalid()
    value = parse_haproxy_status(_proc_text(base / "status"))
    if value["Pid"] != pid:
        _haproxy_invalid()
    return value


def verify_haproxy_identity(pid):
    """Read-only, bounded snapshot; children come ONLY from the supplied master."""
    if type(pid) is not int or not 1 <= pid <= 2147483647:
        _haproxy_invalid()
    account, group = pwd.getpwnam("haproxy"), grp.getgrnam("haproxy")
    if account.pw_gid != group.gr_gid:
        _haproxy_invalid()
    children = _haproxy_children(pid)
    master = _haproxy_process(pid)
    workers = [_haproxy_process(child) for child in children]
    validate_haproxy_identity(master, workers, account.pw_uid, group.gr_gid)
    # Fail closed on observed exits/reloads/identity changes; never retry forever.
    if (children != _haproxy_children(pid) or master != _haproxy_process(pid) or
            workers != [_haproxy_process(child) for child in children]):
        _haproxy_invalid()


def _metadata():
    spec = importlib.util.spec_from_file_location("nathaya_check_metadata", ROOT / "installer/state.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_managed_unit_hashes(state, root=Path("/")):
    """Compare against the EXISTING registry, never against the new renderer."""
    metadata = _metadata()
    files = state["files"] if state is not None else {}
    for name in metadata.unit_paths():
        path = metadata._safe(root / name.lstrip("/"), root == Path("/"))
        if name in files and not path.exists():
            raise ValueError("Missing registered managed unit")
        if path.exists():
            if name not in files or hashlib.sha256(path.read_bytes()).hexdigest() != files[name]:
                raise ValueError("Foreign/edited managed unit")


def validate_haproxy_unit(fragment, dropins, load, owned, exists):
    """Pure effective-unit policy; not-found is safe only when genuinely absent."""
    if dropins:
        raise ValueError("HAProxy unit override conflict")
    if load == "not-found" and not fragment and not exists and not owned:
        return
    if load != "loaded" or fragment != _HAPROXY_UNIT or not owned or not exists:
        raise ValueError("HAProxy effective unit conflict")


def check_haproxy_unit(root=Path("/"), state=None):
    metadata = _metadata()
    if state is None:
        state, _raw = metadata.read_service_registry(root)
    check_managed_unit_hashes(state, root)
    values = []
    for prop in ("FragmentPath", "DropInPaths", "LoadState"):
        result = subprocess.run(["systemctl", "show", "nathaya-haproxy.service",
                                 "--property=" + prop, "--value"],
                                check=False, text=True, capture_output=True, timeout=10)
        if result.returncode != 0 or type(result.stdout) is not str or len(result.stdout) > _PROC_LIMIT:
            raise ValueError("HAProxy unit inspection failed")
        values.append(result.stdout.strip())
    path = root / _HAPROXY_UNIT.lstrip("/")
    validate_haproxy_unit(*values, owned=state is not None and _HAPROXY_UNIT in state["files"],
                          exists=path.exists())


def _haproxy_cli(args):
    try:
        if args[0] == "verify-haproxy-identity":
            if len(args) != 2 or not re.fullmatch(r"[1-9][0-9]{0,9}", args[1]):
                _haproxy_invalid()
            verify_haproxy_identity(int(args[1]))
        else:
            if len(args) != 1:
                _haproxy_invalid()
            check_haproxy_unit()
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, subprocess.SubprocessError):
        print("BLOCKED HAProxy: identity/unit validation failed", file=sys.stderr)
        return 1


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
    if sys.argv[1:2] in (["canonical-ssh-listeners"], ["compare-ssh-listeners"]):
        return _ssh_cli(sys.argv[1:])
    if sys.argv[1:2] in (["verify-haproxy-identity"], ["check-haproxy-unit"]):
        return _haproxy_cli(sys.argv[1:])
    ports = json.loads((ROOT / "config/ports.json").read_text())
    required = required_listeners(ports)
    state, _raw = _metadata().read_service_registry()
    managed = state is not None
    if sys.argv[1:2] == ["preflight"]:
        check_haproxy_unit(state=state)
    state = state if state is not None else {"files": {}}
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
    try: raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("BLOCKED preflight/listener: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
