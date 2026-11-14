#!/usr/bin/env python3
"""Fixed-path, root-only metadata writer. Does not import or source runtime config."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path
import sys
import tempfile

def atomic_json(path, value):
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("Unsafe metadata path")
    fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def canonical_version(raw):
    if isinstance(raw, bytes):
        try: raw = raw.decode("ascii")
        except UnicodeError as exc: raise ValueError("Invalid VERSION") from exc
    if not isinstance(raw, str) or not re.fullmatch(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\n", raw):
        raise ValueError("VERSION must be canonical MAJOR.MINOR.PATCH plus newline")
    return raw[:-1]

def _version_tuple(value):
    return tuple(map(int, canonical_version(value + "\n").split(".")))

def _safe(path, production=False):
    path = Path(os.path.abspath(path))
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try: info = current.lstat()
        except FileNotFoundError: continue
        if stat.S_ISLNK(info.st_mode): raise ValueError("Symlink metadata path")
        if current != path and not stat.S_ISDIR(info.st_mode): raise ValueError("Invalid metadata parent")
        if production and (info.st_uid != 0 or info.st_mode & 0o022): raise ValueError("Untrusted metadata owner/mode")
        if current == path and not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ValueError("Unsafe metadata file")
    return path

def _read(path, production=False):
    path = _safe(path, production)
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384: raise ValueError("Unsafe metadata size/type")
        data = stream.read(16385)
    if len(data) > 16384: raise ValueError("Metadata size exceeded")
    return data

def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("Duplicate metadata key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def inspect_install(source, root=Path("/")):
    """Read-only preflight. Explicit fixture root is internal, never a CLI option."""
    root = Path(os.path.abspath(root))
    production = root == Path("/")
    candidate = canonical_version(_read(Path(source) / "VERSION"))
    version_path = _safe(root / "opt/nathaya/VERSION", production)
    state_path = _safe(root / "opt/nathaya/updater-state/installed.json", production)
    pending = _safe(root / "opt/nathaya/updater-state/pending.json", production)
    if pending.exists(): raise ValueError("Pending updater recovery must be resolved before setup")
    version_raw = _read(version_path, production) if version_path.exists() else None
    previous = canonical_version(version_raw) if version_raw is not None else None
    state_raw = _read(state_path, production) if state_path.exists() else None
    baseline = _json(state_raw) if state_raw is not None else None
    if baseline is not None:
        if stat.S_IMODE(state_path.stat().st_mode) != 0o600: raise ValueError("Baseline must be private 0600")
        if not isinstance(baseline, dict) or set(baseline) != {"schema", "version"} or type(baseline["schema"]) is not int or baseline["schema"] != 1:
            raise ValueError("Unsupported application-state schema; no automatic migration")
        if previous is None or baseline["version"] != previous: raise ValueError("Installed identity inconsistent; restore/reconcile before setup")
    if previous is not None and _version_tuple(candidate) < _version_tuple(previous): raise ValueError("Installer downgrade rejected")
    return {"schema": 1, "candidate": candidate, "previous_version": previous, "baseline": baseline,
            "version_sha256": hashlib.sha256(version_raw).hexdigest() if version_raw is not None else None,
            "baseline_sha256": hashlib.sha256(state_raw).hexdigest() if state_raw is not None else None}

def prepare_install(source, root, journal):
    snapshot = inspect_install(source, root)
    atomic_json(_safe(journal, Path(root) == Path("/")), snapshot)
    return snapshot

def validate_prepared(source, root, journal):
    saved = _json(_read(journal, Path(root) == Path("/")))
    if saved != inspect_install(source, root): raise ValueError("Install baseline/source changed after lock")
    return saved

def commit_install(source, root, journal):
    root = Path(os.path.abspath(root))
    production = root == Path("/")
    saved = _json(_read(journal, production))
    expected = {"schema", "candidate", "previous_version", "baseline", "version_sha256", "baseline_sha256"}
    if not isinstance(saved, dict) or set(saved) != expected or type(saved["schema"]) is not int or saved["schema"] != 1:
        raise ValueError("Invalid install snapshot")
    candidate = canonical_version(_read(Path(source) / "VERSION"))
    if saved["candidate"] != candidate or (saved["previous_version"] is not None and _version_tuple(candidate) < _version_tuple(saved["previous_version"])):
        raise ValueError("Candidate changed/downgrade")
    if _safe(root / "opt/nathaya/updater-state/pending.json", production).exists(): raise ValueError("Pending recovery")
    if canonical_version(_read(root / "opt/nathaya/VERSION", production)) != candidate: raise ValueError("Deployed VERSION mismatch")
    state_path = _safe(root / "opt/nathaya/updater-state/installed.json", production)
    raw = _read(state_path, production) if state_path.exists() else None
    digest = hashlib.sha256(raw).hexdigest() if raw is not None else None
    if digest != saved["baseline_sha256"]: raise ValueError("Baseline changed during installation")
    current = _json(raw) if raw is not None else None
    if current != saved["baseline"]: raise ValueError("Baseline mismatch")
    if current != {"schema": 1, "version": candidate}:
        atomic_json(state_path, {"schema": 1, "version": candidate})
    return candidate

def unit_paths():
    units = ["nathaya-sshd", "nathaya-dropbear", "nathaya-ws", "nathaya-nginx", "nathaya-haproxy",
             "vmess@config", "vless@config", "trojan@config", "shadowsocks@config",
             "nathaya-ssh-expire", "nathaya-cert-renew", "nathaya-update"]
    result = ["/etc/systemd/system/" + u + ".service" for u in units]
    result += ["/etc/systemd/system/" + u + ".timer" for u in ("nathaya-ssh-expire", "nathaya-cert-renew", "nathaya-update")]
    return result

def main():
    if os.geteuid() != 0: raise ValueError("Root required")
    action = sys.argv[1]
    if action == "check" and len(sys.argv) == 3:
        inspect_install(Path(sys.argv[2]))
    elif action in ("prepare", "validate-prepared", "commit") and len(sys.argv) == 4:
        journal = Path(os.path.abspath(sys.argv[3]))
        if journal.name != "updater-before.json" or journal.parent.parent != Path("/var/backups/nathaya-tunnel") or not journal.parent.name.startswith("run."):
            raise ValueError("Journal must be in the private installer run directory")
        handler = {"prepare": prepare_install, "validate-prepared": validate_prepared, "commit": commit_install}[action]
        handler(Path(sys.argv[2]), Path("/"), journal)
    elif action == "record-services" and len(sys.argv) == 2:
        paths = unit_paths()
        paths += ["/etc/profile.d/nathaya-dashboard.sh", "/usr/local/bin/nathaya-update"]
        paths += ["/etc/nathaya-tunnel/services/" + n for n in ("nginx.conf", "haproxy.cfg")]
        paths += [f"/etc/nathaya-tunnel/xray/{p}/config.json" for p in ("vmess", "vless", "trojan", "shadowsocks")]
        files = {}
        for name in paths:
            path = Path(name)
            if not path.exists() and not path.is_symlink(): continue
            if not path.is_file() or path.is_symlink() or path.stat().st_uid != 0: raise ValueError("Unsafe managed destination")
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        atomic_json(Path("/etc/nathaya-tunnel/managed-services.json"), {"schema": 1, "owner": "Nathaya Tunnel", "files": files})
    else: raise ValueError("Unknown metadata operation")

if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, KeyError): raise SystemExit("Metadata operation failed; no secret values printed")
