"""Trusted schema-1 policy/validator. No imports from a downloaded release.

Only regular USTAR members are accepted; extraction never uses extractall().
The trust base (updater/, tools/, installer/) is packaged but NOT auto-deployed.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import shutil
import subprocess
import tarfile
import zlib

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_MANIFEST = 128 * 1024
MAX_MEMBERS = 256
SOURCE = {"owner": "Yusuf2790", "repo": "nathaya-tunnel"}
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


class Blocked(ValueError):
    """Untrusted, unsupported, inconsistent or unsafe input: fail closed."""


def require(condition, message):
    if not condition:
        raise Blocked(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def version(value):
    require(isinstance(value, str) and
            re.fullmatch(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", value),
            "Only canonical stable MAJOR.MINOR.PATCH versions are supported")
    return tuple(map(int, value.split(".")))


def safe_name(name):
    require(isinstance(name, str) and 0 < len(name.encode("utf-8")) <= 100 and
            re.fullmatch(r"[A-Za-z0-9_./-]+", name) and
            all(part not in ("", ".", "..") and not part.startswith(".")
                for part in name.split("/")), "Unsafe release path")
    return name


def json_bytes(data):
    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Blocked("Invalid JSON number")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Blocked("Invalid JSON") from exc


def safe_path(path, boundary=None, root_owned=False):
    """Check existing ancestors, links, permissions, and regular single-link leaves.

    boundary is ONLY used by fixture APIs (never by the production CLI).
    Production checks all ancestors including /opt and /run.
    """
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "Unsafe filesystem path")
    boundary = Path(boundary) if boundary else Path("/")
    require(path == boundary or boundary in path.parents, "Path outside boundary")
    current = boundary
    for part in ((), path.relative_to(boundary).parts):
        # The first iteration checks the boundary itself.
        components = [None] if not part else part
        for component in components:
            if component is not None:
                current = current / component
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            require(not stat.S_ISLNK(info.st_mode), "Symlink filesystem path blocked")
            is_dir = stat.S_ISDIR(info.st_mode)
            require(is_dir or (current == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                    "Unsafe filesystem object")
            require(current == path or is_dir, "Non-directory ancestor")
            if root_owned:
                require(info.st_uid == 0 and not info.st_mode & 0o022, "Untrusted owner or permissions")
    return path


def read_regular(path, limit=MAX_FILE, boundary=None, root_owned=False):
    path = safe_path(path, boundary, root_owned)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                "Unsafe or oversized file")
        if root_owned:
            require(info.st_uid == 0 and not info.st_mode & 0o022, "Untrusted file")
        raw = stream.read(limit + 1)
        require(len(raw) <= limit, "File exceeds size cap")
        return raw


def load_policy(raw):
    policy = parse_json(raw)
    require(isinstance(policy, dict) and set(policy) ==
            {"schema", "channel", "source", "supported_deployed_schemas", "files"}, "Invalid policy fields")
    require(type(policy["schema"]) is int and policy["schema"] == 1 and
            policy["channel"] == "stable" and policy["source"] == SOURCE and
            policy["supported_deployed_schemas"] == [1] and
            type(policy["supported_deployed_schemas"][0]) is int, "Unsupported policy/source/schema")
    files = policy["files"]
    require(isinstance(files, dict) and 1 <= len(files) < MAX_MEMBERS, "Invalid file policy")
    for name, spec in files.items():
        safe_name(name)
        # Defense in depth: even local policy mistakes must not package runtime secrets.
        require(name in {"VERSION", "NOTICE", "menu.sh", "setup.sh", "config/config.conf.example",
                         "config/ports.json", "licenses/Alrescha79-MIT.txt",
                         "docs/install.md", "docs/architecture.md", "docs/update.md",
                         "docs/alrescha-parity.md", "docs/permissions.md",
                         "templates/openvpn/client-tcp.ovpn.in", "templates/openvpn/client-udp.ovpn.in",
                         "templates/openvpn/client-ssl.ovpn.in"} or
                (name.startswith(("modules/", "updater/", "tools/", "installer/", "services/")) and
                 name.endswith((".sh", ".py", ".json", ".service", ".timer"))),
                "Non-program path in policy")
        require(not any(part.lower() in {"data", "logs", "keys", "secrets", "accounts", "cache"}
                        for part in name.split("/")), "Runtime/secret path in policy")
        require(isinstance(spec, dict) and set(spec) == {"mode", "deploy"} and
                spec["mode"] in ("0644", "0755") and type(spec["deploy"]) is bool,
                "Invalid file policy entry")
        if spec["deploy"]:
            require(name in {"VERSION", "menu.sh", "config/config.conf.example"} or
                    name.startswith("modules/"), "Routine updates may replace code only, not the trust base")
    require("VERSION" in files and files["VERSION"] == {"mode": "0644", "deploy": True},
            "VERSION must be deployed")
    names = set(files)
    require(all(not any(parent.as_posix() in names for parent in Path(name).parents
                        if parent != Path(".")) for name in names), "File/directory path collision")
    return policy


def validate_public_example(raw):
    """The packaged example must stay public, empty and inert (never runtime config)."""
    expected = {"DOMAIN": "", "TELEGRAM_STATUS": "OFF", "TELEGRAM_BOT_TOKEN": "", "TELEGRAM_ADMIN_ID": ""}
    values = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise Blocked("Invalid public config example") from exc
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)\s*=\s*(.*)", line)
        require(match is not None, "Invalid public config example")
        key, value = match.groups()
        require(key in expected and key not in values, "Unknown/duplicate public config example key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in (chr(34), chr(39)):
            value = value[1:-1]
        require(value == expected[key], "Public config example must contain only inert defaults")
        values[key] = value
    require(values == expected, "Public config example is incomplete")


def syntax_check(files):
    """Parse only; NEVER source/import/execute release code, including validators."""
    for name, raw in files.items():
        if name.endswith(".sh"):
            try:
                bash = "/bin/bash" if Path("/bin/bash").is_file() else shutil.which("bash")
                require(bash is not None, "Bash syntax checker unavailable")
                result = subprocess.run([bash, "--noprofile", "--norc", "-n"],
                                        input=raw, env=CLEAN_ENV, capture_output=True, timeout=15,
                                        cwd="/", check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Blocked("Bash syntax checker unavailable") from exc
            require(result.returncode == 0, "Bash syntax validation failed")
        elif name.endswith(".py"):
            try:
                compile(raw, name, "exec", dont_inherit=True)
            except (SyntaxError, ValueError, RecursionError) as exc:
                raise Blocked("Python syntax validation failed") from exc


def unpack(blob):
    """Bound gzip expansion before parsing any tar metadata (including PAX bombs).

    No directory, symlink, hardlink, special, PAX or GNU extension is accepted.
    Prefixes are unnecessary: explicit schema-1 paths fit in USTAR's name field.
    """
    require(0 < len(blob) <= MAX_ARCHIVE, "Archive size cap exceeded")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob), mode="rb") as stream:
            raw = stream.read(MAX_EXPANDED + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise Blocked("Corrupt gzip archive") from exc
    require(len(raw) <= MAX_EXPANDED and len(raw) % 512 == 0, "Expanded archive size invalid")
    files, modes, offset = {}, {}, 0
    while offset + 512 <= len(raw):
        header = raw[offset:offset + 512]
        if header == bytes(512):
            require(len(raw) - offset >= 1024 and not any(raw[offset:]), "Invalid tar trailer")
            return files, modes
        require(len(files) < MAX_MEMBERS, "Too many archive members")
        require(header[257:265] == b"ustar\x0000" and not any(header[345:500]),
                "Only plain USTAR headers are supported")
        try:
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
        except (tarfile.TarError, UnicodeError, ValueError) as exc:
            raise Blocked("Invalid tar header") from exc
        name = safe_name(member.name)
        require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and not member.linkname and
                not member.pax_headers and member.uid == 0 and member.gid == 0,
                "Non-regular/untrusted archive member")
        require(name not in files, "Duplicate archive path")
        require(member.mode in (0o644, 0o755) and 0 <= member.size <=
                (MAX_MANIFEST if name == "manifest.json" else MAX_FILE), "Invalid member size/mode")
        start, end = offset + 512, offset + 512 + member.size
        require(end <= len(raw), "Truncated archive member")
        files[name], modes[name] = raw[start:end], f"{member.mode:04o}"
        offset = start + ((member.size + 511) // 512) * 512
    raise Blocked("Missing tar trailer")


def validate_artifact(blob, expected_sha256, expected_version, policy, checker=syntax_check):
    require(isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha256),
            "Trusted SHA256 digest required")
    require(sha256(blob) == expected_sha256, "Artifact digest mismatch")
    version(expected_version)
    files, modes = unpack(blob)
    require(set(files) == set(policy["files"]) | {"manifest.json"}, "Missing/extra archive paths")
    require(modes["manifest.json"] == "0644", "Invalid manifest mode")
    manifest = parse_json(files.pop("manifest.json"))
    require(isinstance(manifest, dict) and set(manifest) == {"schema", "version", "channel", "files"} and
            type(manifest["schema"]) is int and manifest["schema"] == 1 and
            manifest["version"] == expected_version and manifest["channel"] == "stable",
            "Unsupported manifest identity/schema/channel")
    entries = manifest["files"]
    require(isinstance(entries, list) and len(entries) == len(files), "Invalid manifest file list")
    seen = set()
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "mode", "size"},
                "Invalid manifest entry")
        name = safe_name(entry["path"])
        require(name in files and name not in seen, "Duplicate/unknown manifest path")
        seen.add(name)
        require(entry["sha256"] == sha256(files[name]) and type(entry["size"]) is int and
                entry["size"] == len(files[name]) and
                entry["mode"] == modes[name] == policy["files"][name]["mode"],
                "Manifest hash/size/mode mismatch")
    require(files["VERSION"] == (expected_version + "\n").encode("ascii"), "VERSION identity mismatch")
    if "updater/release-policy.json" in files:
        require(load_policy(files["updater/release-policy.json"]) == policy, "Packaged policy differs from trusted policy")
    if "config/config.conf.example" in files:
        validate_public_example(files["config/config.conf.example"])
    checker(files)
    return manifest, files


def build_artifact(source, policy, checker=syntax_check):
    """Read ONLY the explicit local installer program policy; never walk the tree."""
    source = Path(os.path.abspath(source))
    safe_path(source)
    files, total = {}, 0
    for name in sorted(policy["files"]):
        files[name] = read_regular(source / name)
        total += len(files[name])
        require(total <= MAX_EXPANDED - MAX_MANIFEST - MAX_MEMBERS * 1024, "Source exceeds expanded size budget")
    try:
        identity = files["VERSION"].decode("ascii").removesuffix("\n")
    except UnicodeError as exc:
        raise Blocked("Invalid VERSION") from exc
    version(identity)
    require(files["VERSION"] == (identity + "\n").encode("ascii"), "VERSION must have one newline")
    manifest = {"schema": 1, "version": identity, "channel": "stable", "files": [
        {"path": name, "sha256": sha256(raw), "size": len(raw), "mode": policy["files"][name]["mode"]}
        for name, raw in sorted(files.items())]}
    payloads = {"manifest.json": json_bytes(manifest), **files}
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in payloads.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o644 if name == "manifest.json" else int(policy["files"][name]["mode"], 8)
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = "root"
                archive.addfile(member, io.BytesIO(raw))
    blob = output.getvalue()
    # Run the LOCAL trusted validator, not any script from the constructed release.
    validate_artifact(blob, sha256(blob), identity, policy, checker)
    return identity, blob
