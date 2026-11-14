#!/usr/bin/env python3
"""Offline, read-only ZIP structural inventory. Never extracts or runs members.

No names, identities, hashes, raw configuration or PEM contents are reported.
Counts are overlapping content/extension/mode heuristics, NOT exhaustive discovery.
This is NOT an approval, provenance check, PKI audit or installer unlock.
Unknown ZIP extra metadata is rejected (including Unix link encodings).
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_MEMBERS = 128
MAX_MEMBER = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_RATIO = 100
MAX_CENTRAL = 1024 * 1024
MAX_REPORTED_DIRECTIVES = 64  # per config; bounded JSON even for repeated safe lines
PRIVATE = re.compile(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----")
CERTIFICATE = b"-----BEGIN CERTIFICATE-----"
CONFIG_LINE = re.compile(br"(?m)^\s*(?:client|server|remote|proto|dev|port|ca|cert|key|auth-user-pass)(?:\s|$)")


def require(condition):
    if not condition:
        raise ValueError("Unsafe or invalid ZIP")


def safe_name(info):
    # orig_filename retains NULs that ZipInfo.filename would truncate.
    name = info.orig_filename
    require(isinstance(name, str) and name and name == info.filename)
    require(not any(ord(c) < 32 or ord(c) == 127 for c in name))
    require("\\" not in name and ":" not in name and not name.startswith("/"))
    parts = name.rstrip("/").split("/")
    require(all(part not in ("", ".", "..") for part in parts))
    require(not name.endswith("//"))
    return unicodedata.normalize("NFC", name.rstrip("/")).casefold()


def safe_extra(extra):
    # Only the timestamp extra field is accepted; no Unix/ASi/link metadata,
    # Unicode alternate paths, opaque vendor records or unneeded ZIP64 fields.
    seen = set()
    while extra:
        require(len(extra) >= 4)
        tag = int.from_bytes(extra[:2], "little")
        length = int.from_bytes(extra[2:4], "little")
        require(length <= len(extra) - 4 and tag == 0x5455 and tag not in seen)
        value = extra[4:4 + length]
        require(bool(value) and value[0] <= 7)
        require(len(value) == 1 + 4 * bin(value[0]).count("1"))
        seen.add(tag)
        extra = extra[4 + length:]


def zip_layout(stream, archive_size):
    """Bound central metadata and member count BEFORE ZipFile allocates entries.

    Conservative single-disk ZIP only: no ZIP64, prefixed executable, appended
    data or opaque records between the central directory and end record.
    """
    tail_start = max(0, archive_size - 65557)
    stream.seek(tail_start)
    tail = stream.read(65557)
    position = tail.rfind(b"PK\x05\x06")
    require(position >= 0 and len(tail) - position >= 22)
    end = struct.unpack("<4s4H2IH", tail[position:position + 22])
    require(position + 22 + end[7] == len(tail))
    require(end[1] == end[2] == 0 and end[3] == end[4] <= MAX_MEMBERS)
    require(end[5] <= MAX_CENTRAL and end[6] + end[5] == tail_start + position)
    stream.seek(end[6])
    central = stream.read(end[5])
    require(len(central) == end[5])
    offset = count = 0
    while offset < len(central):
        require(len(central) - offset >= 46 and count < MAX_MEMBERS)
        entry = struct.unpack("<4s6H3I5H2I", central[offset:offset + 46])
        require(entry[0] == b"PK\x01\x02" and entry[13] == 0 and 0 < entry[10] <= 4096)
        offset += 46 + entry[10] + entry[11] + entry[12]
        require(offset <= len(central))
        count += 1
    require(count == end[4])
    return end[6]


def safe_value(tokens):
    """Return a canonical allowlisted value, never arbitrary config text."""
    key, values = tokens[0], tokens[1:]
    if key == "port" and len(values) == 1 and re.fullmatch(r"[0-9]{1,5}", values[0]):
        port = int(values[0])
        if 1 <= port <= 65535:
            return str(port)
    if key == "proto" and len(values) == 1 and values[0] in (
            "tcp", "udp", "tcp-server", "tcp-client", "tcp4", "tcp6", "udp4", "udp6",
            "tcp4-server", "tcp6-server", "tcp4-client", "tcp6-client"):
        return values[0]
    if key == "dev" and len(values) == 1 and re.fullmatch(r"(?:tun|tap)[0-9]{0,3}", values[0]):
        return values[0]
    if key == "local" and len(values) == 1:
        try:
            # Scoped addresses may carry arbitrary identifiers: disallow them.
            if "%" not in values[0]:
                return str(ipaddress.ip_address(values[0]))
        except ValueError:
            pass
    if key == "server" and len(values) == 2:
        try:
            network = ipaddress.IPv4Network("/".join(values), strict=True)
            if str(network.netmask) == values[1]:
                return str(network.network_address) + " " + str(network.netmask)
        except ValueError:
            pass
    return None


def sanitized_config(data):
    directives = []
    redacted = 0
    inline = False
    pem = False
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("-----BEGIN "):
            pem = True
        if pem:
            if line.startswith("-----END "):
                pem = False
            redacted += 1
            continue
        if line.startswith("<"):
            inline = not line.startswith("</")
            redacted += 1
            continue
        if inline or line.startswith("-----"):
            redacted += 1
            continue
        tokens = line.split()
        value = safe_value(tokens)
        if value is None or len(directives) >= MAX_REPORTED_DIRECTIVES:
            redacted += 1
        else:
            directives.append({"directive": tokens[0], "value": value})
    return {"directives": directives, "redacted_lines": redacted}


def audit_stream(stream, sanitized=False):
    """Inspect a seekable binary stream. All checks finish before any report."""
    stream.seek(0, 2)
    archive_size = stream.tell()
    require(0 < archive_size <= MAX_ARCHIVE)
    stream.seek(0)
    require(stream.read(4) in (b"PK\x03\x04", b"PK\x05\x06"))
    central_offset = zip_layout(stream, archive_size)
    stream.seek(0)
    counts = dict.fromkeys(("members", "directories", "private_key", "public_certificate",
                            "config", "executable", "other"), 0)
    configs = []
    with zipfile.ZipFile(stream, "r") as archive:
        members = archive.infolist()
        require(len(members) <= MAX_MEMBERS)
        names = set()
        files = set()
        total = 0
        ranges = []
        # Validate every entry BEFORE decompressing any member.
        for info in members:
            name = safe_name(info)
            require(name not in names)
            names.add(name)
            safe_extra(info.extra)
            require(0 <= info.header_offset < archive_size)
            stream.seek(info.header_offset)
            header = stream.read(30)
            require(len(header) == 30)
            fields = struct.unpack("<4s5H3I2H", header)
            require(fields[0] == b"PK\x03\x04" and fields[2] == info.flag_bits
                    and fields[3] == info.compress_type and 0 < fields[9] <= 4096)
            local_name = stream.read(fields[9])
            require(len(local_name) == fields[9])
            require(local_name.decode("utf-8" if info.flag_bits & 0x800 else "cp437") == info.orig_filename)
            if not info.flag_bits & 8:  # no data descriptor: local sizes/CRC must match
                require(fields[6:9] == (info.CRC, info.compress_size, info.file_size))
            local_extra = stream.read(fields[10])
            require(len(local_extra) == fields[10])
            safe_extra(local_extra)
            end = info.header_offset + 30 + fields[9] + fields[10] + info.compress_size
            require(end <= central_offset)
            ranges.append((info.header_offset, end))
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            directory = info.is_dir()
            require(kind in (0, stat.S_IFDIR if directory else stat.S_IFREG))
            require(not (info.external_attr & 0x08))  # DOS volume label
            require(not (info.external_attr & 0x10) or directory)
            require(not info.flag_bits & ~(0x800 | 8 | 6))  # UTF-8, descriptor, deflate options only
            require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
            require(0 <= info.file_size <= MAX_MEMBER and info.compress_size >= 0)
            require(info.file_size <= MAX_RATIO * max(1, info.compress_size))
            require(not directory or info.file_size == 0)
            total += info.file_size
            require(total <= MAX_TOTAL)
            if not directory:
                files.add(name)
        ranges.sort()
        require(not ranges or ranges[0][0] == 0)
        require(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])))
        for name in names:
            require(not any("/".join(name.split("/")[:i]) in files
                            for i in range(1, len(name.split("/")))))
        for info in members:
            counts["members"] += 1
            if info.is_dir():
                counts["directories"] += 1
                continue
            with archive.open(info, "r") as member:
                data = member.read(MAX_MEMBER + 1)
            require(len(data) == info.file_size and len(data) <= MAX_MEMBER)
            suffix = Path(info.filename).suffix.lower()
            # Opaque key/PKCS#12 and DER certificate extensions are conservative
            # candidates too; counts do not assert parsing, trust or completeness.
            private = bool(PRIVATE.search(data)) or suffix in (".key", ".p12", ".pfx", ".ppk")
            certificate = CERTIFICATE in data or suffix in (".crt", ".cer")
            config = suffix in (".ovpn", ".conf", ".cfg") or bool(CONFIG_LINE.search(data))
            executable = bool((info.external_attr >> 16) & 0o111) or data.startswith(
                (b"\x7fELF", b"MZ", b"#!")) or suffix in (".sh", ".py", ".exe", ".dll", ".so")
            for label, present in (("private_key", private), ("public_certificate", certificate),
                                   ("config", config), ("executable", executable)):
                counts[label] += int(present)
            counts["other"] += int(not any((private, certificate, config, executable)))
            if sanitized and config:
                configs.append(sanitized_config(data))
    result = {"status": "structural_report_only", "manual_review_required": True,
              "installation_status": "BLOCKED", "counts": counts}
    if sanitized:
        result["sanitized_configs"] = configs
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--sanitized-report", action="store_true",
                        help="Include only canonical port/proto/dev/local/server values")
    args = parser.parse_args(argv)
    try:
        # Never follow a final symlink, open a pipe/device, or modify the archive.
        before = args.archive.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_ARCHIVE)
        fd = os.open(args.archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            after = os.fstat(stream.fileno())
            require(stat.S_ISREG(after.st_mode) and after.st_ino == before.st_ino
                    and after.st_dev == before.st_dev)
            report = audit_stream(stream, args.sanitized_report)
    except (ValueError, OSError, EOFError, RuntimeError, NotImplementedError,
            struct.error, zlib.error, zipfile.BadZipFile):
        # Never echo exception text, filenames, ZIP comments, paths or contents.
        print(json.dumps({"status": "rejected", "manual_review_required": True,
                          "installation_status": "BLOCKED"}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
