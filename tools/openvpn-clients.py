#!/usr/bin/env python3
"""Standalone offline LEGACY client fixture generator, NOT server installation.

Requires explicit insecure-mode acknowledgement and a caller-supplied public CA.
Writes only three known client profiles (optionally allovpn.zip) to a NEW directory
under the platform temporary directory. No network, subprocess, server PKI, client
keys, archive imports, installer configuration, locks or runtime overrides.
Certificate checks are structural, NOT signature/provenance/trust verification.
OpenVPN installation remains BLOCKED; compatibility and PKI need manual review.
Legacy directives adapted from Alrescha79 setup.sh:835-909; see NOTICE and MIT.
"""
import argparse
import base64
import binascii
from datetime import datetime
import io
import ipaddress
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
PROFILES = (("client-tcp.ovpn", "tcp", 1194), ("client-udp.ovpn", "udp", 2200),
            ("client-ssl.ovpn", "tcp", 443))
MAX_CA = 65536
COMMON_TAIL = ("persist-key", "persist-tun", "pull", "resolv-retry infinite", "nobind",
               "user nobody", "comp-lzo", "remote-cert-tls server", "verb 3", "mute 2",
               "connect-retry 5 5", "connect-retry-max 8080", "mute-replay-warnings",
               "redirect-gateway def1", "script-security 2", "cipher none", "auth none")


def require(condition):
    if not condition:
        raise ValueError("Invalid input or unsafe output")


def der_items(data):
    """Small bounded DER reader; no indefinite, nonminimal or truncated lengths."""
    result = []
    offset = 0
    while offset < len(data):
        require(offset + 2 <= len(data))
        tag, length = data[offset:offset + 2]
        require(tag & 31 != 31)
        offset += 2
        if length & 128:
            count = length & 127
            require(1 <= count <= 3 and offset + count <= len(data))
            require(data[offset] != 0)
            length = int.from_bytes(data[offset:offset + count], "big")
            require(length >= 128)
            offset += count
        require(offset + length <= len(data))
        result.append((tag, data[offset:offset + length]))
        offset += length
    return result


def sequence(data):
    items = der_items(data)
    require(len(items) == 1 and items[0][0] == 0x30)
    return der_items(items[0][1])


def integer(data):
    require(bool(data) and not data[0] & 128)
    require(len(data) == 1 or data[0] != 0 or data[1] & 128)
    return int.from_bytes(data, "big")


def algorithm(item):
    require(item[0] == 0x30)
    fields = der_items(item[1])
    require(1 <= len(fields) <= 2 and fields[0][0] == 6 and bool(fields[0][1]))
    if len(fields) == 2 and fields[1][0] == 5:
        require(fields[1][1] == b"")


def name(item):
    require(item[0] == 0x30 and bool(item[1]))
    for tag, rdn in der_items(item[1]):
        require(tag == 0x31 and bool(rdn))
        for tag, attribute in der_items(rdn):
            require(tag == 0x30)
            pair = der_items(attribute)
            require(len(pair) == 2 and pair[0][0] == 6 and bool(pair[0][1]))
            require(pair[1][0] in (12, 18, 19, 20, 22, 28, 30) and bool(pair[1][1]))


def certificate_der(data):
    cert = sequence(data)
    require(len(cert) == 3 and cert[0][0] == 0x30 and cert[2][0] == 3)
    algorithm(cert[1])
    require(len(cert[2][1]) > 1 and cert[2][1][0] == 0)
    fields = der_items(cert[0][1])
    require(len(fields) == 8 and fields[0] == (0xa0, b"\x02\x01\x02"))
    require(fields[1][0] == 2 and 0 < integer(fields[1][1]) and len(fields[1][1]) <= 20)
    algorithm(fields[2])
    require(fields[2] == cert[1])
    name(fields[3])
    require(fields[4][0] == 0x30)
    times = der_items(fields[4][1])
    require(len(times) == 2)
    parsed = []
    for tag, value in times:
        require(tag in (23, 24))
        text = value.decode("ascii")
        require(bool(re.fullmatch(r"[0-9]{12}Z" if tag == 23 else r"[0-9]{14}Z", text)))
        if tag == 23:  # X.509 UTCTime pivot is 1950, not strptime's 1969.
            text = ("19" if int(text[:2]) >= 50 else "20") + text
        parsed.append(datetime.strptime(text, "%Y%m%d%H%M%SZ"))
    require(parsed[0] < parsed[1])
    name(fields[5])
    require(fields[6][0] == 0x30)
    public_key = der_items(fields[6][1])
    require(len(public_key) == 2 and public_key[1][0] == 3)
    algorithm(public_key[0])
    require(len(public_key[1][1]) > 1 and public_key[1][1][0] == 0)
    # Only v3 CA certificates with explicit BasicConstraints CA:TRUE are accepted;
    # a public server/leaf certificate is not a substitute for a CA.
    require(fields[7][0] == 0xa3)
    extensions = sequence(fields[7][1])
    seen = set()
    is_ca = False
    for tag, content in extensions:
        require(tag == 0x30)
        ext = der_items(content)
        require(len(ext) in (2, 3) and ext[0][0] == 6 and bool(ext[0][1]))
        oid = ext[0][1]
        require(oid not in seen)
        seen.add(oid)
        if len(ext) == 3:
            require(ext[1] == (1, b"\xff"))
        require(ext[-1][0] == 4)
        if oid == b"\x55\x1d\x13":
            constraints = sequence(ext[-1][1])
            require(1 <= len(constraints) <= 2 and constraints[0] == (1, b"\xff"))
            if len(constraints) == 2:
                require(constraints[1][0] == 2)
                integer(constraints[1][1])
            is_ca = True
    require(is_ca)


def public_ca(data):
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_CA)
    require(b"PRIVATE KEY" not in data.upper())
    match = re.fullmatch(br"[\r\n]*-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END CERTIFICATE-----[\r\n]*", data)
    require(match is not None)
    encoded = match[1].replace(b"\r", b"").replace(b"\n", b"")
    try:
        der = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(der) == encoded)
        certificate_der(der)
    except (ValueError, UnicodeError, binascii.Error, OverflowError):
        raise ValueError("Invalid public CA certificate") from None
    wrapped = b"\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64))
    return b"-----BEGIN CERTIFICATE-----\n" + wrapped + b"\n-----END CERTIFICATE-----\n"


def validate_host(host):
    require(isinstance(host, str) and host and host == host.strip() and "%" not in host)
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        require(len(host) <= 253 and host.isascii())
        require(all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in host.split(".")))
        return host.lower()


def read_regular(path, maximum):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        require(not part.is_symlink())
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum)
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum)
    return data


def render_clients(host, ca):
    host = validate_host(host)
    ca = public_ca(ca)
    result = {}
    for filename, proto, port in PROFILES:
        template = read_regular(ROOT / "templates/openvpn" / (filename + ".in"), 8192).decode("ascii")
        directives = tuple(line for line in template.splitlines() if line and not line.startswith("#"))
        expected = ("auth-user-pass", "client", "dev tun", "proto " + proto,
                    "remote @HOST@ " + str(port)) + COMMON_TAIL
        require(directives == expected and template.count("@HOST@") == 1)
        result[filename] = (template.replace("@HOST@", host) + "<ca>\n").encode("ascii") + ca + b"</ca>\n"
    return result


def zip_clients(profiles):
    require(set(profiles) == {item[0] for item in PROFILES})
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_STORED) as archive:
        # Whitelist only; never glob/walk/copy other files from any directory.
        for filename, _, _ in PROFILES:
            info = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, profiles[filename])
    return result.getvalue()


def write_clients(output_directory, profiles, with_zip=False):
    """Create a new temp child with exclusive, dir-fd-relative fixed filenames."""
    require(set(profiles) == {item[0] for item in PROFILES})
    requested = Path(output_directory)
    require(".." not in requested.parts)
    output = Path(os.path.abspath(requested))
    base = Path(os.path.abspath(tempfile.gettempdir()))
    require(base != Path("/") and output != base and output.is_relative_to(base))
    payloads = dict(profiles)
    if with_zip:
        payloads["allovpn.zip"] = zip_clients(profiles)
    # Walk from / using O_NOFOLLOW, so no ancestor can redirect the writes.
    parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in output.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)  # fails if it exists
        directory_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=parent_fd)
        try:
            for filename, data in payloads.items():
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
        finally:
            os.close(directory_fd)
    finally:
        os.close(parent_fd)
    # On I/O failure leave only the incomplete private temp directory for manual
    # disposal. Never recursively delete a caller's directory or follow links.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ca-file", type=Path, required=True, help="One PUBLIC CA PEM; never a server/client key")
    parser.add_argument("--output-directory", type=Path, required=True, help="NEW child of the system temp directory")
    parser.add_argument("--zip", action="store_true", help="Also create allovpn.zip containing only the three profiles")
    parser.add_argument("--acknowledge-legacy-insecure", action="store_true",
                        help="Required: comp-lzo, cipher none and auth none are intentionally preserved")
    args = parser.parse_args(argv)
    if not args.acknowledge_legacy_insecure:
        print("BLOCKED: --acknowledge-legacy-insecure is required.", file=sys.stderr)
        return 1
    try:
        profiles = render_clients(args.host, read_regular(args.ca_file, MAX_CA))
        write_clients(args.output_directory, profiles, args.zip)
    except (ValueError, OSError, UnicodeError):
        print("BLOCKED: invalid public CA, host, templates or NEW temporary output directory.", file=sys.stderr)
        return 1
    print("Legacy insecure client profiles created; manual review required. Server installation remains BLOCKED.")
    for filename in profiles:
        print(filename)
    if args.zip:
        print("allovpn.zip")
    return 0


if __name__ == "__main__":
    sys.exit(main())
