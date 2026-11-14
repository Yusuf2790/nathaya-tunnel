#!/usr/bin/env python3
"""Pinned GitHub binary acquisition. Never executes downloaded scripts or extractall.
The digest authenticates downloaded bytes against pinned HTTPS release metadata;
this is NOT a publisher signature or a claim of reproducible source builds.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import os
import re
import ssl
import stat
import struct
import urllib.parse
import urllib.request
import zipfile

class Blocked(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise Blocked(message)

def full_blockers(lock):
    # No server contract/opaque executable is accepted until audit is implemented
    # and reviewed. Changing a JSON status alone must not unlock a full install.
    return [f"{key}: {lock[key]['reason']}" for key in
            ("openvpn_archive", "udp_custom", "badvpn")]

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and parsed.hostname in
                ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
                and not parsed.username and not parsed.password, "Untrusted binary redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch(url, limit):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in ("github.com", "api.github.com")
            and not parsed.username and not parsed.password and not parsed.fragment,
            "Untrusted artifact URL")
    request = urllib.request.Request(url, headers={"User-Agent": "Nathaya-Tunnel/2", "Accept": "application/vnd.github+json"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), Redirect())
    with opener.open(request, timeout=30) as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Artifact exceeds size bound")
    return data

def xray_metadata(item):
    require(item["repository"] == "XTLS/Xray-core" and re.fullmatch(r"v[0-9.]+", item["version"]), "Untrusted Xray source/version")
    expected = f"https://github.com/XTLS/Xray-core/releases/download/{item['version']}/Xray-linux-64.zip"
    metadata = f"https://api.github.com/repos/XTLS/Xray-core/releases/tags/{item['version']}"
    require(item["url"] == expected and item["metadata"] == metadata and item["asset"] == "Xray-linux-64.zip"
            and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]), "Invalid Xray lock")
    release = json.loads(fetch(metadata, 2 * 1024 * 1024))
    require(release.get("tag_name") == item["version"] and not release.get("draft") and not release.get("prerelease"), "Not the pinned stable Xray release")
    matches = [a for a in release["assets"] if a["name"] == item["asset"]]
    require(len(matches) == 1, "Xray asset missing/ambiguous")
    asset = matches[0]
    require(asset.get("digest") == "sha256:" + item["sha256"] and asset["browser_download_url"] == expected
            and 0 < asset["size"] <= item["max_bytes"], "Xray release digest unavailable or differs from lock")
    return asset

def unpack_xray(blob, item):
    require(hashlib.sha256(blob).hexdigest() == item["sha256"], "Xray checksum mismatch")
    result = {}
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        infos = archive.infolist()
        require(len(infos) <= 20 and sum(x.file_size for x in infos) <= 128 * 1024 * 1024, "Xray ZIP too large")
        seen = set()
        for info in infos:
            path = PurePosixPath(info.filename)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in info.filename
                    and info.filename not in seen and not stat.S_ISLNK(info.external_attr >> 16), "Unsafe Xray ZIP member")
            seen.add(info.filename)
            if info.filename in ("xray", "LICENSE"):
                require(info.file_size <= 100 * 1024 * 1024, "Xray member too large")
                result[info.filename] = archive.read(info)
    require(set(result) == {"xray", "LICENSE"}, "Xray executable/license missing")
    binary = result["xray"]
    require(binary[:6] == b"\x7fELF\x02\x01" and len(binary) > 64
            and struct.unpack_from("<H", binary, 18)[0] == 62, "Xray is not ELF64 little-endian amd64")
    require(b"PRIVATE KEY" not in result["LICENSE"], "Unexpected private material")
    return result

def safe_new(path, data):
    require(path.parent.is_dir() and not path.parent.is_symlink(), "Unsafe artifact stage")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--check-full", action="store_true")
    parser.add_argument("--probe-xray", action="store_true")
    parser.add_argument("--stage", type=Path)
    args = parser.parse_args()
    try:
        lock = json.loads(args.lock.read_text())
        if args.check_full:
            raise Blocked("; ".join(full_blockers(lock)))
        asset = xray_metadata(lock["xray"])
        if args.probe_xray:
            print("Pinned Xray metadata/digest available; binary has NOT been run")
            return
        require(args.stage is not None, "Artifact stage required")
        parts = unpack_xray(fetch(asset["browser_download_url"], lock["xray"]["max_bytes"]), lock["xray"])
        for name, data in parts.items():
            safe_new(args.stage / name, data)
        safe_new(args.stage / "xray-binary.json", (json.dumps({"version": lock["xray"]["version"], "archive_sha256": lock["xray"]["sha256"], "binary_sha256": hashlib.sha256(parts["xray"]).hexdigest()}) + "\n").encode())
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        print("BLOCKED artifact: " + str(exc))
        raise SystemExit(78)

if __name__ == "__main__":
    main()
