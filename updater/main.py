"""Fixed-path updater entry point; fixture-root APIs are NOT CLI options.

Network downloads are data only. No archive code is imported or executed.
No apt, setup, account, SSH, firewall, OS-upgrade or reboot operations exist here.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


def _trusted_validator():
    # This check happens BEFORE importing the local validator. Python -I prevents
    # current-directory/PYTHONPATH module injection; the shell wrapper cleans env.
    path = Path(os.path.abspath(__file__)).parent / "release.py"
    cursor = Path("/")
    production = Path(os.path.abspath(__file__)) == Path("/opt/nathaya/updater/main.py")
    for part in path.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or (production and
                (info.st_uid != 0 or info.st_mode & 0o022)):
            raise RuntimeError("Untrusted installed validator path")
        if cursor == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise RuntimeError("Unsafe installed validator")
    spec = importlib.util.spec_from_file_location("nathaya_trusted_release", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R = _trusted_validator()
Blocked = R.Blocked
API_URL = "https://api.github.com/repos/Yusuf2790/nathaya-tunnel/releases/latest"
METADATA_LIMIT = 1024 * 1024
POLICY_REL = "opt/nathaya/updater/release-policy.json"
STATE_REL = "opt/nathaya/updater-state"
INSTALLED_REL = STATE_REL + "/installed.json"
MANUAL_REL = STATE_REL + "/manual-verification.json"
AUTO_REL = STATE_REL + "/auto.json"
PENDING_REL = STATE_REL + "/pending.json"


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_download):
        super().__init__()
        self.allow_download = allow_download
        self.count = 0

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        self.count += 1
        parsed = urllib.parse.urlsplit(newurl)
        R.require(self.allow_download and self.count <= 3 and parsed.scheme == "https" and
                  parsed.hostname in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"} and
                  parsed.port in (None, 443) and not parsed.username and not parsed.password and
                  not parsed.fragment, "Untrusted HTTPS redirect blocked")
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def fetch_https(url, limit, download=False):
    """Unauthenticated, no proxy/env credentials, bounded reads and redirects."""
    parsed = urllib.parse.urlsplit(url)
    R.require(parsed.scheme == "https" and parsed.port in (None, 443) and
              not parsed.username and not parsed.password and not parsed.fragment and
              ((not download and url == API_URL) or
               (download and parsed.hostname == "github.com" and not parsed.query and
                parsed.path.startswith("/Yusuf2790/nathaya-tunnel/releases/download/"))),
              "Untrusted source URL")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeRedirect(download),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    headers = {"User-Agent": "nathaya-tunnel-updater/1", "Accept-Encoding": "identity",
               "Accept": "application/octet-stream" if download else "application/vnd.github+json"}
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response:
            R.require(response.status == 200, "Unexpected HTTPS response")
            encoding = response.headers.get("Content-Encoding", "identity")
            R.require(encoding == "identity", "Unsupported HTTP content encoding")
            length = response.headers.get("Content-Length")
            if length is not None:
                R.require(length.isdecimal() and int(length) <= limit, "Download exceeds size cap")
            body = response.read(limit + 1)
            R.require(len(body) <= limit, "Download exceeds size cap")
            if length is not None:
                R.require(len(body) == int(length), "Truncated HTTPS response")
            return body
    except (OSError, urllib.error.URLError, ValueError) as exc:
        # Do not print URLs, signed redirect queries, headers or response bodies.
        raise Blocked("HTTPS fetch failed or blocked") from exc


def release_metadata(raw):
    metadata = R.parse_json(raw)
    R.require(isinstance(metadata, dict) and metadata.get("draft") is False and
              metadata.get("prerelease") is False, "Latest release is not stable/published")
    tag = metadata.get("tag_name")
    R.require(isinstance(tag, str) and tag.startswith("v"), "Unsupported release tag")
    identity = tag[1:]
    R.version(identity)
    R.require(type(metadata.get("id")) is int and metadata["id"] > 0 and
              metadata.get("url") ==
              f'https://api.github.com/repos/Yusuf2790/nathaya-tunnel/releases/{metadata["id"]}',
              "Release source identity mismatch")
    name = f"nathaya-v{identity}.tar.gz"
    assets = metadata.get("assets")
    R.require(isinstance(assets, list), "Release assets missing")
    candidates = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == name]
    R.require(len(candidates) == 1, "Unique versioned release artifact required")
    asset = candidates[0]
    digest = asset.get("digest")
    R.require(isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
              "BLOCKED: GitHub asset has no trusted SHA256 digest")
    url = f"https://github.com/Yusuf2790/nathaya-tunnel/releases/download/{tag}/{name}"
    R.require(asset.get("browser_download_url") == url and asset.get("state") == "uploaded" and
              type(asset.get("size")) is int and 0 < asset["size"] <= R.MAX_ARCHIVE,
              "Invalid asset source/state/size")
    return {"version": identity, "digest": digest[7:], "url": url, "size": asset["size"]}


class Updater:
    """Internal dependency-injected fixture API; CLI always uses root='/' ."""
    def __init__(self, root=Path("/"), *, fetcher=fetch_https, checker=R.syntax_check,
                 activator=None):
        self.root = Path(os.path.abspath(root))
        self.production = self.root == Path("/")
        self.boundary = None if self.production else self.root
        self.fetcher, self.checker = fetcher, checker
        self.activator = activator or self.activation_check
        self.policy_raw = self.read(POLICY_REL, R.MAX_MANIFEST)
        self.policy = R.load_policy(self.policy_raw)
        self.policy_digest = R.sha256(self.policy_raw)

    def path(self, relative):
        R.safe_name(relative)
        return R.safe_path(self.root / relative, self.boundary, self.production)

    def read(self, relative, limit=R.MAX_FILE):
        return R.read_regular(self.path(relative), limit, self.boundary, self.production)

    def exists(self, relative):
        return self.path(relative).exists()

    def private_json(self, relative):
        path = self.path(relative)
        info = path.stat()
        R.require(stat.S_IMODE(info.st_mode) == 0o600, "Updater state must have mode 0600")
        return R.parse_json(self.read(relative, R.MAX_MANIFEST))

    def mkdir(self, relative, mode=0o700):
        path = self.path(relative)
        existed = path.exists()
        path.mkdir(mode=mode, parents=False, exist_ok=True)
        if not existed:
            path.chmod(mode)
        self.path(relative)
        R.require(path.is_dir(), "Expected directory")
        if mode == 0o700:
            R.require(stat.S_IMODE(path.stat().st_mode) == 0o700, "Private directory must be mode 0700")

    @staticmethod
    def sync_directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, relative, raw, mode=0o600):
        target = self.path(relative)
        # Parent creation is explicit. No write follows a symlink or stale temp path.
        fd, temp = tempfile.mkstemp(prefix=".update-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                if self.production:
                    os.fchown(stream.fileno(), 0, 0)
                os.fchmod(stream.fileno(), mode)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.path(relative)
            os.replace(temp, target)
            self.sync_directory(target.parent)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def unlink(self, relative):
        target = self.path(relative)
        target.unlink()
        self.sync_directory(target.parent)

    def state_ready(self):
        self.mkdir(STATE_REL)
        R.require(not self.exists(PENDING_REL),
                  "Incomplete update: private backup/journal requires manual recovery; do not clear blindly")

    @contextmanager
    def lock(self):
        path = self.path("run/nathaya-tunnel-setup.lock")
        try:
            path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise Blocked("Installer/updater lock active or stale; inspect manually") from exc
        try:
            yield
        finally:
            # Never delete another process's contents or steal a stale lock.
            path.rmdir()

    def installed(self):
        raw = self.read("opt/nathaya/VERSION", 32)
        try:
            identity = raw.decode("ascii").removesuffix("\n")
        except UnicodeError as exc:
            raise Blocked("Invalid deployed VERSION") from exc
        R.version(identity)
        R.require(raw == (identity + "\n").encode("ascii"), "Invalid deployed VERSION")
        installed = self.private_json(INSTALLED_REL)
        R.require(isinstance(installed, dict) and set(installed) == {"schema", "version"} and
                  type(installed["schema"]) is int and
                  installed["schema"] in self.policy["supported_deployed_schemas"] and
                  installed["version"] == identity, "Unsupported/inconsistent deployed schema/version")
        return identity

    def verification(self):
        if not self.exists(MANUAL_REL):
            return None
        marker = self.private_json(MANUAL_REL)
        R.require(isinstance(marker, dict) and set(marker) ==
                  {"schema", "source", "policy_sha256", "version", "artifact_sha256", "installed_version"} and
                  type(marker["schema"]) is int and marker["schema"] == 1 and
                  marker["source"] == R.SOURCE and marker["policy_sha256"] == self.policy_digest and
                  isinstance(marker["artifact_sha256"], str) and
                  re.fullmatch(r"[0-9a-f]{64}", marker["artifact_sha256"]),
                  "Manual verification marker does not match trusted source/policy")
        R.version(marker["version"])
        R.version(marker["installed_version"])
        return marker

    def auto_enabled(self):
        if not self.exists(AUTO_REL):
            return False
        marker = self.private_json(AUTO_REL)
        R.require(isinstance(marker, dict) and set(marker) == {"enabled", "source", "policy_sha256"} and
                  type(marker["enabled"]) is bool and marker["source"] == R.SOURCE and
                  marker["policy_sha256"] == self.policy_digest, "Invalid/stale automatic-update marker")
        return marker["enabled"]

    def verified_release(self, current):
        meta = release_metadata(self.fetcher(API_URL, METADATA_LIMIT, download=False))
        R.require(R.version(meta["version"]) >= R.version(current), "Downgrade/replay release blocked")
        blob = self.fetcher(meta["url"], R.MAX_ARCHIVE, download=True)
        R.require(len(blob) == meta["size"], "Artifact size differs from GitHub metadata")
        manifest, files = R.validate_artifact(blob, meta["digest"], meta["version"], self.policy, self.checker)
        # One coherent version: changed immutable installer/updater/engine glue
        # cannot be silently ignored while stamping a newer VERSION.
        for name, spec in self.policy["files"].items():
            package_only = name == "setup.sh" or name.startswith(("tools/", "templates/", "docs/"))
            if not spec["deploy"] and not package_only:
                R.require(self.exists("opt/nathaya/" + name),
                          "Installed trust-base file missing; repair from a reviewed source first")
                R.require(self.read("opt/nathaya/" + name) == files[name],
                          "Trust-base change requires reviewed manual source reinstall, not routine update")
        return meta, manifest, files

    def mark_manual(self, meta):
        marker = {"schema": 1, "source": R.SOURCE, "policy_sha256": self.policy_digest,
                  "version": meta["version"], "artifact_sha256": meta["digest"],
                  "installed_version": self.installed()}
        self.write(MANUAL_REL, R.json_bytes(marker))

    def check(self):
        self.state_ready()
        current = self.installed()
        meta, _, _ = self.verified_release(current)
        # Checking the installed version is allowed to establish trust; applying it is not.
        self.mark_manual(meta)
        return {"installed": current, "verified": meta["version"], "update_available":
                R.version(meta["version"]) > R.version(current), "auto_enabled": self.auto_enabled()}

    def parent_dirs(self, relative):
        # Only create release code directories inside the fixed deployment base.
        parent = Path(relative).parent
        missing = []
        while not self.path(parent.as_posix()).exists():
            R.require(parent != Path("opt/nathaya"), "Deployment base missing")
            missing.append(parent.as_posix())
            parent = parent.parent
        for name in reversed(missing):
            self.mkdir(name, 0o755)

    def activation_check(self, identity):
        R.require(self.installed() == identity, "Activation identity mismatch")
        files = {name: self.read("opt/nathaya/" + name) for name, spec in self.policy["files"].items()
                 if spec["deploy"]}
        self.checker(files)

    def deploy(self, identity, files):
        self.state_ready()
        R.require(R.version(identity) > R.version(self.installed()), "Same-version replay/downgrade blocked")
        tracked = ["opt/nathaya/" + name for name, spec in self.policy["files"].items() if spec["deploy"]]
        tracked.append(INSTALLED_REL)
        self.mkdir(STATE_REL + "/transactions")
        backup_path = Path(tempfile.mkdtemp(prefix="run-", dir=self.path(STATE_REL + "/transactions")))
        backup_rel = backup_path.relative_to(self.root).as_posix()
        originals, journal = {}, []
        for index, relative in enumerate(tracked):
            target = self.path(relative)
            if target.exists():
                raw = self.read(relative)
                mode = stat.S_IMODE(target.stat().st_mode)
                R.require(mode in (0o600, 0o644, 0o755), "Unexpected deployed file mode")
                originals[relative] = (raw, mode)
                self.write(f"{backup_rel}/{index}", raw)
                journal.append({"path": relative, "backup": str(index), "mode": mode})
            else:
                originals[relative] = None
                journal.append({"path": relative, "backup": None, "mode": None})
        self.write(backup_rel + "/journal.json", R.json_bytes({"files": journal}))
        self.write(PENDING_REL, R.json_bytes({"backup": backup_rel, "version": identity}))
        replaced = []
        created_dirs = []
        try:
            for name, spec in self.policy["files"].items():
                if not spec["deploy"]:
                    continue
                relative = "opt/nathaya/" + name
                # Record new directories for best-effort empty-directory rollback.
                parent = Path(relative).parent
                while not self.path(parent.as_posix()).exists():
                    created_dirs.append(parent.as_posix())
                    parent = parent.parent
                self.parent_dirs(relative)
                replaced.append(relative)
                self.write(relative, files[name], int(spec["mode"], 8))
            replaced.append(INSTALLED_REL)
            self.write(INSTALLED_REL, R.json_bytes({"schema": 1, "version": identity}))
            for name, spec in self.policy["files"].items():
                if spec["deploy"]:
                    R.require(self.read("opt/nathaya/" + name) == files[name], "Deployed bytes differ from validated artifact")
            self.activator(identity)
            self.unlink(PENDING_REL)
        except BaseException:
            # Includes activation failures and handled termination; power loss leaves pending.json.
            try:
                for relative in reversed(replaced):
                    previous = originals[relative]
                    if previous is None:
                        if self.exists(relative):
                            self.unlink(relative)
                    else:
                        self.write(relative, previous[0], previous[1])
                for relative in replaced:
                    previous = originals[relative]
                    if previous is None:
                        R.require(not self.exists(relative), "Rollback left a new code file")
                    else:
                        R.require(self.read(relative) == previous[0] and
                                  stat.S_IMODE(self.path(relative).stat().st_mode) == previous[1],
                                  "Rollback bytes/mode verification failed")
                for relative in sorted(set(created_dirs), key=lambda value: value.count("/"), reverse=True):
                    directory = self.path(relative)
                    if directory.exists():
                        directory.rmdir()
                if self.exists(PENDING_REL):
                    self.unlink(PENDING_REL)
            except BaseException as exc:
                # Re-establish the guard if commit unlink succeeded but its fsync failed.
                try:
                    self.write(PENDING_REL, R.json_bytes({"backup": backup_rel, "version": identity}))
                except BaseException:
                    pass  # Storage failure may make even the recovery guard impossible.
                raise Blocked("Rollback incomplete; retain pending journal and private backup for recovery") from exc
            raise
        return backup_rel

    def apply(self, automatic=False):
        self.state_ready()
        current = self.installed()
        if automatic:
            R.require(self.auto_enabled() and self.verification() is not None,
                      "Automatic updates disabled or manual verification missing")
        meta, _, files = self.verified_release(current)
        if automatic and meta["version"] == current:
            return {"installed": current, "changed": False}
        R.require(R.version(meta["version"]) > R.version(current), "Same-version replay blocked")
        backup = self.deploy(meta["version"], files)
        if not automatic:
            self.mark_manual(meta)
        return {"installed": meta["version"], "changed": True, "backup": backup}

    def systemd(self, *arguments):
        R.require(self.production, "Fixture API cannot invoke systemd")
        R.require(Path("/run/systemd/system").is_dir() and
                  R.read_regular(Path("/proc/1/comm"), 64).strip() == b"systemd",
                  "systemd must be PID 1")
        R.safe_path(Path("/usr/bin/systemctl"), root_owned=True)
        result = subprocess.run(["/usr/bin/systemctl", *arguments], env=R.CLEAN_ENV,
                                cwd="/", capture_output=True, timeout=30, check=False)
        R.require(result.returncode == 0, "systemd operation failed (unit templates may not be installed)")

    def enable_auto(self):
        self.state_ready()
        current = self.installed()
        verification = self.verification()
        R.require(verification is not None and verification["installed_version"] == current,
                  "Run manual --check or --apply successfully for this installed version first")
        # Only exact trusted templates may be activated; never install/replace unit files here.
        for unit in ("nathaya-update.service", "nathaya-update.timer"):
            R.require(self.read("etc/systemd/system/" + unit) == self.read("opt/nathaya/updater/" + unit),
                      "Install the trusted systemd templates manually before enable-auto")
        self.systemd("cat", "nathaya-update.service", "nathaya-update.timer")
        self.write(AUTO_REL, R.json_bytes({"enabled": True, "source": R.SOURCE,
                                          "policy_sha256": self.policy_digest}))
        try:
            self.systemd("enable", "--now", "nathaya-update.timer")
        except BaseException:
            self.write(AUTO_REL, R.json_bytes({"enabled": False, "source": R.SOURCE,
                                              "policy_sha256": self.policy_digest}))
            raise
        return {"auto_enabled": True}

    def disable_auto(self):
        self.mkdir(STATE_REL)
        # Gate is closed first, even if systemd is unavailable or stopping the timer fails.
        self.write(AUTO_REL, R.json_bytes({"enabled": False, "source": R.SOURCE,
                                          "policy_sha256": self.policy_digest}))
        self.systemd("disable", "--now", "nathaya-update.timer")
        return {"auto_enabled": False}

    def status(self):
        return {"installed": self.installed(), "auto_enabled": self.auto_enabled(),
                "manual_verified": self.verification() is not None,
                "recovery_required": self.exists(PENDING_REL)}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Nathaya stable code-only updater (fixed /opt/nathaya)")
    parser.add_argument("command", choices=("--check", "--apply", "status", "enable-auto", "disable-auto", "auto"))
    # --check/--apply are command spellings, not root/destination override options.
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["--check"], ["--apply"]):
        command = arguments[0]
    else:
        command = parser.parse_args(arguments).command
    if os.geteuid() != 0:
        parser.error("run as root on the VPS using /bin/sh /opt/nathaya/updater/update.sh")
    if Path(os.path.abspath(__file__)) != Path("/opt/nathaya/updater/main.py"):
        parser.error("production entry point must be installed at /opt/nathaya/updater/main.py")
    os.umask(0o077)
    def interrupted(signum, frame):
        raise KeyboardInterrupt("Updater interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        updater = Updater()
        with updater.lock():
            methods = {"--check": updater.check, "--apply": updater.apply, "status": updater.status,
                       "enable-auto": updater.enable_auto, "disable-auto": updater.disable_auto,
                       "auto": lambda: updater.apply(automatic=True)}
            result = methods[command]()
        print(R.json_bytes(result).decode("utf-8"), end="")
        return 0
    except Blocked as exc:
        # Blocked reasons are fixed local strings, never raw response or file content.
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt):
        # Never echo raw network bodies/URLs or private file contents.
        print("BLOCKED: update not completed; verify source/digest, identity, permissions, lock and private recovery journal.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
