"""Python-only updater fixtures: no network, subprocess, systemd or host-root writes.

Run from a trusted checkout: python3 -I -B tests/update_test.py
The real Bash parser/systemd integration requires separate VPS validation.
"""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

REPO = Path(__file__).absolute().parent.parent
SPEC = importlib.util.spec_from_file_location("fixture_updater", REPO / "updater/main.py")
U = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(U)
R = U.R


def fixture_checker(files):
    # Explicit test double, NOT a claim that Bash syntax passed.
    for name, raw in files.items():
        if name.endswith(".sh"):
            R.require(raw.startswith(b"#!/bin/bash\n") and b"SYNTAX-FAIL" not in raw,
                      "Fixture syntax rejection")


def policy():
    return R.load_policy(R.json_bytes({
        "schema": 1, "channel": "stable", "source": R.SOURCE,
        "supported_deployed_schemas": [1], "files": {
            "VERSION": {"mode": "0644", "deploy": True},
            "menu.sh": {"mode": "0755", "deploy": True},
            "modules/common/bootstrap.sh": {"mode": "0644", "deploy": True}}}))


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def archive(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for member, raw in members:
            tar.addfile(member, io.BytesIO(raw) if member.isreg() else None)
    return gzip.compress(output.getvalue(), mtime=0)


def members(blob):
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        return [(copy.copy(member), tar.extractfile(member).read()) for member in tar]


def metadata(identity, blob):
    name = f"nathaya-v{identity}.tar.gz"
    return {"id": 7, "url": "https://api.github.com/repos/Yusuf2790/nathaya-tunnel/releases/7",
            "draft": False, "prerelease": False, "tag_name": "v" + identity,
            "assets": [{"name": name, "state": "uploaded", "size": len(blob),
                        "digest": "sha256:" + R.sha256(blob),
                        "browser_download_url":
                        f"https://github.com/Yusuf2790/nathaya-tunnel/releases/download/v{identity}/{name}"}]}


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nathaya-update-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir(mode=0o700)
        (self.root / "run").mkdir()
        self.source = self.base / "source"
        self.source.mkdir()
        self.policy = policy()
        self.old = {"VERSION": b"2.0.0\n", "menu.sh": b"#!/bin/bash\nprintf old\n",
                    "modules/common/bootstrap.sh": b"#!/bin/bash\n# old\n"}
        for name, raw in self.old.items():
            write(self.root / "opt/nathaya" / name, raw, int(self.policy["files"][name]["mode"], 8))
        write(self.root / U.POLICY_REL, R.json_bytes(self.policy))
        state = self.root / U.STATE_REL
        state.mkdir(mode=0o700)
        write(self.root / U.INSTALLED_REL, R.json_bytes({"schema": 1, "version": "2.0.0"}), 0o600)
        self.protected = {
            "etc/nathaya-tunnel/config.conf": b"fixture-config-data\n",
            "opt/nathaya/data/ssh/accounts.db": b"fixture-account-data\n",
            "opt/nathaya/keys/fixture": b"inert-fixture-not-a-key\n",
            "usr/local/bin/menu": b"fixture-wrapper-unchanged\n",
            "etc/systemd/system/ssh.service": b"fixture-unit-unchanged\n"}
        for name, raw in self.protected.items():
            write(self.root / name, raw, 0o600)
        self.make_release("2.0.1")
        self.calls = []
        self.engine = U.Updater(self.root, fetcher=self.fetch, checker=fixture_checker)
        # A subprocess/network call in any fixture is an error, even on the host's test OS.
        self.addCleanup(patch.stopall)
        patch.object(U.subprocess, "run", side_effect=AssertionError("No subprocess in fixtures")).start()
        patch.object(U.urllib.request, "build_opener", side_effect=AssertionError("No live HTTP in fixtures")).start()

    def make_release(self, identity):
        self.new = {"VERSION": (identity + "\n").encode(), "menu.sh": b"#!/bin/bash\nprintf new\n",
                    "modules/common/bootstrap.sh": b"#!/bin/bash\n# new\n"}
        for name, raw in self.new.items():
            write(self.source / name, raw)
        self.identity, self.blob = R.build_artifact(self.source, self.policy, fixture_checker)
        self.meta = metadata(identity, self.blob)

    def fetch(self, url, limit, download=False):
        self.calls.append((url, limit, download))
        if download:
            self.assertEqual(url, self.meta["assets"][0]["browser_download_url"])
            return self.blob
        self.assertEqual(url, U.API_URL)
        return R.json_bytes(self.meta)

    def validate(self, blob=None, digest=None, identity=None):
        blob = self.blob if blob is None else blob
        return R.validate_artifact(blob, digest or R.sha256(blob), identity or self.identity,
                                   self.policy, fixture_checker)

    def assert_preserved(self):
        for name, raw in self.protected.items():
            path = self.root / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_builder_roundtrip_deterministic_explicit_allowlist(self):
        write(self.source / "data/ssh/accounts.db", b"exclude-fixture\n")
        write(self.source / ".env", b"exclude-fixture\n")
        identity, blob = R.build_artifact(self.source, self.policy, fixture_checker)
        self.assertEqual((identity, blob), (self.identity, self.blob))
        manifest, files = self.validate()
        self.assertEqual(set(files), set(self.policy["files"]))
        self.assertEqual(manifest["schema"], 1)

    def test_public_example_stays_empty_and_off(self):
        public = (b'DOMAIN=""\nTELEGRAM_STATUS="OFF"\n'
                  b'TELEGRAM_BOT_TOKEN=""\nTELEGRAM_ADMIN_ID=""\n')
        R.validate_public_example(public)
        for candidate in (public.replace(b'STATUS="OFF"', b'STATUS="ON"'),
                          public + b'UNKNOWN=""\n', public + b'DOMAIN=""\n'):
            with self.assertRaises(R.Blocked):
                R.validate_public_example(candidate)

    def test_archive_digest_and_corrupt_gzip(self):
        with self.assertRaises(R.Blocked):
            self.validate(digest="0" * 64)
        broken = self.blob[:-8] + b"corrupt!"
        with self.assertRaises(R.Blocked):
            self.validate(broken)

    def test_missing_trusted_digest_blocks_before_download(self):
        self.meta["assets"][0].pop("digest")
        with self.assertRaises(R.Blocked):
            self.engine.check()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.root / U.MANUAL_REL).exists())

    def test_metadata_source_stability_and_asset_checks(self):
        changes = [lambda m: m.update(draft=True), lambda m: m.update(prerelease=True),
                   lambda m: m.update(tag_name="v2.0.1-rc1"),
                   lambda m: m.update(url="https://api.github.com/repos/other/repo/releases/7"),
                   lambda m: m["assets"][0].update(browser_download_url="https://example.invalid/archive"),
                   lambda m: m["assets"][0].update(size=R.MAX_ARCHIVE + 1),
                   lambda m: m["assets"].append(copy.deepcopy(m["assets"][0]))]
        for change in changes:
            with self.subTest(change=change):
                mutated = copy.deepcopy(self.meta)
                change(mutated)
                with self.assertRaises(R.Blocked):
                    U.release_metadata(R.json_bytes(mutated))

    def test_traversal_absolute_links_directories_duplicate_and_extra(self):
        for bad_name in ("../outside", "/etc/passwd", "modules/../outside", "modules//bad", "./menu.sh"):
            candidate = members(self.blob)
            candidate[1][0].name = bad_name
            with self.subTest(name=bad_name), self.assertRaises(R.Blocked):
                self.validate(archive(candidate))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.XHDTYPE):
            candidate = members(self.blob)
            candidate[1][0].type = kind
            candidate[1][0].linkname = "menu.sh"
            candidate[1][0].size = 0
            with self.subTest(kind=kind), self.assertRaises(R.Blocked):
                self.validate(archive(candidate))
        candidate = members(self.blob)
        with self.assertRaises(R.Blocked):
            self.validate(archive(candidate + [candidate[1]]))
        extra = tarfile.TarInfo("extra.sh")
        extra.mode, extra.size = 0o644, 1
        with self.assertRaises(R.Blocked):
            self.validate(archive(candidate + [(extra, b"x")]))
        self.assertFalse((self.base / "outside").exists())

    def test_manifest_hash_mode_version_and_schema(self):
        for mutate in (lambda m: m["files"][0].update(sha256="0" * 64),
                       lambda m: m["files"][0].update(mode="0755"),
                       lambda m: m.update(schema=2), lambda m: m.update(version="2.0.2")):
            candidate = members(self.blob)
            manifest = json.loads(candidate[0][1])
            mutate(manifest)
            raw = R.json_bytes(manifest)
            candidate[0][0].size = len(raw)
            candidate[0] = (candidate[0][0], raw)
            with self.subTest(mutate=mutate), self.assertRaises(R.Blocked):
                self.validate(archive(candidate))
        candidate = members(self.blob)
        candidate[1][0].mode = 0o4755
        with self.assertRaises(R.Blocked):
            self.validate(archive(candidate))
        with self.assertRaises(R.Blocked):
            self.validate(identity="2.0.2")

    def test_caps_and_json_duplicates(self):
        with patch.object(R, "MAX_EXPANDED", 512), self.assertRaises(R.Blocked):
            self.validate()
        with patch.object(R, "MAX_MEMBERS", 1), self.assertRaises(R.Blocked):
            self.validate()
        with patch.object(R, "MAX_FILE", 1), self.assertRaises(R.Blocked):
            self.validate()
        with self.assertRaises(R.Blocked):
            R.parse_json(b'{"schema":1,"schema":1}')

    def test_source_filesystem_links_rejected(self):
        target = self.source / "menu.sh"
        target.unlink()
        target.symlink_to(self.root / "opt/nathaya/menu.sh")
        with self.assertRaises(R.Blocked):
            R.build_artifact(self.source, self.policy, fixture_checker)
        target.unlink()
        target.hardlink_to(self.root / "opt/nathaya/menu.sh")
        with self.assertRaises(R.Blocked):
            R.build_artifact(self.source, self.policy, fixture_checker)

    def test_default_disabled_and_manual_check_gate(self):
        self.assertFalse(self.engine.status()["auto_enabled"])
        with self.assertRaises(R.Blocked):
            self.engine.apply(automatic=True)
        self.assertEqual(self.calls, [])
        with self.assertRaises(R.Blocked):
            self.engine.enable_auto()
        result = self.engine.check()
        self.assertTrue(result["update_available"])
        self.assertFalse(result["auto_enabled"])
        self.assertEqual(stat.S_IMODE((self.root / U.MANUAL_REL).stat().st_mode), 0o600)
        self.assert_preserved()
        self.assertEqual(self.engine.installed(), "2.0.0")

    def test_enable_requires_gate_templates_and_systemd_then_disable(self):
        self.engine.check()
        with self.assertRaises(FileNotFoundError):
            self.engine.enable_auto()
        for unit in ("nathaya-update.service", "nathaya-update.timer"):
            raw = (REPO / "updater" / unit).read_bytes()
            write(self.root / "opt/nathaya/updater" / unit, raw)
            write(self.root / "etc/systemd/system" / unit, raw)
        # The real fixture API refuses systemd; substitute an explicit recording double.
        with self.assertRaises(R.Blocked):
            self.engine.enable_auto()
        systemd_calls = []
        self.engine.systemd = lambda *args: systemd_calls.append(args)
        self.assertTrue(self.engine.enable_auto()["auto_enabled"])
        self.assertTrue(self.engine.auto_enabled())
        self.assertIn(("enable", "--now", "nathaya-update.timer"), systemd_calls)
        self.assertFalse(self.engine.disable_auto()["auto_enabled"])
        self.assertFalse(self.engine.auto_enabled())

    def test_apply_preserves_runtime_wrapper_and_service_then_blocks_replay(self):
        with self.engine.lock():
            result = self.engine.apply()
        self.assertTrue(result["changed"])
        self.assertEqual(self.engine.installed(), "2.0.1")
        for name, raw in self.new.items():
            self.assertEqual((self.root / "opt/nathaya" / name).read_bytes(), raw)
        self.assert_preserved()
        self.assertTrue((self.root / result["backup"] / "journal.json").is_file())
        self.assertFalse((self.root / U.PENDING_REL).exists())
        with self.assertRaises(R.Blocked):
            self.engine.apply()
        self.assertEqual(self.engine.installed(), "2.0.1")

    def test_current_check_allowed_but_no_apply_and_no_downgrade(self):
        self.make_release("2.0.0")
        self.assertFalse(self.engine.check()["update_available"])
        with self.assertRaises(R.Blocked):
            self.engine.apply()
        self.make_release("1.9.9")
        with self.assertRaises(R.Blocked):
            self.engine.check()
        for invalid in ("02.0.0", "2.0", "v2.0.0", "2.0.0+build", "2.0.0-rc1"):
            with self.subTest(version=invalid), self.assertRaises(R.Blocked):
                R.version(invalid)

    def test_activation_failure_restores_bytes_modes_schema_version(self):
        before_installed = (self.root / U.INSTALLED_REL).read_bytes()
        def fail(identity):
            self.assertEqual(identity, "2.0.1")
            self.assertEqual(self.engine.installed(), "2.0.1")
            raise R.Blocked("Fixture activation failure")
        self.engine.activator = fail
        with self.engine.lock(), self.assertRaises(R.Blocked):
            self.engine.apply()
        for name, raw in self.old.items():
            path = self.root / "opt/nathaya" / name
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), int(self.policy["files"][name]["mode"], 8))
        self.assertEqual((self.root / U.INSTALLED_REL).read_bytes(), before_installed)
        self.assertEqual(self.engine.installed(), "2.0.0")
        self.assertFalse((self.root / U.PENDING_REL).exists())
        self.assertFalse((self.root / U.MANUAL_REL).exists())
        self.assert_preserved()

    def test_invalid_schema_pending_lock_and_symlink_targets_fail_closed(self):
        write(self.root / U.INSTALLED_REL, R.json_bytes({"schema": 2, "version": "2.0.0"}), 0o600)
        with self.assertRaises(R.Blocked):
            self.engine.check()
        write(self.root / U.INSTALLED_REL, R.json_bytes({"schema": 1, "version": "2.0.0"}), 0o600)
        write(self.root / U.PENDING_REL, b"{}\n", 0o600)
        with self.assertRaises(R.Blocked):
            self.engine.check()
        (self.root / U.PENDING_REL).unlink()
        (self.root / "run/nathaya-tunnel-setup.lock").mkdir()
        with self.assertRaises(R.Blocked), self.engine.lock():
            self.fail("Must not acquire existing lock")
        (self.root / "run/nathaya-tunnel-setup.lock").rmdir()
        target = self.root / "opt/nathaya/menu.sh"
        target.unlink()
        target.symlink_to(self.root / "etc/nathaya-tunnel/config.conf")
        with self.assertRaises(R.Blocked):
            self.engine.apply()
        self.assert_preserved()

    def test_marker_policy_change_and_mode_cannot_enable(self):
        self.engine.check()
        marker = self.root / U.MANUAL_REL
        marker.chmod(0o644)
        with self.assertRaises(R.Blocked):
            self.engine.enable_auto()
        marker.chmod(0o600)
        changed = copy.deepcopy(self.policy)
        changed["files"]["menu.sh"]["mode"] = "0644"
        write(self.root / U.POLICY_REL, R.json_bytes(changed))
        other = U.Updater(self.root, fetcher=self.fetch, checker=fixture_checker)
        with self.assertRaises(R.Blocked):
            other.enable_auto()

    def test_syntax_failure_blocks_before_code_or_manual_marker(self):
        write(self.source / "menu.sh", b"#!/bin/bash\nSYNTAX-FAIL\n")
        with self.assertRaises(R.Blocked):
            R.build_artifact(self.source, self.policy, fixture_checker)
        def failing_checker(files):
            raise R.Blocked("Fixture syntax rejection")
        self.engine.checker = failing_checker
        with self.assertRaises(R.Blocked):
            self.engine.apply()
        self.assertEqual(self.engine.installed(), "2.0.0")
        self.assertFalse((self.root / U.MANUAL_REL).exists())

    def test_automatic_apply_requires_existing_gate_and_never_creates_manual_proof(self):
        self.engine.check()
        original_proof = (self.root / U.MANUAL_REL).read_bytes()
        write(self.root / U.AUTO_REL, R.json_bytes({"enabled": True, "source": R.SOURCE,
                                                  "policy_sha256": self.engine.policy_digest}), 0o600)
        self.assertTrue(self.engine.apply(automatic=True)["changed"])
        self.assertEqual((self.root / U.MANUAL_REL).read_bytes(), original_proof)
        self.assertFalse(self.engine.apply(automatic=True)["changed"])
        self.assert_preserved()

    def test_activation_rollback_removes_new_file_and_keeps_backup(self):
        added = "modules/new/feature.sh"
        updated = copy.deepcopy(self.policy)
        updated["files"][added] = {"mode": "0644", "deploy": True}
        write(self.source / added, b"#!/bin/bash\n# fixture new file\n")
        write(self.root / U.POLICY_REL, R.json_bytes(updated))
        self.identity, self.blob = R.build_artifact(self.source, updated, fixture_checker)
        self.meta = metadata(self.identity, self.blob)
        def failure(identity):
            raise R.Blocked("Fixture activation failure")
        engine = U.Updater(self.root, fetcher=self.fetch, checker=fixture_checker, activator=failure)
        with self.assertRaises(R.Blocked):
            engine.apply()
        self.assertFalse((self.root / "opt/nathaya" / added).exists())
        self.assertFalse((self.root / "opt/nathaya/modules/new").exists())
        self.assertEqual(engine.installed(), "2.0.0")
        self.assertTrue(list((self.root / U.STATE_REL / "transactions").glob("run-*/journal.json")))
        self.assert_preserved()

    def test_packaged_validator_code_is_never_imported_or_deployed(self):
        updated = copy.deepcopy(self.policy)
        updated["files"]["updater/release.py"] = {"mode": "0644", "deploy": False}
        malicious_but_valid_python = b'raise RuntimeError("MUST NEVER EXECUTE")\n'
        write(self.source / "updater/release.py", malicious_but_valid_python)
        def parse_only(files):
            fixture_checker(files)
            compile(files["updater/release.py"], "candidate", "exec", dont_inherit=True)
        _, blob = R.build_artifact(self.source, updated, parse_only)
        _, files = R.validate_artifact(blob, R.sha256(blob), self.identity, updated, parse_only)
        self.assertEqual(files["updater/release.py"], malicious_but_valid_python)
        self.assertFalse((self.root / "opt/nathaya/updater/release.py").exists())

    def test_redirect_rejects_insecure_credentials_and_foreign_hosts(self):
        request = urllib.request.Request(self.meta["assets"][0]["browser_download_url"])
        for url in ("http://release-assets.githubusercontent.com/x", "https://evil.invalid/x",
                    "https://github.com/other/repo", "https://user@release-assets.githubusercontent.com/x"):
            with self.subTest(url=url), self.assertRaises(R.Blocked):
                U.SafeRedirect(True).redirect_request(request, None, 302, "", {}, url)
        with self.assertRaises(R.Blocked):
            U.SafeRedirect(False).redirect_request(request, None, 302, "", {},
                                                   "https://release-assets.githubusercontent.com/x")


if __name__ == "__main__":
    unittest.main()
