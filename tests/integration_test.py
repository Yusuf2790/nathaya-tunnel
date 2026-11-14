"""Offline full-source contracts; no installer, subprocess, network or root writes.

Run with python3 -I -B tests/integration_test.py. The injected checker compiles
Python in memory only: Bash/systemd/VPS validation is NOT claimed here.
"""
import sys
sys.dont_write_bytecode = True

import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


U = module("integration_updater", "updater/main.py")
R = U.R
S = module("integration_install_state", "installer/state.py")

# Independent explicit contract, not a directory walk or policy-derived expected set.
PROGRAM = frozenset("""
menu.sh VERSION NOTICE licenses/Alrescha79-MIT.txt
config/config.conf.example config/ports.json
modules/common/bootstrap.sh modules/common/functions.sh modules/common/telegram.sh
modules/common/ui.sh modules/dashboard/dashboard.sh
modules/menu/domain.sh modules/menu/main.sh modules/menu/set_domain.sh modules/menu/ssh.sh
modules/ssh/account-db.sh modules/ssh/create.sh modules/ssh/delete.sh
modules/ssh/list-expired.sh modules/ssh/list-member.sh modules/ssh/lock.sh
modules/ssh/login.sh modules/ssh/renew.sh modules/ssh/trial.sh modules/ssh/unlock.sh
modules/maintenance/ssh-expire.sh
installer/lib.sh installer/policy.sh installer/openssh.sh installer/domain.sh
installer/dependencies.sh installer/firewall.sh installer/dropbear.sh installer/websocket.sh
installer/udp.sh installer/openvpn.sh installer/ui.sh installer/runtime.sh installer/tls.sh
installer/tls-renew.sh installer/xray.sh installer/proxies.sh installer/maintenance.sh
installer/verify.sh installer/preflight.sh installer/menu-wrapper.sh installer/external-lock.json
installer/artifacts.py installer/render.py installer/checks.py installer/state.py
services/login-policy.sh services/nathaya-dashboard.sh services/ws_proxy.py
services/nathaya-ssh-expire.service services/nathaya-ssh-expire.timer
services/nathaya-cert-renew.service services/nathaya-cert-renew.timer
updater/main.py updater/release.py updater/release-policy.json updater/update.sh
updater/nathaya-update.service updater/nathaya-update.timer
""".split())
PACKAGE_ONLY = frozenset("""
setup.sh tools/build-release.py tools/audit-openvpn.py tools/openvpn-clients.py
 templates/openvpn/client-tcp.ovpn.in templates/openvpn/client-udp.ovpn.in
 templates/openvpn/client-ssl.ovpn.in docs/install.md docs/architecture.md
 docs/update.md docs/alrescha-parity.md docs/permissions.md
""".split())
RELEASE = PROGRAM | PACKAGE_ONLY
DEPLOY = frozenset({"menu.sh", "VERSION", "config/config.conf.example"} |
                   {name for name in PROGRAM if name.startswith("modules/")})
TRUST = PROGRAM - DEPLOY


def write(path, raw, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def checker(files):
    # Deliberately no shell parser subprocess. foundation.sh covers Bash -n.
    for name, raw in files.items():
        if name.endswith(".py"):
            compile(raw, name, "exec", dont_inherit=True)


def actual_policy():
    return R.load_policy((REPO / "updater/release-policy.json").read_bytes())


def metadata(identity, blob):
    name = f"nathaya-v{identity}.tar.gz"
    return {"id": 7, "url": "https://api.github.com/repos/Yusuf2790/nathaya-tunnel/releases/7",
            "draft": False, "prerelease": False, "tag_name": "v" + identity,
            "assets": [{"name": name, "state": "uploaded", "size": len(blob),
                        "digest": "sha256:" + R.sha256(blob),
                        "browser_download_url":
                        f"https://github.com/Yusuf2790/nathaya-tunnel/releases/download/v{identity}/{name}"}]}


class Isolated(unittest.TestCase):
    def setUp(self):
        for obj, attr in ((subprocess, "Popen"), (subprocess, "run"), (os, "system"),
                          (os, "popen"), (urllib.request, "build_opener"),
                          (urllib.request, "urlopen"), (socket, "create_connection")):
            guard = patch.object(obj, attr, side_effect=AssertionError("Real operation forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="nathaya-integration-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def same_bytes(self, path, raw):
        # Avoid printing config/DB/key contents if an assertion fails.
        self.assertTrue(path.read_bytes() == raw, "Fixture bytes changed")


class SourceContractTests(Isolated):
    def test_exact_64_program_65_source_76_release_and_deploy_policy(self):
        self.assertEqual(len(PROGRAM), 64)
        self.assertEqual(len(RELEASE), 76)
        text = (REPO / "installer/lib.sh").read_text()
        block = re.search(r"nt_program_files\(\) \{\n(.*?)\n\}", text, re.S)
        self.assertIsNotNone(block)
        body = block.group(1)
        self.assertTrue(body.startswith("    printf '%s\\n' \\\n"))
        names = body.splitlines()[1:]
        actual = [line.strip().removesuffix("\\").strip() for line in names]
        self.assertEqual(len(actual), 64)
        self.assertEqual(set(actual), PROGRAM)
        source = re.search(r"nt_source_files\(\) \{\n(.*?)\n\}", text, re.S)
        self.assertIsNotNone(source)
        self.assertEqual(source.group(1).strip(), "nt_program_files\n    printf '%s\\n' setup.sh")
        policy = actual_policy()
        expected = {name: {"mode": "0755" if name in {"menu.sh", "updater/update.sh"} else "0644",
                           "deploy": name in DEPLOY} for name in RELEASE}
        self.assertEqual(policy["files"], expected)
        self.assertLess(PROGRAM | {"setup.sh"}, set(policy["files"]))
        self.assertEqual({name for name, spec in policy["files"].items()
                          if not spec["deploy"] and name not in PACKAGE_ONLY}, TRUST)
        self.assertFalse(TRUST & PACKAGE_ONLY)
        self.assertFalse(any(name.startswith((".git/", "tests/", "data/", "logs/", "keys/"))
                             or name == "config/config.conf" for name in policy["files"]))
        R.validate_public_example((REPO / "config/config.conf.example").read_bytes())

    def test_full_actual_checkout_artifact_roundtrip_injected_checker(self):
        policy = actual_policy()
        calls = []

        def checked(files):
            calls.append(set(files))
            checker(files)

        identity, blob = R.build_artifact(REPO, policy, checked)
        manifest, files = R.validate_artifact(blob, R.sha256(blob), identity, policy, checked)
        self.assertEqual(calls, [RELEASE, RELEASE])
        self.assertEqual(set(files), RELEASE)
        self.assertEqual({entry["path"] for entry in manifest["files"]}, RELEASE)
        for name in RELEASE:
            self.assertTrue(files[name] == (REPO / name).read_bytes(), "Packaged bytes differ")
        self.assertEqual((identity, blob), R.build_artifact(REPO, policy, checked))
        # Files outside the manifest do not enter an artifact, even in a dirty checkout.
        source = self.base / "source"
        for name in RELEASE:
            write(source / name, files[name])
        for name in (".git/marker", "tests/marker", "config/config.conf", "data/ssh/accounts.db",
                     "logs/marker", "keys/marker", ".env"):
            write(source / name, b"OFFLINE_EXCLUDED_FIXTURE\n", 0o600)
        self.assertEqual(R.build_artifact(source, policy, checked), (identity, blob))

    def test_installer_source_subset_is_insufficient_and_each_release_file_required(self):
        policy = actual_policy()
        source = self.base / "source"
        for name in PROGRAM | {"setup.sh"}:
            write(source / name, (REPO / name).read_bytes())
        with self.assertRaises(FileNotFoundError):
            R.build_artifact(source, policy, checker)
        for name in PACKAGE_ONLY - {"setup.sh"}:
            write(source / name, (REPO / name).read_bytes())
        for name in sorted(RELEASE):
            with self.subTest(path=name):
                raw = (source / name).read_bytes()
                (source / name).unlink()
                with self.assertRaises(FileNotFoundError):
                    R.build_artifact(source, policy, checker)
                write(source / name, raw)

    def test_static_worker_commit_and_reboot_gate_ordering(self):
        # STATIC contract only: the live worker/finalizer/countdown are never called.
        source = (REPO / "setup.sh").read_text()
        worker = source.split("nt_worker() {\n", 1)[1].split("\nnt_setup_main() {", 1)[0]
        verify = worker.index("    nt_run_stage verification nt_core_verify\n")
        commit = worker.index('state.py" commit "$NT_SOURCE" "$NT_RUN/updater-before.json"')
        gates = worker.index("    NT_GATES_RC=0\n")
        reboot = worker.index("    nt_reboot_countdown\n")
        self.assertLess(verify, commit)
        self.assertLess(commit, gates)
        self.assertLess(gates, reboot)
        for line in worker.splitlines():
            if "nt_run_stage " in line:
                self.assertRegex(line, r"^    nt_run_stage ")
                self.assertNotRegex(line, r"[;&|]")
        ui = (REPO / "installer/ui.sh").read_text()
        countdown = ui.split("nt_reboot_countdown() {\n", 1)[1]
        self.assertLess(countdown.index("nt_can_reboot "), countdown.index("for ((remaining="))
        self.assertLess(countdown.index("    nt_finalize_success\n"), countdown.index("    systemctl reboot\n"))

    def test_static_ssh_preflight_baseline_reaches_worker(self):
        # No live worker/installer calls: inheritance is exercised by installer.sh.
        setup = (REPO / "setup.sh").read_text()
        main = setup.split("nt_setup_main() {\n", 1)[1]
        self.assertLess(main.index("    nt_preflight\n"), main.index("    nt_ssh_persist_baseline\n"))
        self.assertLess(main.index('NT_RUN="$(mktemp -d '), main.index("    nt_ssh_persist_baseline\n"))
        fork = main.index('( NT_LOCK_HELD=1; nt_worker )')
        self.assertLess(main.index("    nt_ssh_persist_baseline\n"), fork)
        self.assertNotIn("nt_ssh_snapshot", main)
        worker = setup.split("nt_worker() {\n", 1)[1].split("\nnt_setup_main() {", 1)[0]
        self.assertLess(worker.index("    nt_ssh_assert_baseline\n"), worker.index("    nt_run_stage staging"))
        self.assertLess(worker.index("    nt_ssh_assert_baseline\n"), worker.index("    NT_OS_MAINTENANCE=1"))
        self.assertNotIn("nt_ssh_snapshot", worker)
        self.assertIn("    nt_ssh_snapshot\n", (REPO / "installer/preflight.sh").read_text())
        dependencies = (REPO / "installer/dependencies.sh").read_text()
        self.assertNotIn("NT_SOCKET_IDENTITY_BEFORE=", dependencies)
        self.assertNotIn("NT_SSH_START_BEFORE=", dependencies)
        self.assertLess(dependencies.index("    nt_ssh_accept_post_os_identity || return 1"),
                        dependencies.index("    NT_OS_MAINTENANCE=0"))
        ssh = (REPO / "installer/openssh.sh").read_text()
        identity = ssh.split("nt_ssh_read_identity() {\n", 1)[1].split("\nnt_ssh_snapshot()", 1)[0]
        self.assertIn("nt_ssh_scalar_to ssh.socket ActiveEnterTimestampMonotonic", identity)
        self.assertIn("nt_ssh_scalar_to ssh.socket InvocationID", identity)
        self.assertNotIn("ssh.socket Listen", identity)
        self.assertNotIn("-p Listen)", ssh)
        differing = ssh.split("                if (( _nt_rc == 1 )); then\n", 1)[1].split("                else\n", 1)[0]
        self.assertLess(differing.index('                    cat -- "$NT_RUN/$_nt_prefix.diff.json"'),
                        differing.index('                    nt_error "Kumpulan listener'))
        acceptance = ssh.split("nt_ssh_accept_post_os_identity() {\n", 1)[1].split("\n\nnt_openssh_keys()", 1)[0]
        self.assertLess(acceptance.index("    nt_verify_preserved_ssh || return 1"),
                        acceptance.index("    NT_SSH_START_EXPECTED="))

    def test_policy_never_accepts_runtime_or_secret_paths(self):
        for name in ("config/config.conf", "data/ssh/accounts.db", "logs/fixture.log",
                     "keys/fixture.key", "updater/secrets/fixture.json", "tools/fixture.pem"):
            policy = actual_policy()
            policy["files"][name] = {"mode": "0644", "deploy": False}
            with self.subTest(path=name), self.assertRaises(R.Blocked):
                R.load_policy(R.json_bytes(policy))

    def test_python_sources_compile_in_memory_not_pycache(self):
        paths = list(REPO.rglob("*.py"))
        paths = [path for path in paths if ".git" not in path.relative_to(REPO).parts]
        self.assertTrue(paths)
        for path in paths:
            compile(path.read_bytes(), str(path.relative_to(REPO)), "exec", dont_inherit=True)


class InstallStateTests(Isolated):
    def setUp(self):
        super().setUp()
        self.source = self.base / "source"
        self.root = self.base / "root"
        self.root.mkdir()
        self.version = self.root / "opt/nathaya/VERSION"
        self.baseline = self.root / U.INSTALLED_REL
        self.baseline.parent.mkdir(parents=True)
        self.journal = self.base / "updater-before.json"
        write(self.source / "VERSION", b"2.0.1\n")
        self.protected = {
            "etc/nathaya-tunnel/config.conf": b"inert-config-fixture\n",
            "opt/nathaya/data/ssh/accounts.db": b"inert-db-fixture\n",
            "etc/ssh/ssh_host_ed25519_key": b"inert-not-a-private-key\n"}
        for name, raw in self.protected.items():
            write(self.root / name, raw, 0o600)

    def seed(self, identity="2.0.0", schema=1, baseline_version=None):
        write(self.version, (identity + "\n").encode())
        raw = (json.dumps({"version": baseline_version or identity, "schema": schema}, indent=2)
               + "\n\n").encode()
        write(self.baseline, raw, 0o600)
        return raw

    def preserved(self):
        for name, raw in self.protected.items():
            self.same_bytes(self.root / name, raw)
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)

    def prepare(self):
        snapshot = S.prepare_install(self.source, self.root, self.journal)
        self.assertEqual(snapshot, S.validate_prepared(self.source, self.root, self.journal))
        self.assertEqual(stat.S_IMODE(self.journal.stat().st_mode), 0o600)
        return snapshot

    def test_normal_new_commit_only_after_deployed_version(self):
        before = set(self.root.rglob("*"))
        snapshot = S.inspect_install(self.source, self.root)
        self.assertEqual(set(self.root.rglob("*")), before)
        self.assertIsNone(snapshot["previous_version"])
        self.assertIsNone(snapshot["baseline"])
        self.assertEqual(self.prepare(), snapshot)
        self.assertFalse(self.baseline.exists())
        write(self.version, b"2.0.1\n")  # emulate deployment, never execute setup
        self.assertEqual(S.commit_install(self.source, self.root, self.journal), "2.0.1")
        self.assertEqual(json.loads(self.baseline.read_bytes()), {"schema": 1, "version": "2.0.1"})
        self.assertEqual(stat.S_IMODE(self.baseline.stat().st_mode), 0o600)
        self.preserved()

    def test_same_version_preserves_exact_baseline_bytes_without_republish(self):
        raw = self.seed("2.0.1")
        self.prepare()
        with patch.object(S, "atomic_json", side_effect=AssertionError("Unnecessary baseline rewrite")):
            self.assertEqual(S.commit_install(self.source, self.root, self.journal), "2.0.1")
        self.same_bytes(self.baseline, raw)
        self.preserved()

    def test_upgrade_retains_old_baseline_until_successful_commit(self):
        raw = self.seed()
        self.assertEqual(self.prepare()["previous_version"], "2.0.0")
        self.same_bytes(self.baseline, raw)
        with self.assertRaises(ValueError):
            S.commit_install(self.source, self.root, self.journal)  # old deployed version
        self.same_bytes(self.baseline, raw)
        write(self.version, b"2.0.1\n")
        self.same_bytes(self.baseline, raw)
        self.assertEqual(S.commit_install(self.source, self.root, self.journal), "2.0.1")
        self.assertEqual(json.loads(self.baseline.read_bytes()), {"schema": 1, "version": "2.0.1"})
        self.preserved()

    def test_uncommitted_partial_install_preserves_baseline_config_db_key(self):
        raw = self.seed()
        self.prepare()
        write(self.version, b"2.0.1\n")
        # Failure before mandatory gates: no commit and no pretend rollback.
        self.same_bytes(self.baseline, raw)
        with self.assertRaises(ValueError):
            S.inspect_install(self.source, self.root)  # detects inconsistent identity
        self.same_bytes(self.baseline, raw)
        self.preserved()

    def test_downgrade_pending_schema_mismatch_and_private_mode_rejected(self):
        cases = ("downgrade", "pending", "schema", "boolean-schema", "mismatch", "mode")
        for case in cases:
            with self.subTest(case=case):
                raw = self.seed("2.0.2" if case == "downgrade" else "2.0.0",
                                schema=True if case == "boolean-schema" else 2 if case == "schema" else 1,
                                baseline_version="9.0.0" if case == "mismatch" else None)
                pending = self.root / U.PENDING_REL
                if case == "pending":
                    write(pending, b"{}\n", 0o600)
                if case == "mode":
                    self.baseline.chmod(0o644)
                with self.assertRaises(ValueError):
                    S.inspect_install(self.source, self.root)
                with self.assertRaises(ValueError):
                    S.prepare_install(self.source, self.root, self.journal)
                self.assertFalse(self.journal.exists())
                self.same_bytes(self.baseline, raw)
                if pending.exists():
                    pending.unlink()
                self.preserved()

    def test_source_version_changed_after_prepare_blocks_validate_and_commit(self):
        raw = self.seed()
        self.prepare()
        write(self.source / "VERSION", b"2.0.2\n")
        with self.assertRaisesRegex(ValueError, "changed after lock"):
            S.validate_prepared(self.source, self.root, self.journal)
        write(self.version, b"2.0.2\n")
        with self.assertRaisesRegex(ValueError, "Candidate changed"):
            S.commit_install(self.source, self.root, self.journal)
        self.same_bytes(self.baseline, raw)
        self.preserved()

    def test_changed_baseline_or_pending_after_prepare_blocks_commit(self):
        self.seed()
        self.prepare()
        write(self.version, b"2.0.1\n")
        raw = self.baseline.read_bytes() + b"\n"
        write(self.baseline, raw, 0o600)
        with self.assertRaises(ValueError):
            S.commit_install(self.source, self.root, self.journal)
        self.same_bytes(self.baseline, raw)
        # Restore original baseline hash, then independently test late pending recovery.
        self.seed()
        self.prepare()
        write(self.version, b"2.0.1\n")
        raw = self.baseline.read_bytes()
        write(self.root / U.PENDING_REL, b"{}\n", 0o600)
        with self.assertRaises(ValueError):
            S.commit_install(self.source, self.root, self.journal)
        self.same_bytes(self.baseline, raw)
        self.preserved()


class InstalledTrustTests(Isolated):
    def setUp(self):
        super().setUp()
        self.policy = actual_policy()
        self.identity, self.blob = R.build_artifact(REPO, self.policy, checker)
        self.meta = metadata(self.identity, self.blob)
        self.root = self.base / "root"
        self.root.mkdir(mode=0o700)
        # Only the actual install manifest, not the entire checkout, is installed.
        for name in PROGRAM:
            write(self.root / "opt/nathaya" / name, (REPO / name).read_bytes(),
                  int(self.policy["files"][name]["mode"], 8))
        self.calls = []
        self.engine = U.Updater(self.root, fetcher=self.fetch, checker=checker,
                                activator=lambda _: self.fail("No deployment in trust checks"))

    def fetch(self, url, limit, download=False):
        self.calls.append(download)
        self.assertEqual(url, self.meta["assets"][0]["browser_download_url"] if download else U.API_URL)
        raw = self.blob if download else R.json_bytes(self.meta)
        self.assertLessEqual(len(raw), limit)
        return raw

    def test_exact_installed_trust_group_accepts_package_only_absence(self):
        self.assertEqual({name for name, spec in self.engine.policy["files"].items()
                          if not spec["deploy"] and name not in PACKAGE_ONLY}, TRUST)
        for name in PACKAGE_ONLY:
            self.assertFalse((self.root / "opt/nathaya" / name).exists())
        _, manifest, files = self.engine.verified_release(self.identity)
        self.assertEqual(set(files), RELEASE)
        self.assertEqual(manifest["version"], self.identity)
        self.assertEqual(self.calls, [False, True])

    def test_each_installed_trust_file_missing_or_drift_fails_closed(self):
        for name in sorted(TRUST):
            path = self.root / "opt/nathaya" / name
            raw = path.read_bytes()
            for case in ("missing", "drift"):
                with self.subTest(path=name, case=case):
                    if case == "missing":
                        path.unlink()
                    else:
                        write(path, raw + b"\nOFFLINE_DRIFT\n")
                    with self.assertRaisesRegex(R.Blocked, "trust-base|Trust-base"):
                        self.engine.verified_release(self.identity)
                    self.assertFalse((self.root / U.MANUAL_REL).exists())
                    write(path, raw, int(self.policy["files"][name]["mode"], 8))


if __name__ == "__main__":
    unittest.main()
