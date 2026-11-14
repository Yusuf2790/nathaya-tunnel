"""Offline HAProxy identity/ownership/backup fixtures; never execute a command.

Run with python3 -I -B tests/haproxy_identity_test.py. Not a live VPS test.
"""
import sys
sys.dont_write_bytecode = True

from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import urllib.request
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
ERROR = "BLOCKED HAProxy: identity/unit validation failed\n"
UNIT = "/etc/systemd/system/nathaya-haproxy.service"


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


C = module("haproxy_fixture_checks", "installer/checks.py")
S = module("haproxy_fixture_state", "installer/state.py")


def status(pid=100, ppid=1, uid=0, gid=0, caps="4e0"):
    return (f"Name: haproxy\nPid: {pid}\nPPid: {ppid}\n"
            f"Uid: {uid} {uid} {uid} {uid}\nGid: {gid} {gid} {gid} {gid}\nGroups: {gid}\n"
            f"CapEff: {caps}\nCapPrm: {caps}\nCapAmb: 0000000000000000\nNoNewPrivs: 1\n")


def worker(pid=101):
    return status(pid, 100, 123, 124, "0")


class Offline(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for obj, names in ((subprocess, ("run", "Popen", "call", "check_call", "check_output")),
                           (os, ("system", "popen")),
                           (socket, ("socket", "create_connection", "getaddrinfo")),
                           (urllib.request, ("urlopen", "urlretrieve")),
                           (C.pwd, ("getpwnam",)), (C.grp, ("getgrnam",))):
            for name in names:
                self.stack.enter_context(patch.object(obj, name, side_effect=AssertionError(
                    "Real operation forbidden in HAProxy fixture tests")))

    def cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            # The new CLI must dispatch before legacy registry/config/ss checks.
            for name in ("required_listeners", "parse_ss", "check_rows", "_metadata"):
                stack.enter_context(patch.object(C, name, side_effect=AssertionError(
                    "Legacy preflight reached by identity CLI")))
            stack.enter_context(patch.object(sys, "argv", ["checks.py"] + args))
            stack.enter_context(patch.object(sys, "stdout", out))
            stack.enter_context(patch.object(sys, "stderr", err))
            rc = C.main()
        return rc, out.getvalue(), err.getvalue()


class IdentityFixtures(Offline):
    def parsed(self):
        return C.parse_haproxy_status(status()), [C.parse_haproxy_status(worker())]

    def test_valid_master_and_multiple_nonroot_old_workers(self):
        master, workers = self.parsed()
        workers.append(C.parse_haproxy_status(worker(102)))
        self.assertTrue(C.validate_haproxy_identity(master, workers, 123, 124))

    def test_empty_supplementary_groups_are_allowed(self):
        master, workers = self.parsed()
        workers[0]["Groups"] = ()
        self.assertTrue(C.validate_haproxy_identity(master, workers, 123, 124))

    def test_root_or_partial_root_workers_and_caps_denied(self):
        for field, value in (("Uid", (0,) * 4), ("Gid", (0,) * 4),
                             ("Uid", (123, 123, 0, 123)), ("Gid", (124, 0, 124, 124)),
                             ("Uid", (125,) * 4), ("Gid", (125,) * 4),
                             ("Groups", (0,)), ("Groups", (124, 42)),
                             ("CapEff", 1), ("CapPrm", 1), ("CapAmb", 1),
                             ("NoNewPrivs", 0), ("PPid", 99)):
            with self.subTest(field=field):
                master, workers = self.parsed()
                workers[0][field] = value
                with self.assertRaises(ValueError):
                    C.validate_haproxy_identity(master, workers, 123, 124)

    def test_master_exact_narrow_capability_and_identity_contract(self):
        for field, value in (("Uid", (123,) * 4), ("Gid", (124,) * 4),
                             ("Uid", (0, 0, 123, 0)), ("CapAmb", 0x4e0),
                             ("CapEff", 0), ("CapPrm", 0), ("NoNewPrivs", 0),
                             ("CapEff", 0x4c0), ("CapPrm", 0x4c0),
                             ("CapEff", 0x4e0 | (1 << 21)), ("CapPrm", (1 << 41) - 1)):
            master, workers = self.parsed()
            master[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.validate_haproxy_identity(master, workers, 123, 124)
        master, workers = self.parsed()
        for uid, gid in ((0, 124), (123, 0), (-1, 124), (True, 124)):
            with self.assertRaises(ValueError):
                C.validate_haproxy_identity(master, workers, uid, gid)
        with self.assertRaises(ValueError):
            C.validate_haproxy_identity(master, [], 123, 124)

    def test_status_missing_duplicate_malformed_fields(self):
        for bad in ("", status().replace("NoNewPrivs: 1\n", ""),
                    status() + "Uid: 0 0 0 0\n", status().replace("CapEff: 4e0", "CapEff: nope"),
                    status().replace("Uid: 0 0 0 0", "Uid: 0 0 0"),
                    status().replace("PPid: 1", "PPid: -1")):
            with self.assertRaises(ValueError):
                C.parse_haproxy_status(bad)

    def runtime(self, overrides=None):
        reads = {"/proc/100/status": status(), "/proc/101/status": worker(),
                 "/proc/102/status": worker(102), "/proc/100/task/100/children": "101 102\n"}
        reads.update(overrides or {})
        def read(path):
            value = reads[str(path)]  # Any arbitrary PID read fails this fixture.
            if isinstance(value, Exception):
                raise value
            return value
        self.stack.enter_context(patch.object(C, "_proc_text", side_effect=read))
        self.stack.enter_context(patch.object(C.os, "readlink", return_value="/usr/sbin/haproxy"))
        self.stack.enter_context(patch.object(C.pwd, "getpwnam",
                                             return_value=SimpleNamespace(pw_uid=123, pw_gid=124)))
        self.stack.enter_context(patch.object(C.grp, "getgrnam",
                                             return_value=SimpleNamespace(gr_gid=124)))

    def test_runtime_cli_enumerates_only_master_children_and_dispatches_early(self):
        self.runtime()
        self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (0, "", ""))

    def test_read_errors_have_fixed_no_private_diagnostic(self):
        self.runtime({"/proc/101/status": OSError("PRIVATE_FIXTURE_VALUE")})
        self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))

    def test_deleted_or_other_executable_rejected(self):
        self.runtime()
        for exe in ("/usr/sbin/haproxy (deleted)", "/tmp/haproxy"):
            with patch.object(C.os, "readlink", return_value=exe):
                self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))

    def test_observed_reload_or_identity_change_rejected_without_retry(self):
        self.runtime()
        with patch.object(C, "_haproxy_children", side_effect=[[101], [101, 102]]) as read:
            self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))
            self.assertEqual(read.call_count, 2)
        with patch.object(C, "_haproxy_process", side_effect=[
                C.parse_haproxy_status(status()), C.parse_haproxy_status(worker()),
                C.parse_haproxy_status(status()), C.parse_haproxy_status(worker().replace(
                    "NoNewPrivs: 1", "NoNewPrivs: 0"))]):
            with patch.object(C, "_haproxy_children", return_value=[101]):
                self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))

    def test_malformed_empty_or_duplicate_children_are_rejected(self):
        self.runtime()
        for children in ("", "101 101", "100", "../101", "0", "101 " * 1025):
            with patch.object(C, "_proc_text", return_value=children):
                self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))

    def test_missing_or_root_account_is_failure(self):
        self.runtime()
        with patch.object(C.pwd, "getpwnam", side_effect=KeyError("PRIVATE_FIXTURE_VALUE")):
            self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))
        with patch.object(C.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=0, pw_gid=124)):
            self.assertEqual(self.cli(["verify-haproxy-identity", "100"]), (1, "", ERROR))

    def test_cli_bad_args_and_unit_dispatch_are_early(self):
        for args in (["verify-haproxy-identity"], ["verify-haproxy-identity", "../1"],
                     ["verify-haproxy-identity", "0"], ["verify-haproxy-identity", "100", "101"],
                     ["check-haproxy-unit", "extra"]):
            self.assertEqual(self.cli(args), (1, "", ERROR))
        with patch.object(C, "check_haproxy_unit") as check:
            self.assertEqual(self.cli(["check-haproxy-unit"]), (0, "", ""))
            check.assert_called_once_with()


class RegistryFixtures(Offline):
    def setUp(self):
        super().setUp()
        temp = tempfile.TemporaryDirectory(prefix="nathaya-haproxy-fixture-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve() / "root"
        self.directory = self.root / "etc/nathaya-tunnel"
        self.directory.mkdir(parents=True, mode=0o700)
        self.registry = self.directory / "managed-services.json"
        self.unit = self.root / UNIT.lstrip("/")
        self.unit.parent.mkdir(parents=True)
        self.unit.write_bytes(b"old-managed-unit-fixture\n")
        self.unit.chmod(0o644)
        self.old = {"schema": 1, "owner": "Nathaya Tunnel",
                    "files": {UNIT: hashlib.sha256(self.unit.read_bytes()).hexdigest()}}
        self.seed(self.old)
        self.run = self.root / "run.fixture"
        self.run.mkdir(mode=0o700)

    def seed(self, value):
        # Preserve noncanonical whitespace to prove byte-exact backup, not reserialization.
        raw = (json.dumps(value, indent=2) + "\n\n").encode()
        self.registry.write_bytes(raw)
        self.registry.chmod(0o600)
        return raw

    def check(self, fragment=UNIT, dropins="", load="loaded", bad_property=None):
        values = dict(zip(("FragmentPath", "DropInPaths", "LoadState"), (fragment, dropins, load)))
        def show(args, **kwargs):
            self.assertEqual(args[:3], ["systemctl", "show", "nathaya-haproxy.service"])
            self.assertEqual(args[4:], ["--value"])
            prop = args[3].removeprefix("--property=")
            self.assertIn(prop, values)
            self.assertFalse(kwargs["check"])
            self.assertEqual(kwargs["timeout"], 10)
            return SimpleNamespace(stdout=values[prop] + "\n", stderr="", returncode=int(prop == bad_property))
        with patch.object(C.subprocess, "run", side_effect=show) as mock:
            C.check_haproxy_unit(self.root)
            self.assertEqual(mock.call_count, 3)
            self.assertEqual([c.args[0][3] for c in mock.call_args_list],
                             ["--property=" + p for p in ("FragmentPath", "DropInPaths", "LoadState")])

    def test_old_registered_hash_matches_even_when_new_renderer_will_change(self):
        self.check()  # no comparison with new renderer bytes, no global port query

    def test_drift_foreign_hardlink_or_symlink_never_blessed(self):
        self.unit.write_bytes(b"edited-unit-fixture\n")
        with self.assertRaises(ValueError):
            self.check()
        self.unit.write_bytes(b"old-managed-unit-fixture\n")
        self.registry.unlink()
        with self.assertRaises(ValueError):
            self.check()
        self.seed(self.old)
        link = self.unit.with_name("hardlink")
        os.link(self.unit, link)
        with self.assertRaises(ValueError):
            self.check()
        link.unlink()
        self.unit.unlink()
        self.unit.symlink_to(link)
        with self.assertRaises(ValueError):
            self.check()

    def test_dropins_mask_vendor_and_nonzero_property_codes_rejected(self):
        for kwargs in ({"dropins": "/etc/systemd/system/nathaya-haproxy.service.d/local.conf"},
                       {"load": "masked", "fragment": "/dev/null"},
                       {"fragment": "/usr/lib/systemd/system/nathaya-haproxy.service"},
                       {"load": "not-found", "fragment": ""},
                       *({"bad_property": p} for p in ("FragmentPath", "DropInPaths", "LoadState"))):
            with self.subTest(case=kwargs), self.assertRaises(ValueError):
                self.check(**kwargs)

    def test_genuinely_missing_unit_is_safe_but_unowned_effective_unit_is_not(self):
        self.registry.unlink()
        self.unit.unlink()
        self.check(fragment="", load="not-found")
        for kwargs in ({"fragment": UNIT}, {"fragment": "", "load": "masked"},
                       {"fragment": "", "load": "not-found", "dropins": "/fixture.conf"}):
            with self.assertRaises(ValueError):
                self.check(**kwargs)

    def test_registered_missing_unit_is_drift_not_fresh_install(self):
        self.unit.unlink()
        with self.assertRaises(ValueError):
            self.check(fragment="", load="not-found")
        with self.assertRaises(ValueError):
            C.validate_haproxy_unit("", "", "not-found", owned=True, exists=False)

    def test_other_managed_unit_drift_also_blocks_under_lock(self):
        other = self.unit.with_name("nathaya-nginx.service")
        other.write_bytes(b"foreign-fixture\n")
        with self.assertRaises(ValueError):
            self.check()

    def test_strict_registry_schema_private_mode_and_links(self):
        for value in ({}, {**self.old, "schema": True}, {**self.old, "schema": 2},
                      {**self.old, "owner": "foreign"}, {**self.old, "files": {}},
                      {**self.old, "files": {UNIT: "invalid"}}, {**self.old, "extra": 1}):
            self.seed(value)
            with self.assertRaises(ValueError):
                S.read_service_registry(self.root)
        self.seed(self.old)
        self.registry.chmod(0o644)
        with self.assertRaises(ValueError):
            S.read_service_registry(self.root)
        self.registry.chmod(0o600)
        self.directory.chmod(0o755)
        with self.assertRaises(ValueError):
            S.read_service_registry(self.root)
        self.directory.chmod(0o700)
        link = self.run / "linked"
        os.link(self.registry, link)
        with self.assertRaises(ValueError):
            S.read_service_registry(self.root)
        link.unlink()
        self.registry.unlink()
        self.registry.symlink_to(link)
        with self.assertRaises(ValueError):
            S.read_service_registry(self.root)

    def test_production_trusted_path_requires_root_owner(self):
        # Synthetic stat data only: never read or write a real production path.
        target = Path("/etc/nathaya-tunnel/managed-services.json")
        for foreign in (target, target.parent):
            def info(path, *args, **kwargs):
                return SimpleNamespace(st_mode=(stat.S_IFREG | 0o600) if path == target else
                                       (stat.S_IFDIR | 0o700), st_nlink=1,
                                       st_uid=123 if path == foreign else 0)
            with patch.object(S.Path, "lstat", info):
                with self.assertRaises(ValueError):
                    S._safe(target, production=True)

    def test_backup_rejects_untrusted_or_ambiguous_previous_snapshots(self):
        backup = self.run / "managed-services.before.json"
        absent = self.run / "managed-services.absent"
        backup.write_bytes(self.registry.read_bytes())
        backup.chmod(0o644)
        with self.assertRaises(ValueError):
            S.backup_service_registry(self.run, self.root)
        backup.chmod(0o600)
        absent.write_bytes(b"absent\n")
        absent.chmod(0o600)
        with self.assertRaises(ValueError):
            S.backup_service_registry(self.run, self.root)
        absent.unlink()
        backup.unlink()
        self.run.chmod(0o755)
        with self.assertRaises(ValueError):
            S.backup_service_registry(self.run, self.root)

    def test_private_backup_exact_old_bytes_first_snapshot_wins(self):
        raw = self.registry.read_bytes()
        self.unit.write_bytes(b"new-unit-fixture\n")
        S.record_services(self.root, self.run)
        backup = self.run / "managed-services.before.json"
        self.assertTrue(backup.read_bytes() == raw, "Old registry bytes not preserved")
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.run.stat().st_mode), 0o700)
        self.assertFalse((self.run / "managed-services.absent").exists())
        self.assertNotEqual(json.loads(self.registry.read_bytes()), self.old)
        self.unit.write_bytes(b"second-unit-fixture\n")
        S.record_services(self.root, self.run)
        self.assertTrue(backup.read_bytes() == raw, "First backup replaced")

    def test_absence_marker_remains_distinct_after_second_record(self):
        self.registry.unlink()
        S.record_services(self.root, self.run)
        absent = self.run / "managed-services.absent"
        self.assertEqual(absent.read_bytes(), b"absent\n")
        self.assertEqual(stat.S_IMODE(absent.stat().st_mode), 0o600)
        S.record_services(self.root, self.run)
        self.assertFalse((self.run / "managed-services.before.json").exists())
        self.assertEqual(absent.read_bytes(), b"absent\n")

    def test_backup_failure_never_publishes_registry(self):
        raw = self.registry.read_bytes()
        with patch.object(S, "backup_service_registry", side_effect=ValueError("fixture failure")):
            with self.assertRaises(ValueError):
                S.record_services(self.root, self.run)
        self.assertTrue(self.registry.read_bytes() == raw, "Published before backup")

    def test_backup_cli_interface_and_no_unapproved_destination(self):
        with patch.object(S.os, "geteuid", return_value=0), patch.object(S, "record_services") as record:
            with patch.object(sys, "argv", ["state.py", "record-services", "--backup",
                                             "/var/backups/nathaya-tunnel/run.fixture"]):
                S.main()
            record.assert_called_once_with(backup=Path("/var/backups/nathaya-tunnel/run.fixture"))
            with patch.object(sys, "argv", ["state.py", "record-services", "--backup", "/tmp/run.fixture"]):
                with self.assertRaises(ValueError):
                    S.main()


if __name__ == "__main__":
    unittest.main()
