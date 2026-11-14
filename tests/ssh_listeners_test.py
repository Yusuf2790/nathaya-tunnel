"""Pure SSH Listen fixtures; no commands, live sockets, network or system checks.

Import checks.py and call main() in process; only temporary regular-file fixtures
are read by compare mode. These tests do not establish live VPS/systemd behavior.
"""
import sys
sys.dont_write_bytecode = True

import ast
from contextlib import ExitStack, contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
ERROR = "BLOCKED SSH listeners: invalid input\n"


@contextmanager
def offline():
    with ExitStack() as stack:
        for obj, names in (
                (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
                (socket, ("socket", "create_connection", "getaddrinfo")),
                (urllib.request, ("urlopen", "urlretrieve")),
                (os, ("system", "popen"))):
            for name in names:
                stack.enter_context(patch.object(obj, name, side_effect=AssertionError(
                    "External execution/network forbidden in fixture tests")))
        yield


with offline():
    spec = importlib.util.spec_from_file_location("ssh_listener_checks", ROOT / "installer/checks.py")
    C = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(C)


def record(address="0.0.0.0", family="IPv4", port=22, kind="Stream"):
    return {"family": family, "address": address, "port": port, "type": kind}


class ListenerFixtures(unittest.TestCase):
    def setUp(self):
        self.guards = offline()
        self.guards.__enter__()
        self.addCleanup(self.guards.__exit__, None, None, None)

    def cli(self, args, raw=b""):
        stdout, stderr = io.StringIO(), io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
        with ExitStack() as stack:
            for name in ("required_listeners", "parse_ss", "check_rows", "pid_in_unit"):
                stack.enter_context(patch.object(C, name, side_effect=AssertionError(
                    "Legacy system check reached by SSH-only CLI")))
            # Catch configuration/registry/proc reads, even if no subprocess is used.
            for name in ("read_text", "exists", "is_symlink", "stat"):
                stack.enter_context(patch.object(C.Path, name, side_effect=AssertionError(
                    "Legacy filesystem preflight reached by SSH-only CLI")))
            stack.enter_context(patch.object(sys, "argv", ["checks.py"] + args))
            stack.enter_context(patch.object(sys, "stdin", stdin))
            stack.enter_context(patch.object(sys, "stdout", stdout))
            stack.enter_context(patch.object(sys, "stderr", stderr))
            status = C.main()
        stdin.close()
        return status, stdout.getvalue(), stderr.getvalue()

    def assertBadCLI(self, args, raw=b""):
        status, out, err = self.cli(args, raw)
        self.assertEqual(status, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, ERROR)

    def test_reorder_whitespace_padding_and_prefixes(self):
        expected = [record(), record("::", "IPv6")]
        for raw in (
                "0.0.0.0:22 (Stream)\n[::]:22 (Stream)\n",
                "[::]:22 (Stream) 0.0.0.0:22 (Stream)",
                " \tListen= [::]:00022 \n( \tStream\r\n) \nListen=0.0.0.0:22(Stream)\t",
                "0.0.0.0:22 (Stream) [::]:22 (Stream) 0.0.0.0:22 (Stream)",
                "0.0.0.0:000000000022 (Stream) [::]:22 (Stream)"):
            with self.subTest(raw=raw):
                self.assertEqual(C.canonical_ssh_listeners(raw), expected)

    def test_numeric_normalization_and_exact_zones(self):
        self.assertEqual(C.canonical_ssh_listeners(
            "[2001:0DB8:0000:0000:0000:0000:0000:0001]:22 (Stream)"),
            [record("2001:db8::1", "IPv6")])
        self.assertEqual(C.canonical_ssh_listeners("[FE80:0:0:0:0:0:0:1%EnP0s3]:65535 (Datagram)"),
                         [record("fe80::1%EnP0s3", "IPv6", 65535, "Datagram")])
        self.assertEqual(C.canonical_ssh_listeners("[::1%003]:1 (SequentialPacket)"),
                         [record("::1%003", "IPv6", 1, "SequentialPacket")])
        self.assertNotEqual(C.canonical_ssh_listeners("[::1%003]:22 (Stream)"),
                            C.canonical_ssh_listeners("[::1%3]:22 (Stream)"))

    def test_empty_policies(self):
        for raw in ("", " \t\n\r", "Listen=", " Listen= \n"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    C.canonical_ssh_listeners(raw)
                self.assertEqual(C.canonical_ssh_listeners(raw, False), [])
        with self.assertRaises(ValueError):
            C.validate_ssh_listener_set([])
        self.assertEqual(C.validate_ssh_listener_set([], False), [])
        self.assertEqual(C.ssh_listener_diff([], []), {"removed": [], "added": []})

    def test_reject_entire_malformed_input(self):
        good = "127.0.0.1:22 (Stream)"
        for raw in (None, 22, b"", "*:22 (Stream)", "22 (Stream)",
                    "::1:22 (Stream)", "[127.0.0.1]:22 (Stream)",
                    "localhost:22 (Stream)", "127.00.0.1:22 (Stream)",
                    "[::gg]:22 (Stream)", "[::1%]:22 (Stream)",
                    "[::1%eth0%1]:22 (Stream)", "[::1%eth 0]:22 (Stream)",
                    "0.0.0.0:0 (Stream)", "0.0.0.0:65536 (Stream)",
                    "0.0.0.0:" + "9" * 5000 + " (Stream)",
                    "0.0.0.0:-22 (Stream)", "0.0.0.0:+22 (Stream)",
                    "0.0.0.0:２２ (Stream)", "0.0.0.0:22 (stream)",
                    "0.0.0.0:22 (Raw)", "0.0.0.0:22 Stream", "0.0.0.0:22 ()",
                    good + " trailing-secret", "secret\n" + good,
                    good + "\nsecret\n" + good, good + good,
                    good + "\x00", good + "\x1b", good + "\x7f", good + "\x85",
                    good + "\v", good + "\f", good + "\u00a0"):
            with self.subTest(index=repr(raw)[:40]):
                with self.assertRaisesRegex(ValueError, "^Invalid SSH listener data$"):
                    C.canonical_ssh_listeners(raw)

    def test_schema_strictness_and_set_sorting(self):
        v4, v6 = record(), record("::", "IPv6")
        self.assertEqual(C.validate_ssh_listener_set([v6, v4, v4]), [v4, v6])
        invalid = [None, {}, (), "[]", [None], [[]], [dict(v4, extra="private")],
                   [{k: v for k, v in v4.items() if k != "type"}]]
        for field, values in (
                ("family", (None, [], "ipv4", "IPv7", "IPv6")),
                ("address", (None, 1, "localhost", "0.0.0.00", "::")),
                ("port", (True, False, 0, 65536, -1, "22", 22.0, None)),
                ("type", (None, [], "stream", "Raw"))):
            invalid.extend([[dict(v4, **{field: value})] for value in values])
        invalid.extend([[record("2001:0DB8::1", "IPv6")],
                        [record("0:0:0:0:0:0:0:1", "IPv6")],
                        [record("::1%bad\nzone", "IPv6")]])
        for value in invalid:
            with self.subTest(index=repr(value)[:60]):
                with self.assertRaisesRegex(ValueError, "^Invalid SSH listener data$"):
                    C.validate_ssh_listener_set(value)

    def test_diff_every_dimension_and_combined_changes(self):
        old = record()
        for new in (record("::", "IPv6"), record(kind="Datagram"),
                    record(kind="SequentialPacket"), record("127.0.0.1"), record(port=2222)):
            with self.subTest(new=new):
                self.assertEqual(C.ssh_listener_diff([old], [new]),
                                 {"removed": [old], "added": [new]})
        v6 = record("::", "IPv6")
        self.assertEqual(C.ssh_listener_diff([v6, old, old], [old, v6]),
                         {"removed": [], "added": []})
        changed = [record(port=23), record("::1", "IPv6")]
        self.assertEqual(C.ssh_listener_diff([v6, old], list(reversed(changed))),
                         {"removed": [old, v6], "added": changed})
        self.assertEqual(C.ssh_listener_diff([old], []), {"removed": [old], "added": []})
        self.assertEqual(C.ssh_listener_diff([], [old]), {"removed": [], "added": [old]})

    def test_canonical_cli_output_and_errors(self):
        expected = json.dumps([record(), record("::", "IPv6")],
                              sort_keys=True, separators=(",", ":")) + "\n"
        self.assertEqual(self.cli(["canonical-ssh-listeners"],
                                  b"[::]:22 (Stream)\n0.0.0.0:22 (Stream)"), (0, expected, ""))
        self.assertEqual(self.cli(["canonical-ssh-listeners", "--allow-empty"]), (0, "[]\n", ""))
        for args, raw in (([], b""), (["--unknown"], b"private-secret"),
                          (["--allow-empty", "--allow-empty"], b""),
                          ([], b"\xff"), ([], b"secret\n0.0.0.0:22 (Stream)"),
                          ([], b" " * (C._SSH_LIMIT + 1))):
            self.assertBadCLI(["canonical-ssh-listeners"] + args, raw)
        exact = b"0.0.0.0:22 (Stream)"
        exact += b" " * (C._SSH_LIMIT - len(exact))
        self.assertEqual(self.cli(["canonical-ssh-listeners"], exact)[0], 0)
        # Verify the bounded read request itself, not just the rejection afterwards.
        reader = io.BytesIO(b"x" * (C._SSH_LIMIT + 100))
        with patch.object(sys, "argv", ["checks.py", "canonical-ssh-listeners"]), \
                patch.object(sys, "stdin") as stdin, \
                patch.object(sys, "stderr", io.StringIO()), \
                patch.object(sys, "stdout", io.StringIO()):
            stdin.buffer = reader
            self.assertEqual(C.main(), 2)
        self.assertEqual(reader.tell(), C._SSH_LIMIT + 1)

    def test_compare_cli_statuses_regular_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory).resolve() / "before.json", Path(directory).resolve() / "after.json"
            old, new = record(), record(port=2222)
            a.write_text(json.dumps([old]), encoding="utf-8")
            b.write_text(json.dumps([old, old]), encoding="utf-8")
            args = ["compare-ssh-listeners", str(a), str(b)]
            self.assertEqual(self.cli(args), (0, '{"added":[],"removed":[]}\n', ""))
            b.write_text(json.dumps([new]), encoding="utf-8")
            status, out, err = self.cli(args)
            self.assertEqual((status, err), (1, ""))
            self.assertEqual(out, json.dumps({"removed": [old], "added": [new]},
                                            sort_keys=True, separators=(",", ":")) + "\n")
            a.write_text("[]", encoding="utf-8")
            b.write_text("[]", encoding="utf-8")
            self.assertEqual(self.cli(args), (0, '{"added":[],"removed":[]}\n', ""))
            a.write_text(json.dumps([old]), encoding="utf-8")
            self.assertEqual(self.cli(args)[0], 1)

    def test_compare_bad_json_schema_and_paths_do_not_leak(self):
        with tempfile.TemporaryDirectory(prefix="private-fixture-") as directory:
            a, b = Path(directory).resolve() / "before.json", Path(directory).resolve() / "private-after.json"
            a.write_text("[]", encoding="utf-8")
            args = ["compare-ssh-listeners", str(a), str(b)]
            self.assertBadCLI(args)  # Missing path, including its private name, is not printed.
            for raw in (b"private-secret", b"\xff", b"{}", b"null", b"[true]",
                        b"[NaN]", b"[Infinity]", b"[1e999]", b"[", b"[[]]",
                        b'[{"family":"IPv4","address":"0.0.0.0","port":22,"port":23,"type":"Stream"}]',
                        json.dumps([dict(record(), private="private-secret")]).encode(),
                        b" " * (C._SSH_LIMIT + 1), b"[" * 2000):
                b.write_bytes(raw)
                self.assertBadCLI(args)
            b.write_bytes(b"[]" + b" " * (C._SSH_LIMIT - 2))
            self.assertEqual(self.cli(args)[0], 0)
            self.assertBadCLI(["compare-ssh-listeners"])
            self.assertBadCLI(["compare-ssh-listeners", str(a)])
            self.assertBadCLI(args + ["private-extra"])
            self.assertBadCLI(["compare-ssh-listeners", directory, str(a)])
            link = Path(directory) / "symbolic.json"
            link.symlink_to(a)
            self.assertBadCLI(["compare-ssh-listeners", str(link), str(b)])
            self.assertBadCLI(["compare-ssh-listeners", str(b), str(link)])
            parent_link = Path(directory) / "linked-parent"
            parent_link.symlink_to(directory, target_is_directory=True)
            self.assertBadCLI(["compare-ssh-listeners", str(parent_link / a.name), str(b)])
            hard = Path(directory) / "hard.json"
            os.link(a, hard)
            self.assertBadCLI(["compare-ssh-listeners", str(hard), str(b)])
            self.assertBadCLI(["compare-ssh-listeners", str(a), str(b)])

    def test_script_propagates_main_status_without_executing_it(self):
        # In-process main() tests above cannot exercise Python's __main__ guard.
        tree = ast.parse((ROOT / "installer/checks.py").read_text(encoding="utf-8"))
        guard = tree.body[-1]
        self.assertIsInstance(guard, ast.If)
        statement = guard.body[0].body[0]
        self.assertIsInstance(statement, ast.Raise)
        self.assertIsInstance(statement.exc, ast.Call)
        self.assertEqual(statement.exc.func.id, "SystemExit")
        self.assertEqual(statement.exc.args[0].func.id, "main")


if __name__ == "__main__":
    unittest.main()
