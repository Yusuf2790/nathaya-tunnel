"""Offline contracts for the embedded diagnostic; no commands or live host tests.

The shell is inspected as text, never sourced/executed. The Python heredoc is
AST-compiled and imported with a non-main name under hostile host guards. All
controller evidence, sockets, account lookups and runners are in-memory mocks.
This does not establish systemd/HAProxy/strace compatibility on a VPS.
"""
import sys
sys.dont_write_bytecode = True

import ast
import builtins
import collections
from contextlib import ExitStack
import copy
import errno
import grp
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import signal
import socket
import stat
import subprocess
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
import urllib.request
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
# Only checkout source reads happen during discovery, before host guards. No
# renderer CLI, load_ports(), account lookup, runtime path or probe is invoked.
SHELL = (ROOT / 'tools/diagnose-haproxy.sh').read_text(encoding='utf-8')
MARKER = 'NATHAYA_HAPROXY_DIAG_PY'
START = "<<'" + MARKER + "'\n"
if SHELL.count(START) != 1 or SHELL.count('\n' + MARKER + '\n') != 1:
    raise AssertionError('Expected exactly one quoted diagnostic heredoc')
PYTHON = SHELL.split(START, 1)[1].split('\n' + MARKER + '\n', 1)[0]
TREE = ast.parse(PYTHON, filename='diagnose-haproxy.sh:embedded')
CODE = compile(TREE, 'diagnose-haproxy.sh:embedded', 'exec')
SPEC = importlib.util.spec_from_file_location('diagnostic_actual_renderer', ROOT / 'installer/render.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)
PORTS = json.loads((ROOT / 'config/ports.json').read_text(encoding='utf-8'))
# Discovery-only checkout reads: never open fixtures beneath Offline host guards.
SNAPSHOT_DIR = ROOT / 'tests/fixtures/systemd255-haproxy'
SNAPSHOT_MANIFEST = json.loads((SNAPSHOT_DIR / 'manifest.json').read_text(encoding='utf-8'))
SYNTHETIC_PAIR = json.loads((SNAPSHOT_DIR / 'synthetic-pair.json').read_text(encoding='utf-8'))
REPORTED_PARTIAL = (SNAPSHOT_DIR / 'reported-source.partial.show3lines').read_text(encoding='utf-8')
# Deterministic, public fixture bytes, never generated entropy or a deployed key.
FIXTURE_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
NONCE = 'a' * 32
ABSTRACT = 'nathaya-probe-' + 'b' * 32
MAIN = 'nathaya-haproxy.service'
FRAGMENT = '/etc/systemd/system/' + MAIN
CAPS4 = frozenset(('CAP_NET_BIND_SERVICE', 'CAP_SETUID', 'CAP_SETGID', 'CAP_KILL'))
CAPS3 = CAPS4 - {'CAP_KILL'}


def rendered(old=False):
    # Import the actual renderer, not a hand-maintained copy of its unit text.
    text = R.render_core('vpn.example.org', copy.deepcopy(PORTS),
                         ss_server_key=FIXTURE_KEY)['nathaya-haproxy.service']
    return text.replace(' CAP_KILL', '') if old else text


def exec_property(argv):
    return '{ path=' + argv[0] + ' ; argv[]=' + ' '.join(argv) + ' ; ignore_errors=no }'


def source_properties(old=False):
    """Synthetic complete-for-this-fixture show response, not a host snapshot."""
    result = {
        'Id': MAIN, 'Description': 'Nathaya HAProxy', 'LoadState': 'loaded',
        'FragmentPath': FRAGMENT, 'DropInPaths': '', 'NeedDaemonReload': 'no',
        'Type': 'simple', 'User': 'root', 'Group': 'root', 'UMask': '0077',
        'Slice': 'system.slice', 'NoNewPrivileges': 'yes', 'SecureBits': '0',
        'PrivateNetwork': 'no', 'PrivateUsers': 'no', 'JoinsNamespaceOf': '',
        'RootDirectory': '', 'RootImage': '',
        'AmbientCapabilities': '', 'ProtectSystem': 'strict', 'ProtectHome': 'yes',
        'PrivateTmp': 'yes', 'ProtectKernelTunables': 'yes',
        'ProtectKernelModules': 'yes', 'ProtectControlGroups': 'yes',
        'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
        'RestrictAddressFamilies': 'AF_INET AF_INET6 AF_UNIX',
        'CapabilityBoundingSet': ' '.join(sorted(CAPS3 if old else CAPS4)),
        'SystemCallFilter': '~', 'ReadWritePaths': '/opt/nathaya/logs',
        'Restart': 'on-failure', 'RestartUSec': '3s', 'CanReload': 'yes',
        'StandardOutput': 'append', 'StandardError': 'append',
        'StandardOutputFile': '/opt/nathaya/logs/nathaya-haproxy.log',
        'StandardErrorFile': '/opt/nathaya/logs/nathaya-haproxy.log',
        'WatchdogUSec': 'infinity', 'WatchdogTimestamp': '',
        'WatchdogTimestampMonotonic': '0',
        'RuntimeMaxUSec': 'infinity', 'TimeoutStartUSec': '1min 30s',
        'TimeoutStopUSec': '1min 30s', 'TimeoutAbortUSec': '1min 30s',
        'KillMode': 'control-group', 'SendSIGKILL': 'yes',
        'Transient': 'no', 'ControlGroup': '/system.slice/' + MAIN,
        'ActiveState': 'active', 'SubState': 'running', 'ControlPID': '0',
        'MainPID': '123',
        'ExecStart': exec_property(['/usr/sbin/haproxy', '-W', '-db', '-f',
                                   '/etc/nathaya-tunnel/services/haproxy.cfg']),
        'ExecReload': exec_property(['/bin/kill', '-USR2', '$MAINPID']),
    }
    for key in ('ExecStartPre', 'ExecStartPost', 'ExecCondition', 'ExecStop', 'ExecStopPost'):
        result[key] = ''
    return result


class Offline(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def forbidden(*args, **kwargs):
            raise AssertionError('Real host operation forbidden in diagnostic fixtures')
        # Deliberately blanket-deny filesystem access: even /proc reads and
        # tempfile creation are forbidden here. No real temp files are needed.
        targets = (
            (builtins, ('open',)), (io, ('open',)),
            (subprocess, ('run', 'Popen', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput')),
            (os, ('system', 'popen', 'open', 'read', 'close', 'fdopen', 'fstat',
                  'stat', 'lstat', 'access', 'listdir', 'scandir', 'getxattr',
                  'readlink', 'mkdir', 'makedirs', 'remove', 'unlink', 'rmdir', 'rename',
                  'replace', 'chmod', 'chown', 'link', 'symlink', 'umask', 'kill', 'killpg',
                  'urandom', 'fork', 'execv', 'execve', 'posix_spawn', 'posix_spawnp',
                  'getuid', 'geteuid', 'getgid', 'getegid', 'setuid', 'seteuid',
                  'setgid', 'setegid', 'setgroups', 'setresuid', 'setresgid',
                  'spawnv', 'spawnve', 'spawnvp', 'spawnvpe')),
            (socket, ('socket', 'socketpair', 'create_connection', 'getaddrinfo', 'gethostbyname')),
            (pwd, ('getpwnam', 'getpwuid', 'getpwall')),
            (grp, ('getgrnam', 'getgrgid', 'getgrall')),
            (tempfile, ('mkdtemp', 'mkstemp', 'TemporaryDirectory', 'TemporaryFile', 'NamedTemporaryFile')),
            (urllib.request, ('urlopen', 'urlretrieve')),
            (signal, ('signal',)), (time, ('sleep',)), (platform, ('machine',)),
        )
        for obj, names in targets:
            for name in names:
                if hasattr(obj, name):
                    self.stack.enter_context(patch.object(obj, name, side_effect=forbidden))
        self.stack.enter_context(patch.object(secrets, 'token_hex', return_value=NONCE))
        self.D = ModuleType('nathaya_haproxy_diagnostic_fixture')
        self.D.__file__ = 'diagnose-haproxy.sh:embedded'
        exec(CODE, self.D.__dict__)

    def controller(self, old=False):
        c = self.D.Controller()
        c.directory = Path('/run/nathaya-haproxy-probe.fixture')
        c.source_bytes = rendered(old).encode()
        c.fragment = self.D.validate_fragment(rendered(old))
        c.source = source_properties(old)
        c.caps = self.D.validate_effective(c.source, c.fragment)
        c.record = Mock()
        c.save = Mock(side_effect=lambda name, content: c.directory / name)
        return c

    def plan(self, c, phase='plain'):
        # Real factory, with virtual directories, reservations and evidence only.
        with patch.object(Path, 'mkdir') as mkdir, patch.object(c, 'reserve', return_value=(49173, ABSTRACT)):
            result = c.factory(phase)
        mkdir.assert_called_once_with(mode=0o700)
        return result

    def probe(self, c, plan):
        p = dict(c.source)
        p.update({
            'Id': plan['unit'], 'Description': plan['properties']['Description'],
            'FragmentPath': '/run/systemd/transient/' + plan['unit'],
            'Transient': 'yes', 'ControlGroup': '/system.slice/' + plan['unit'],
            'ActiveState': 'activating', 'SubState': 'start-pre', 'ControlPID': '42',
            'MainPID': '0', 'Restart': 'no', 'RuntimeMaxUSec': '8s',
            'TimeoutStartUSec': '5s', 'TimeoutStopUSec': '2s', 'TimeoutAbortUSec': '2s',
            'CanReload': 'no', 'StandardOutputFile': str(plan['output']),
            'StandardErrorFile': str(plan['output']),
            'ExecStart': exec_property(plan['argv']),
            'ExecStartPre': exec_property(plan['pre']) if plan['pre'] else '',
            'ExecReload': '',
        })
        # Both disabled v255 spellings are valid: retain the source spelling
        # here; the SYNTHETIC pair explicitly overrides the probe to '0'.
        # Preserve availability, not production argv: these aliases describe the
        # transient plan, whose Pre gate is active and Reload is unused.
        for key in ('ExecStart', 'ExecStartPre'):
            if key + 'Ex' in p:
                p[key + 'Ex'] = p[key]
        if 'ExecReloadEx' in p:
            p['ExecReloadEx'] = ''
        return p

    def gate(self, c, plan, probe=None, current=None, live=None, clock=1):
        p = self.probe(c, plan) if probe is None else probe
        current = c.source if current is None else current
        plan['created_at'] = 0
        with ExitStack() as stack:
            stack.enter_context(patch.object(c, 'show', side_effect=[p, current, p if live is None else live]))
            stack.enter_context(patch.object(self.D, '_no_lock'))
            stack.enter_context(patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})))
            stack.enter_context(patch.object(time, 'monotonic', **(
                {'side_effect': clock} if isinstance(clock, list) else {'return_value': clock})))
            c.gate(plan)

    def main_with(self, c, args=None):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(self.D, 'Controller', return_value=c), patch.object(signal, 'signal'), \
                patch.object(sys, 'stdout', out), patch.object(sys, 'stderr', err):
            rc = self.D.main(['--run'] if args is None else args)
        return rc, out.getvalue(), err.getvalue()


class ImportAndShellContracts(Offline):
    def test_ast_compiled_import_does_not_dispatch_main(self):
        self.assertNotEqual(self.D.__name__, '__main__')
        for name in ('parse_show', 'validate_fragment', 'validate_effective',
                     'restriction_differences', 'make_config', 'trace_command',
                     'sanitise_trace', 'owned_unit', 'Controller', 'main'):
            self.assertTrue(callable(getattr(self.D, name)))
        # setUp executes the complete compiled AST under host guards, not a
        # subset of definitions stripped of top-level side effects.
        compile(ast.parse(PYTHON), 'diagnostic-explicit-compile-check', 'exec')
        compile(ast.parse(self.D.GATE_PROGRAM), 'prestart-explicit-compile-check', 'exec')

    def test_help_is_builtin_only_before_python_dispatch(self):
        prefix = SHELL.split(START, 1)[0]
        help_arm = prefix.split('1:--help)', 1)[1].split(';;', 1)[0]
        self.assertIn('return 0', help_arm)
        self.assertIn('--help is read-only', help_arm)
        # Remove quoted strings and shell continuations, leaving only builtins.
        unquoted = re.sub(r"'[^']*'", "''", help_arm).replace('\\\n', '')
        statements = [line.strip() for line in unquoted.splitlines() if line.strip()]
        self.assertEqual(len(statements), 2)
        self.assertTrue(statements[0].startswith('builtin printf '))
        self.assertEqual(statements[1], 'return 0')
        self.assertIn('1:--run|1:--cap-boundaries) ;;', prefix)
        # Dispatch exactly one allowlisted argument, never arbitrary shell argv.
        self.assertIn('case "$#:${1-}" in', prefix)
        self.assertIn('*) builtin printf', prefix)
        self.assertIn('>&2; return 64 ;;', prefix)
        self.assertIn('exec /usr/bin/env -i PATH=', prefix)  # TERM/INT reach controller PID.
        self.assertIn('/usr/bin/python3 -I -B - "$1" ' + START.rstrip('\n'), prefix)
        self.assertEqual(prefix.count('/usr/bin/python3 -I -B - "$1"'), 1)
        self.assertNotIn('/usr/bin/python3 -I -B - "$@"', prefix)
        self.assertLess(prefix.index('return 64 ;;'), prefix.index('exec /usr/bin/env -i'))
        tail = SHELL.split('\n' + MARKER + '\n', 1)[1]
        self.assertRegex(tail, r'if \[\[ "\$\{BASH_SOURCE\[0\]\}" == "\$0" \]\]; then\s+nathaya_diagnose_haproxy_main "\$@"\s+fi')
        self.assertNotRegex(prefix, r'\b(?:source|systemctl|systemd-run|sudo|apt|curl|wget)\b')

    def test_host_guards_reject_accidental_real_operations(self):
        for operation in (lambda: Path('/proc/1/comm').read_text(),
                          lambda: Path('/run/fixture-forbidden').mkdir(),
                          lambda: subprocess.run(['fixture-forbidden']),
                          lambda: socket.socket(), lambda: pwd.getpwnam('haproxy'),
                          lambda: grp.getgrnam('haproxy'), lambda: tempfile.mkdtemp()):
            with self.assertRaisesRegex(AssertionError, 'Real host operation forbidden'):
                operation()

    def test_main_invalid_arguments_never_construct_controller(self):
        with patch.object(self.D, 'Controller') as factory, patch.object(sys, 'stderr', io.StringIO()):
            for args in ([], ['--help'], ['--run', 'extra'], ['--trace']):
                self.assertEqual(self.D.main(args), 64)
        factory.assert_not_called()

    def test_rooted_run_on_unsupported_host_stops_before_proc_or_commands(self):
        # Real main + real prepare, fake root identities and unsupported arch.
        c = self.D.Controller()
        c.command = Mock(side_effect=AssertionError('No command before host validation'))
        with ExitStack() as stack:
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            stack.enter_context(patch.object(platform, 'machine', return_value='aarch64'))
            rc, out, err = self.main_with(c)
        self.assertEqual(rc, 2)
        self.assertIn('unsupported: root-Ubuntu-24.04-amd64-required', out)
        self.assertEqual(err, '')
        self.assertIsNone(c.directory)
        c.command.assert_not_called()

    def test_non_systemd_pid1_is_inspected_only_through_mock(self):
        c = self.D.Controller()
        with ExitStack() as stack:
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            stack.enter_context(patch.object(platform, 'machine', return_value='x86_64'))
            read = stack.enter_context(patch.object(Path, 'read_text', return_value='not-systemd\n'))
            with self.assertRaisesRegex(self.D.Unsupported, 'systemd-PID1-required'):
                c.prepare()
        read.assert_called_once_with()
        self.assertIsNone(c.directory)

    def test_root_systemd_but_unsupported_os_stops_before_tempwork(self):
        c = self.D.Controller()
        c.command = Mock()
        with ExitStack() as stack:
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            stack.enter_context(patch.object(platform, 'machine', return_value='x86_64'))
            stack.enter_context(patch.object(Path, 'read_text', return_value='systemd\n'))
            read = stack.enter_context(patch.object(self.D, '_read_private_source',
                                                    return_value=(b'ID=ubuntu\nVERSION_ID=22.04\n', {})))
            with self.assertRaisesRegex(self.D.Unsupported, 'Ubuntu-24.04-required'):
                c.prepare()
        read.assert_called_once_with('/usr/lib/os-release', 65536)
        self.assertIsNone(c.directory)
        c.command.assert_not_called()


class OptionalLoggingContracts(Offline):
    FILE_KEYS = ('StandardOutputFile', 'StandardErrorFile')
    OMISSIONS = ((), ('StandardOutputFile',), ('StandardErrorFile',),
                 ('StandardOutputFile', 'StandardErrorFile'))

    @staticmethod
    def omit(properties, keys):
        result = dict(properties)
        for key in keys:
            result.pop(key, None)
        return result

    def test_file_metadata_is_exactly_two_optional_names(self):
        self.assertEqual(self.D.OPTIONAL_LOG_PROPERTIES, frozenset(self.FILE_KEYS))
        for omitted in self.OMISSIONS:
            left = source_properties()
            right = self.omit(left, omitted)
            self.assertEqual(self.D.restriction_differences(left, right), [])
            self.assertEqual(self.D.restriction_differences(right, left), [])
        for key in ('StandardOutput', 'StandardError', 'NoNewPrivileges',
                    'CapabilityBoundingSet', 'SystemCallFilter', 'FutureSecurityKnob'):
            left = dict(source_properties(), **{key: 'required'})
            right = dict(left)
            del right[key]
            with self.subTest(property=key):
                self.assertEqual(self.D.restriction_differences(left, right), [key])
                self.assertEqual(self.D.restriction_differences(right, left), [key])

    def test_successful_show_omission_is_absence_not_empty_or_read_failure(self):
        c = self.controller(True)
        original = self.omit(source_properties(True), self.FILE_KEYS)
        raw = ''.join(key + '=' + value + '\n' for key, value in original.items()).encode()
        c.command = Mock(return_value=(0, raw, b''))
        result = c.show(MAIN)
        self.assertEqual(result, original)
        for key in self.FILE_KEYS:
            self.assertNotIn(key, result)
        self.assertEqual(self.D.validate_effective(result, c.fragment), CAPS3)
        c.command.assert_called_once()

    def test_nonzero_and_timeout_show_are_not_hidden_by_optional_metadata(self):
        c = self.controller()
        original = self.omit(source_properties(), self.FILE_KEYS)
        raw = ''.join(key + '=' + value + '\n' for key, value in original.items()).encode()
        for code in (1, None):
            c.command = Mock(return_value=(code, raw, b'PRIVATE_FIXTURE_VALUE'))
            with self.subTest(code=code), self.assertRaises(self.D.Unsupported):
                c.show(MAIN)
            c.command.assert_called_once()

    def test_production_path_metadata_is_not_needed_or_reused(self):
        c = self.controller()
        alternate = rendered().replace('append:/opt/nathaya/logs/%N.log',
                                        'append:/different/production/log')
        self.D.validate_fragment(alternate)
        for mode in ('journal', 'inherit', 'append:'):
            with self.subTest(mode=mode), self.assertRaises(self.D.Unsupported):
                self.D.validate_fragment(rendered().replace('append:/opt/nathaya/logs/%N.log', mode))
        for key in self.FILE_KEYS:
            c.source[key] = 'PRIVATE_PRODUCTION_PATH_NOT_NEEDED'
        self.assertEqual(self.D.validate_effective(c.source, c.fragment), CAPS4)
        for phase in ('plain', 'trace'):
            plan = self.plan(c, phase)
            destination = str(c.directory / phase / 'combined.log')
            for key in ('StandardOutput', 'StandardError'):
                self.assertEqual(plan['properties'][key], 'append:' + destination)
                self.assertEqual([a for a in plan['command'] if a.startswith('--property=' + key + '=')],
                                 ['--property=' + key + '=append:' + destination])
            self.assertFalse(any('PRIVATE_PRODUCTION_PATH' in arg for arg in plan['command']))

    def test_full_gate_accepts_each_absence_and_available_path_combination(self):
        for old in (True, False):
            for absent_source in self.OMISSIONS:
                for absent_probe in self.OMISSIONS:
                    with self.subTest(old=old, source=absent_source, probe=absent_probe):
                        c = self.controller(old)
                        c.source = self.omit(c.source, absent_source)
                        plan = self.plan(c)
                        probe = self.omit(self.probe(c, plan), absent_probe)
                        c.save.reset_mock()
                        self.gate(c, plan, probe=probe)
                        c.save.assert_called_once_with('plain/go', b'')
                        evidence = next(call.args[1] for call in c.record.call_args_list
                                        if call.args[0] == 'plain/logging-metadata.json')
                        self.assertEqual(evidence['source_file_properties_available'],
                                         {k: k not in absent_source for k in self.FILE_KEYS})
                        self.assertEqual(evidence['probe_file_properties_available'],
                                         {k: k not in absent_probe for k in self.FILE_KEYS})
                        self.assertEqual(evidence['probe_destination'], str(plan['output']))
                        self.assertEqual(evidence['destination_basis'], 'explicit-private-transient-assignments')

    def test_available_probe_file_must_match_private_path_and_not_empty(self):
        c = self.controller()
        plan = self.plan(c)
        probe = self.probe(c, plan)
        c.validate_probe(probe, plan)
        for key in self.FILE_KEYS:
            for value in ('', '/opt/nathaya/logs/nathaya-haproxy.log',
                          '/run/nathaya-haproxy-probe.other/plain/combined.log'):
                bad = dict(probe, **{key: value})
                with self.subTest(property=key, value=value), self.assertRaises(self.D.Unsupported):
                    c.validate_probe(bad, plan)
        c.validate_probe(self.omit(probe, self.FILE_KEYS), plan)

    def test_missing_file_properties_never_make_output_modes_optional(self):
        c = self.controller()
        plan = self.plan(c)
        for key in ('StandardOutput', 'StandardError'):
            for value in (None, '', 'inherit', 'journal'):
                source = self.omit(c.source, self.FILE_KEYS)
                probe = self.omit(self.probe(c, plan), self.FILE_KEYS)
                if value is None:
                    del source[key]
                    del probe[key]
                else:
                    source[key] = probe[key] = value
                with self.subTest(property=key, value=value):
                    with self.assertRaises(self.D.Unsupported):
                        self.D.validate_effective(source, c.fragment)
                    with self.assertRaises(self.D.Unsupported):
                        c.validate_probe(probe, plan)

    def test_private_destination_requires_both_explicit_assignments_exactly_once(self):
        c = self.controller()
        good = self.plan(c)
        probe = self.omit(self.probe(c, good), self.FILE_KEYS)
        c.validate_probe(probe, good)
        for key in ('StandardOutput', 'StandardError'):
            prefix = '--property=' + key + '='
            for variant in ('dict', 'cli', 'missing', 'duplicate'):
                plan = copy.deepcopy(good)
                production = 'append:/opt/nathaya/logs/nathaya-haproxy.log'
                if variant == 'dict':
                    plan['properties'][key] = production
                elif variant == 'cli':
                    plan['command'] = [prefix + production if a.startswith(prefix) else a
                                       for a in plan['command']]
                elif variant == 'missing':
                    plan['command'] = [a for a in plan['command'] if not a.startswith(prefix)]
                else:
                    plan['command'].append(prefix + production)
                with self.subTest(property=key, variant=variant), self.assertRaises(self.D.Unsupported):
                    c.validate_probe(probe, plan)
        plan = copy.deepcopy(good)
        plan['output'] = Path('/opt/nathaya/logs/nathaya-haproxy.log')
        with self.assertRaises(self.D.Unsupported):
            c.validate_probe(probe, plan)

    def test_second_snapshot_available_production_path_blocks_gate(self):
        c = self.controller(True)
        plan = self.plan(c)
        initial = self.omit(self.probe(c, plan), self.FILE_KEYS)
        live = dict(initial, StandardErrorFile='/opt/nathaya/logs/nathaya-haproxy.log')
        c.save.reset_mock()
        with self.assertRaises(self.D.Unsupported):
            self.gate(c, plan, probe=initial, live=live)
        c.save.assert_not_called()


class EmptyExecHookContracts(Offline):
    SOURCE_HOOKS = ('ExecStartPre', 'ExecStartPost', 'ExecCondition',
                    'ExecStop', 'ExecStopPost')
    PROBE_HOOKS = ('ExecReload', 'ExecStartPost', 'ExecCondition',
                   'ExecStop', 'ExecStopPost')

    @staticmethod
    def fields(hooks):
        return tuple(name + suffix for name in hooks for suffix in ('', 'Ex'))

    @staticmethod
    def representation(properties, fields, absent):
        result = dict(properties)
        result.update(dict.fromkeys(fields, ''))
        for key in absent:
            result.pop(key, None)
        return result

    def refuse_at_either_snapshot(self, c, plan, bad, reason):
        good = self.probe(c, plan)
        for snapshot in ('first', 'live'):
            c.save.reset_mock()
            with self.subTest(snapshot=snapshot), self.assertRaisesRegex(self.D.Unsupported, reason):
                self.gate(c, plan, probe=bad if snapshot == 'first' else good,
                          live=bad if snapshot == 'live' else good)
            c.save.assert_not_called()

    def test_source_all_absent_empty_permutations_and_individual_omissions(self):
        fields = self.fields(self.SOURCE_HOOKS)
        self.assertEqual(self.D.SOURCE_EMPTY_EXEC_HOOKS, self.SOURCE_HOOKS)
        self.assertEqual(self.D.PROBE_EMPTY_EXEC_HOOKS, self.PROBE_HOOKS)
        self.assertEqual(self.D.EMPTY_EXEC_FIELDS,
                         frozenset(fields + self.fields(self.PROBE_HOOKS)))
        for old, caps in ((True, CAPS3), (False, CAPS4)):
            fragment = self.D.validate_fragment(rendered(old))
            # Every Base/Ex availability combination, including exactly one
            # omission, all absent, and all explicitly empty.
            for mask in range(1 << len(fields)):
                absent = [key for bit, key in enumerate(fields) if mask & (1 << bit)]
                props = self.representation(source_properties(old), fields, absent)
                with self.subTest(old=old, absent=absent):
                    self.assertEqual(self.D._source_empty_exec_fields(props, fragment), frozenset(fields))
                    self.assertEqual(self.D.validate_effective(props, fragment), caps)
                    self.assertEqual(set(props) & set(fields), set(fields) - set(absent))

    def test_effective_unused_nonempty_base_and_ex_only_rejected(self):
        fields = self.fields(self.SOURCE_HOOKS)
        for key in fields:
            for others_absent in (False, True):
                for value in ('unexpected', exec_property(['/bin/true'])):
                    props = self.representation(source_properties(), fields,
                                                fields if others_absent else ())
                    props[key] = value
                    with self.subTest(key=key, ex_only=others_absent, value=value):
                        fragment = self.D.validate_fragment(rendered())
                        with self.assertRaisesRegex(self.D.Unsupported, 'active-hook:' + key):
                            self.D._source_empty_exec_fields(props, fragment)
                        with self.assertRaisesRegex(self.D.Unsupported, 'active-hook:' + key):
                            self.D.validate_effective(props, fragment)

    def test_source_fragment_declarations_partial_and_untrusted_properties_rejected(self):
        props = self.representation(source_properties(), self.fields(self.SOURCE_HOOKS),
                                    self.fields(self.SOURCE_HOOKS))
        fragment = self.D.validate_fragment(rendered())
        for key in self.fields(self.SOURCE_HOOKS):
            for value in ('', '/bin/true'):
                raw = rendered().replace('[Service]\n', '[Service]\n' + key + '=' + value + '\n')
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(self.D.Unsupported, 'fragment-directive'):
                        self.D.validate_fragment(raw)
                    # A caller cannot bypass the raw validator with a mapping
                    # that declares a reset, even when show omits that hook.
                    with self.assertRaisesRegex(self.D.Unsupported, 'source-hook-defined-in-fragment:' + key):
                        self.D._source_empty_exec_fields(props, dict(fragment, **{key: value}))
        for bad in (None, {}, {k: v for k, v in fragment.items() if k != 'ExecReload'},
                    dict(fragment, FutureDirective='no'), dict(fragment, User='haproxy'),
                    dict(fragment, ExecStart='/bin/true'), dict(fragment, ExecReload=None)):
            with self.subTest(fragment=type(bad).__name__), self.assertRaisesRegex(
                    self.D.Unsupported, 'source-hook-fragment-uncertain'):
                self.D._source_empty_exec_fields(props, bad)
        for key, wrong in (('Id', 'foreign.service'), ('LoadState', 'not-found'),
                           ('FragmentPath', '/tmp/foreign.service'), ('DropInPaths', '/tmp/drop.conf'),
                           ('NeedDaemonReload', 'yes')):
            for value in (None, wrong):
                bad = dict(props, **{key: value})
                with self.subTest(key=key, value=value), self.assertRaisesRegex(self.D.Unsupported, key):
                    self.D._source_empty_exec_fields(bad, fragment)
            bad = dict(props)
            del bad[key]
            with self.subTest(missing=key), self.assertRaisesRegex(self.D.Unsupported, key):
                self.D._source_empty_exec_fields(bad, fragment)
        with self.assertRaisesRegex(self.D.Unsupported, 'CapabilityBoundingSet'):
            self.D.validate_effective(props, self.D.validate_fragment(rendered(True)))

    def test_source_start_and_reload_base_mandatory_and_available_ex_exact(self):
        fields = self.fields(self.SOURCE_HOOKS)
        for old, caps in ((True, CAPS3), (False, CAPS4)):
            fragment = self.D.validate_fragment(rendered(old))
            good = self.representation(source_properties(old), fields, fields)
            for key in ('ExecStart', 'ExecReload'):
                good[key + 'Ex'] = good[key]
            self.assertEqual(self.D.validate_effective(good, fragment), caps)
            for key in ('ExecStart', 'ExecReload'):
                for value in (None, '', exec_property(['/bin/true']),
                              good[key] + ' ' + exec_property(['/bin/true'])):
                    for target in (key, key + 'Ex'):
                        bad = dict(good)
                        if value is None:
                            del bad[target]
                        else:
                            bad[target] = value
                        with self.subTest(old=old, target=target, value=value):
                            if target.endswith('Ex') and value is None:
                                self.assertEqual(self.D.validate_effective(bad, fragment), caps)
                            else:
                                with self.assertRaisesRegex(self.D.Unsupported, target):
                                    self.D.validate_effective(bad, fragment)

    def test_probe_pre_base_and_available_ex_checked_at_both_snapshots(self):
        for phase in ('plain', 'trace'):
            c = self.controller()
            plan = self.plan(c, phase)
            fields = self.fields(self.PROBE_HOOKS)
            good = self.representation(self.probe(c, plan), fields, fields)
            # Pre Ex is optional, not an alternative to the mandatory Base.
            c.validate_probe(good, plan)
            for key, argv in (('ExecStart', plan['argv']), ('ExecStartPre', plan['pre'])):
                alias = dict(good, **{key + 'Ex': exec_property(argv)})
                c.validate_probe(alias, plan)
                for target in (key, key + 'Ex'):
                    values = ('', exec_property(['/bin/true']),
                              exec_property(argv + ['--unexpected-fixture']),
                              exec_property(argv) + ' ' + exec_property(['/bin/true']))
                    if target == key:
                        values = (None,) + values
                    for value in values:
                        bad = dict(alias)
                        if value is None:
                            del bad[target]
                        else:
                            bad[target] = value
                        with self.subTest(phase=phase, target=target, value=value):
                            with self.assertRaisesRegex(self.D.Unsupported, target):
                                c.validate_probe(bad, plan)
                            self.refuse_at_either_snapshot(c, plan, bad, target)

    def test_probe_unused_absent_empty_permutations_require_owned_no_declaration_plan(self):
        c = self.controller()
        plan = self.plan(c)
        fields = self.fields(self.PROBE_HOOKS)
        for mask in range(1 << len(fields)):
            absent = [key for bit, key in enumerate(fields) if mask & (1 << bit)]
            props = self.representation(self.probe(c, plan), fields, absent)
            with self.subTest(absent=absent):
                self.assertEqual(c.empty_probe_exec_fields(props, plan), frozenset(fields))
                c.validate_probe(props, plan)
        good = self.probe(c, plan)
        for key, value in (('Id', MAIN), ('Transient', 'no'), ('Description', 'foreign'),
                           ('ControlGroup', '/system.slice/foreign.service'), ('FragmentPath', FRAGMENT),
                           ('LoadState', 'not-found'), ('DropInPaths', None),
                           ('DropInPaths', '/tmp/drop.conf'), ('NeedDaemonReload', 'yes')):
            with self.subTest(key=key, value=value), self.assertRaises(self.D.Unsupported):
                c.empty_probe_exec_fields(dict(good, **{key: value}), plan)
        for key in ('DropInPaths', 'LoadState', 'NeedDaemonReload'):
            bad = dict(good)
            del bad[key]
            with self.assertRaisesRegex(self.D.Unsupported, key):
                c.empty_probe_exec_fields(bad, plan)
        # The fixture must not invent unavailable active aliases, nor copy the
        # source's active Reload Ex or empty Pre Ex into the transient snapshot.
        self.assertFalse(any(key + 'Ex' in good for key in ('ExecStart', 'ExecStartPre', 'ExecReload')))
        for phase in ('plain', 'trace'):
            for key in ('ExecStart', 'ExecReload'):
                c.source[key + 'Ex'] = c.source[key]
            c.source['ExecStartPreEx'] = ''
            augmented = self.plan(c, phase)
            probe = self.probe(c, augmented)
            self.assertEqual(probe['ExecStartEx'], exec_property(augmented['argv']))
            self.assertEqual(probe['ExecStartPreEx'], exec_property(augmented['pre']))
            self.assertEqual(probe['ExecReloadEx'], '')
            c.validate_probe(probe, augmented)

    def test_probe_unused_active_base_or_ex_only_never_releases(self):
        c = self.controller()
        plan = self.plan(c)
        fields = self.fields(self.PROBE_HOOKS)
        for key in fields:
            for others_absent in (False, True):
                bad = self.representation(self.probe(c, plan), fields,
                                          fields if others_absent else ())
                bad[key] = exec_property(['/bin/true'])
                with self.subTest(key=key, ex_only=others_absent):
                    with self.assertRaisesRegex(self.D.Unsupported, 'active-hook:' + key):
                        c.empty_probe_exec_fields(bad, plan)
                    self.refuse_at_either_snapshot(c, plan, bad, 'active-hook:' + key)

    def test_probe_unused_plan_mapping_and_all_cli_declaration_forms_rejected(self):
        c = self.controller()
        good = self.plan(c)
        fields = self.fields(self.PROBE_HOOKS)
        probe = self.representation(self.probe(c, good), fields, fields)
        for key in fields:
            for value in ('', '/bin/true'):
                assignment = key + '=' + value
                variants = (None, ['--property=' + assignment], ['--property', assignment],
                            ['-p', assignment], ['-p' + assignment])
                for args in variants:
                    plan = copy.deepcopy(good)
                    if args is None:
                        plan['properties'][key] = value
                    else:
                        boundary = plan['command'].index('--')
                        plan['command'][boundary:boundary] = args
                    with self.subTest(key=key, value=value, args=args):
                        with self.assertRaisesRegex(self.D.Unsupported, 'probe-hook-declared:' + key):
                            c.empty_probe_exec_fields(probe, plan)
                        self.refuse_at_either_snapshot(c, plan, probe, 'probe-hook-declared:' + key)

    def test_comparator_strict_defaults_scoped_proofs_and_no_security_exemptions(self):
        c = self.controller()
        source_fields = self.fields(self.SOURCE_HOOKS)
        probe_fields = self.fields(self.PROBE_HOOKS)
        full = self.representation(c.source, source_fields, ())
        absent = self.representation(full, source_fields, source_fields)
        full_proof = self.D._source_empty_exec_fields(full, c.fragment)
        absent_proof = self.D._source_empty_exec_fields(absent, c.fragment)
        for left, right, lp, rp in ((full, absent, full_proof, absent_proof),
                                    (absent, full, absent_proof, full_proof)):
            self.assertEqual(self.D.restriction_differences(left, right), sorted(source_fields))
            self.assertEqual(self.D.restriction_differences(
                left, right, checked_empty_source=lp, checked_empty_probe=rp), [])
        c.source = full
        plan = self.plan(c)
        probe = self.representation(self.probe(c, plan), probe_fields, probe_fields)
        live = self.representation(probe, probe_fields, ())
        c.validate_probe(probe, plan)
        c.validate_probe(live, plan)
        pp = c.empty_probe_exec_fields(probe, plan)
        pl = c.empty_probe_exec_fields(live, plan)
        self.assertEqual(self.D.restriction_differences(probe, live), sorted(probe_fields))
        self.assertEqual(self.D.restriction_differences(
            probe, live, checked_empty_source=pp, checked_empty_probe=pl), [])
        # Validate active argv first, then allow source Pre empty/absent ->
        # probe active and source Reload active -> probe empty/absent.
        for source in (full, absent):
            self.D.validate_effective(source, c.fragment)
            sp = self.D._source_empty_exec_fields(source, c.fragment)
            for target, tp in ((probe, pp), (live, pl)):
                self.assertEqual(self.D.restriction_differences(
                    source, target, checked_empty_source=sp, checked_empty_probe=tp), [])
        for key in ('User', 'SystemCallFilter', 'NoNewPrivileges', 'FutureSecurityKnob', 'ExecFutureHook'):
            left = dict(absent, **{key: 'required'})
            for right in (dict(left, **{key: 'changed'}), {k: v for k, v in left.items() if k != key}):
                with self.subTest(key=key):
                    self.assertEqual(self.D.restriction_differences(
                        left, right, checked_empty_source=absent_proof,
                        checked_empty_probe=absent_proof), [key])
            with self.assertRaisesRegex(self.D.Unsupported, 'empty-hook-proof-scope'):
                self.D._checked_empty_exec_fields({}, (key,))
        for key in self.D.EMPTY_EXEC_FIELDS:
            for side in ('source', 'probe'):
                active = {key: exec_property(['/bin/true'])}
                kwargs = {'checked_empty_' + side: (key,)}
                with self.subTest(key=key, side=side), self.assertRaisesRegex(
                        self.D.Unsupported, 'active-hook:' + key):
                    self.D.restriction_differences(active if side == 'source' else {},
                                                  active if side == 'probe' else {}, **kwargs)
        for fields in (None, ('ExecStart',), ('ExecStartEx',), ('FutureSecurityKnob',)):
            with self.assertRaisesRegex(self.D.Unsupported, 'empty-hook-proof-scope'):
                self.D._checked_empty_exec_fields({}, fields)

    def test_full_gate_source_current_and_probe_live_omissions_caps_phases_and_private_logs(self):
        sf, pf = self.fields(self.SOURCE_HOOKS), self.fields(self.PROBE_HOOKS)
        for old in (True, False):
            for phase in ('plain', 'trace'):
                for scope, fields in (('source-current', sf), ('probe-live', pf)):
                    # Both directions plus each individual Base/Ex omission.
                    cases = [((), fields), (fields, ())] + [((), (key,)) for key in fields]
                    cases += [((key,), ()) for key in fields]
                    for first_absent, second_absent in cases:
                        with self.subTest(old=old, phase=phase, scope=scope,
                                          first=first_absent, second=second_absent):
                            c = self.controller(old)
                            c.source['ExecStartEx'] = c.source['ExecStart']
                            c.source['ExecReloadEx'] = c.source['ExecReload']
                            c.source = self.representation(c.source, sf,
                                                           first_absent if scope == 'source-current' else sf)
                            # Optional logging metadata remains independently
                            # unavailable; no production destination is copied.
                            for key in OptionalLoggingContracts.FILE_KEYS:
                                c.source.pop(key, None)
                            plan = self.plan(c, phase)
                            current = self.representation(c.source, sf,
                                                         second_absent if scope == 'source-current' else ())
                            probe = self.representation(self.probe(c, plan), pf,
                                                       first_absent if scope == 'probe-live' else pf)
                            live = self.representation(probe, pf,
                                                      second_absent if scope == 'probe-live' else ())
                            for key in OptionalLoggingContracts.FILE_KEYS:
                                probe.pop(key, None)
                                live.pop(key, None)
                            self.assertEqual(c.caps, CAPS3 if old else CAPS4)
                            self.assertEqual((probe['User'], probe['Group']), ('root', 'root'))
                            self.assertEqual(plan['properties']['ReadWritePaths'], '/opt/nathaya/logs')
                            destination = str(c.directory / phase / 'combined.log')
                            for key in ('StandardOutput', 'StandardError'):
                                self.assertEqual(plan['properties'][key], 'append:' + destination)
                            self.assertFalse(any('/opt/nathaya/logs/nathaya-haproxy.log' in arg
                                                 for arg in plan['command']))
                            c.save.reset_mock()
                            self.gate(c, plan, probe=probe, current=current, live=live)
                            c.save.assert_called_once_with(phase + '/go', b'')
                            evidence = next(call.args[1] for call in c.record.call_args_list
                                            if call.args[0] == phase + '/comparison.json')
                            self.assertEqual(evidence['unsupported'], [])
                            self.assertEqual(evidence['validated_empty_exec']['source'], sorted(sf))
                            self.assertEqual(evidence['validated_empty_exec']['probe'], sorted(pf))
                            self.assertEqual(evidence['validated_empty_exec']['source_absent'],
                                             sorted(set(sf) - set(current)))
                            self.assertEqual(evidence['validated_empty_exec']['probe_absent'],
                                             sorted(set(pf) - set(probe)))
                            logging = next(call.args[1] for call in c.record.call_args_list
                                           if call.args[0] == phase + '/logging-metadata.json')
                            self.assertFalse(any(logging['source_file_properties_available'].values()))
                            self.assertFalse(any(logging['probe_file_properties_available'].values()))
                            self.assertEqual(logging['probe_destination'], destination)

    def test_failed_or_timed_out_show_with_valid_omitted_body_never_falls_back(self):
        c = self.controller()
        fields = self.fields(self.SOURCE_HOOKS)
        props = self.representation(c.source, fields, fields)
        self.assertEqual(self.D.validate_effective(props, c.fragment), CAPS4)
        raw = ''.join(key + '=' + value + '\n' for key, value in props.items()).encode()
        c.command = Mock(return_value=(0, raw, b''))
        self.assertEqual(c.show(MAIN), props)
        for code in (1, None):
            c.command = Mock(return_value=(code, raw, b'PRIVATE_FIXTURE_VALUE'))
            with self.subTest(code=code), self.assertRaises(self.D.Unsupported):
                c.show(MAIN)
            c.command.assert_called_once_with(
                ['/usr/bin/systemctl', 'show', '--all', '--no-pager', MAIN], timeout=3)

    def test_source_cannot_prove_fragment_none_never_releases(self):
        for phase in ('plain', 'trace'):
            c = self.controller()
            plan = self.plan(c, phase)
            fields = self.fields(self.SOURCE_HOOKS)
            c.source = self.representation(c.source, fields, fields)
            # Even a valid CURRENT read cannot retroactively prove the saved
            # source snapshot when its verified fragment evidence is missing.
            c.fragment = None
            with self.assertRaisesRegex(self.D.Unsupported, 'source-hook-fragment-uncertain'):
                self.D.validate_effective(c.source, c.fragment)
            c.save.reset_mock()
            with self.assertRaisesRegex(self.D.Unsupported, 'source-hook-fragment-uncertain'):
                self.gate(c, plan)
            c.save.assert_not_called()


class Systemd255SnapshotContracts(Offline):
    """Supplied-property contracts only; no claim of an actual VPS snapshot pair."""

    @staticmethod
    def overlay(base, description):
        result = dict(base)
        result.update(description['set'])
        for key in description['omit']:
            result.pop(key, None)
        return result

    def fixture_pair(self):
        fixture = copy.deepcopy(SYNTHETIC_PAIR)
        c = self.controller(fixture['old'])
        c.source = self.overlay(c.source, fixture['source'])
        plan = self.plan(c, fixture['phase'])
        probe = self.overlay(self.probe(c, plan), fixture['probe'])
        return c, plan, probe

    def artifact(self, c, name):
        matches = [call.args[1] for call in c.record.call_args_list if call.args[0] == name]
        self.assertEqual(len(matches), 1, 'Exactly one aggregate per inspection stage')
        return matches[0]

    def assert_names(self, labels, names):
        text = ';'.join(labels)
        for name in names:
            self.assertIn(name, text)

    def test_missing_snapshots_require_pair_unless_explicit_source_only_preflight(self):
        c, plan, probe = self.fixture_pair()
        c.save.reset_mock()
        for source, candidate, missing in (
                (None, probe, ('source-snapshot-unavailable',)),
                (c.source, None, ('probe-snapshot-unavailable',)),
                (None, None, ('source-snapshot-unavailable', 'probe-snapshot-unavailable',
                              'snapshots-unavailable'))):
            with self.subTest(missing=missing):
                audit = c.audit_compatibility(source, candidate, fragment=c.fragment, plan=plan)
                self.assertFalse(audit['ok'])
                self.assertFalse(audit['complete'])
                self.assertFalse(audit['snapshot_pair_supplied'])
                self.assertEqual(audit['scope'], 'pair-required')
                self.assertTrue(set(missing) <= set(audit['issues']))
        preflight = c.audit_compatibility(c.source, fragment=c.fragment, allow_source_only=True)
        self.assertTrue(preflight['ok'])
        self.assertEqual(preflight['issues'], [])
        self.assertEqual(preflight['scope'], 'source-only-preflight')
        self.assertFalse(preflight['complete'])
        self.assertFalse(preflight['snapshot_pair_supplied'])
        self.assertEqual(preflight['source_caps'], sorted(CAPS3))
        invalid = c.audit_compatibility(dict(c.source, NoNewPrivileges='no'),
                                        fragment=c.fragment, allow_source_only=True)
        self.assertFalse(invalid['ok'])
        self.assertFalse(invalid['complete'])
        self.assert_names(invalid['validation']['source'], ('NoNewPrivileges',))
        missing = c.audit_compatibility(fragment=c.fragment, allow_source_only=True)
        self.assertFalse(missing['ok'])
        self.assertFalse(missing['complete'])
        self.assertIn('source-snapshot-unavailable', missing['issues'])
        ambiguous = c.audit_compatibility(c.source, probe, fragment=c.fragment, plan=plan,
                                          allow_source_only=True)
        self.assertFalse(ambiguous['ok'])
        self.assertFalse(ambiguous['complete'])
        self.assertIn('ambiguous-audit-scope', ambiguous['issues'])
        c.save.assert_not_called()
        c.record.assert_not_called()

    def test_one_sided_runtime_mainpid_is_missing_not_ignored(self):
        c, plan, probe = self.fixture_pair()
        good = c.audit_compatibility(c.source, probe, fragment=c.fragment, plan=plan)
        self.assertTrue(good['ok'])
        self.assertIn('MainPID', good['ignored'])
        equal = dict(probe, MainPID=c.source['MainPID'])
        audit = c.audit_compatibility(c.source, equal, fragment=c.fragment, plan=plan)
        self.assertTrue(audit['ok'])
        self.assertNotIn('MainPID', audit['ignored'])
        for side in ('source', 'probe'):
            source, candidate = dict(c.source), dict(probe)
            target = source if side == 'source' else candidate
            del target['MainPID']
            with self.subTest(side=side):
                audit = c.audit_compatibility(source, candidate, fragment=c.fragment, plan=plan)
                row = next(row for row in audit['properties'] if row['property'] == 'MainPID')
                self.assertEqual(row['classification'], 'missing-' + side)
                self.assertEqual(row['reason'], 'missing-property-no-validated-equivalence')
                self.assertTrue(row['unsupported'])
                self.assertIn('MainPID', audit['unsupported'])
                self.assertNotIn('MainPID', audit['ignored'])
                self.assertFalse(audit['ok'])
                self.assertFalse(audit['complete'])

    def test_alternate_cli_logging_duplicates_aggregate_without_file_metadata_or_go(self):
        for form in ('--property', '-p', '-p-attached'):
            c = self.controller()
            plan = self.plan(c)
            probe = dict(self.probe(c, plan), NoNewPrivileges='no', WatchdogUSec='5s')
            for key in OptionalLoggingContracts.FILE_KEYS:
                del probe[key]
            for key in ('StandardOutput', 'StandardError'):
                self.assertEqual(probe[key], 'append')
                assignment = key + '=append:/opt/nathaya/logs/nathaya-haproxy.log'
                extra = ['-p' + assignment] if form == '-p-attached' else [form, assignment]
                boundary = plan['command'].index('--')
                plan['command'][boundary:boundary] = extra
            names = ('probe-output-plan:StandardOutput', 'probe-output-plan:StandardError',
                     'NoNewPrivileges', 'WatchdogUSec')
            with self.subTest(form=form):
                with self.assertRaises(self.D.Unsupported) as direct:
                    c.validate_probe(probe, plan)
                self.assert_names(direct.exception.labels, names)
                c.save.reset_mock()
                c.release_reservations = Mock()
                with self.assertRaises(self.D.Unsupported) as raised:
                    self.gate(c, plan, probe=probe)
                audit = self.artifact(c, 'plain/comparison.json')
                self.assertFalse(audit['ok'])
                self.assert_names(audit['validation']['probe'], names)
                self.assertEqual(raised.exception.labels, tuple(audit['issues']))
                c.release_reservations.assert_not_called()
                c.save.assert_not_called()

    def test_initial_lock_refusal_persists_independent_watchdog_and_security_errors(self):
        c = self.controller()
        plan = self.plan(c)
        plan['created_at'] = 0
        probe = dict(self.probe(c, plan), WatchdogUSec='5s', NoNewPrivileges='no',
                     FutureSecurityKnob='synthetic-change')
        c.save.reset_mock()
        c.release_reservations = Mock()
        label = 'fixture-setup-lock-present'
        with patch.object(c, 'show', side_effect=[probe, c.source]) as show, \
                patch.object(self.D, '_no_lock', side_effect=self.D.Unsupported(label)) as mock_no_lock, \
                patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})), \
                patch.object(time, 'monotonic', return_value=1), \
                self.assertRaises(self.D.Unsupported) as raised:
            c.gate(plan)
        audit = self.artifact(c, 'plain/comparison.json')
        self.assertFalse(audit['ok'])
        self.assertIn(label, audit['inspection_errors'])
        self.assert_names(audit['validation']['probe'], ('WatchdogUSec', 'NoNewPrivileges'))
        self.assert_names(audit['issues'], (label, 'WatchdogUSec', 'NoNewPrivileges', 'FutureSecurityKnob'))
        self.assertEqual(raised.exception.labels, tuple(audit['issues']))
        self.assertEqual(show.call_count, 2)
        mock_no_lock.assert_called_once_with()
        self.assertFalse(any(call.args[0] in ('plain/live-comparison.json', 'plain/release-audit.json')
                             for call in c.record.call_args_list))
        c.release_reservations.assert_not_called()
        c.save.assert_not_called()

    def test_late_lock_refusals_persist_live_or_release_audit_without_go(self):
        for stage in ('live', 'release'):
            c = self.controller()
            plan = self.plan(c)
            plan['created_at'] = 0
            probe = self.probe(c, plan)
            live = (dict(probe, WatchdogUSec='5s', NoNewPrivileges='no')
                    if stage == 'live' else dict(probe))
            label = 'fixture-' + stage + '-setup-lock-present'
            refusals = [None, self.D.Unsupported(label)] if stage == 'live' else [
                None, None, self.D.Unsupported(label)]
            # Six clock reads reach the live audit; the seventh checks release.
            ticks = [1] * 6 + ([] if stage == 'live' else [3.4])
            c.save.reset_mock()
            c.release_reservations = Mock()
            with self.subTest(stage=stage):
                with patch.object(c, 'show', side_effect=[probe, c.source, live]) as show, \
                        patch.object(self.D, '_no_lock', side_effect=refusals) as mock_no_lock, \
                        patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})), \
                        patch.object(time, 'monotonic', side_effect=ticks) as clock, \
                        self.assertRaises(self.D.Unsupported) as raised:
                    c.gate(plan)
                self.assertTrue(self.artifact(c, 'plain/comparison.json')['ok'])
                live_audit = self.artifact(c, 'plain/live-comparison.json')
                if stage == 'live':
                    audit = live_audit
                    self.assertFalse(audit['ok'])
                    self.assertIn(label, audit['inspection_errors'])
                    self.assert_names(audit['validation']['probe'], ('WatchdogUSec', 'NoNewPrivileges'))
                    self.assertFalse(any(call.args[0] == 'plain/release-audit.json'
                                         for call in c.record.call_args_list))
                else:
                    self.assertTrue(live_audit['ok'])
                    audit = self.artifact(c, 'plain/release-audit.json')
                    self.assertFalse(audit['gate_released'])
                    self.assertEqual(audit['issues'], sorted([label, 'prestart-deadline']))
                self.assertIn(label, audit['issues'])
                self.assertEqual(raised.exception.labels, tuple(audit['issues']))
                self.assertEqual(show.call_count, 3)
                self.assertEqual(mock_no_lock.call_count, len(refusals))
                self.assertEqual(clock.call_count, len(ticks))
                c.release_reservations.assert_not_called()
                c.save.assert_not_called()

    def test_actual_three_lines_are_partial_and_actual_probe_remains_unknown(self):
        self.assertEqual(REPORTED_PARTIAL, 'WatchdogUSec=infinity\nWatchdogTimestamp=\n'
                         'WatchdogTimestampMonotonic=0\n')
        actual = SNAPSHOT_MANIFEST['actual']
        self.assertEqual(actual['coverage'], 'partial')
        self.assertFalse(actual['full_vps_snapshot_pair'])
        self.assertEqual(actual['probe_watchdog_value'], 'UNKNOWN')
        self.assertEqual(actual['cause'], 'UNKNOWN')
        c = self.controller()
        partial = self.D.parse_show(REPORTED_PARTIAL)
        self.assertEqual(set(partial), set(actual['source_keys']))
        with self.assertRaises(self.D.Unsupported):
            self.D.validate_effective(partial, c.fragment)
        audit = c.audit_compatibility(partial, fragment=c.fragment)
        self.assertFalse(audit['ok'])
        self.assertFalse(audit['complete'])
        self.assertFalse(audit['snapshot_pair_supplied'])
        self.assertEqual(audit['coverage'], 'partial')
        row = next(row for row in audit['properties'] if row['property'] == 'WatchdogUSec')
        self.assertFalse(row['probe_present'])
        self.assertIsNone(row['probe'])
        self.assertEqual(row['reason'], 'snapshot-not-supplied')
        self.assertEqual(row['probe_kind'], 'missing')  # API input absent, NOT actual VPS evidence.
        c.save.assert_not_called()
        c.record.assert_not_called()

    def test_synthetic_pair_audits_exactly_all_supplied_keys_not_a_full_host_dump(self):
        self.assertEqual(SYNTHETIC_PAIR['tag'], 'SYNTHETIC')
        self.assertEqual(SYNTHETIC_PAIR['all_fields'], 'SYNTHETIC')
        self.assertFalse(SNAPSHOT_MANIFEST['synthetic']['actual_host_dump'])
        self.assertEqual(SNAPSHOT_MANIFEST['synthetic']['tag'], 'SYNTHETIC')
        self.assertEqual(SYNTHETIC_PAIR['base_provenance']['source'], 'source_properties(old=True)')
        self.assertEqual(SYNTHETIC_PAIR['base_provenance']['probe'], 'Offline.probe(c, plan)')
        c, plan, probe = self.fixture_pair()
        before = copy.deepcopy((c.source, probe, plan))
        audit = c.audit_compatibility(c.source, probe, fragment=c.fragment, plan=plan)
        self.assertTrue(audit['ok'])
        self.assertTrue(audit['snapshot_pair_supplied'])
        self.assertEqual(audit['coverage'], 'supplied-properties-only')
        self.assertEqual(audit['issues'], [])
        self.assertEqual(audit['unsupported'], [])
        rows = audit['properties']
        self.assertEqual({row['property'] for row in rows}, set(c.source) | set(probe))
        self.assertEqual(len(rows), len(set(c.source) | set(probe)))
        self.assertEqual(audit['source_caps'], sorted(CAPS3))
        self.assertEqual(audit['hook_proof_valid'], {'source': True, 'probe': True})
        self.assertEqual((c.source, probe, plan), before)
        for key in self.D.OPTIONAL_LOG_PROPERTIES:
            self.assertNotIn(key, c.source)
            self.assertNotIn(key, probe)
        self.assertNotIn('ExecStartPre', c.source)
        self.assertNotIn('ExecReload', probe)
        self.assertIn('ExecStartPre', probe)
        c.save.reset_mock()
        self.gate(c, plan, probe=probe)
        c.save.assert_called_once_with('plain/go', b'')
        release = self.artifact(c, 'plain/release-audit.json')
        self.assertEqual(release['issues'], [])
        # This artifact precedes go creation; False is not a release failure.
        self.assertFalse(release['gate_released'])

    def test_only_zero_and_infinity_normalize_watchdog_disabled(self):
        for source in ('0', 'infinity'):
            self.assertEqual(self.D.watchdog_behavior(source), 'disabled')
            for probe in ('0', 'infinity'):
                self.assertEqual(self.D.restriction_differences(
                    {'WatchdogUSec': source}, {'WatchdogUSec': probe}), [])
        # SystemCallFilter remains a literal comparator, not watchdog normalization.
        self.assertEqual(self.D.restriction_differences(
            {'SystemCallFilter': '@mount'}, {'SystemCallFilter': '~'}), ['SystemCallFilter'])
        self.assertEqual(self.D.restriction_differences(
            {'SystemCallFilter': '@mount'}, {'SystemCallFilter': '@mount'}), [])

    def test_invalid_watchdog_including_equal_finite_values_never_passes(self):
        c = self.controller()
        plan = self.plan(c)
        for value in ('', '0us', '1us', '5s', '42', 'unknown', 'Infinity', ' 0',
                      None, 0, False, [], {}):
            with self.subTest(kind=type(value).__name__, value=value):
                with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
                    self.D.watchdog_behavior(value)
                source = dict(c.source, WatchdogUSec=value)
                probe = dict(self.probe(c, plan), WatchdogUSec=value)
                with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
                    self.D.validate_effective(source, c.fragment)
                with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
                    c.validate_probe(probe, plan)
                with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
                    self.D.restriction_differences(source, probe)
                audit = c.audit_compatibility(source, probe, fragment=c.fragment, plan=plan)
                self.assertFalse(audit['ok'])
                self.assert_names(audit['validation']['source'], ('WatchdogUSec',))
                self.assert_names(audit['validation']['probe'], ('WatchdogUSec',))
                self.assertIn('WatchdogUSec', audit['unsupported'])

    def test_watchdog_is_required_even_when_both_inventories_omit_it(self):
        c = self.controller()
        plan = self.plan(c)
        source, probe = dict(c.source), self.probe(c, plan)
        del source['WatchdogUSec']
        del probe['WatchdogUSec']
        self.assertNotIn('WatchdogUSec', set(source) | set(probe))
        with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
            self.D.validate_effective(source, c.fragment)
        with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
            c.validate_probe(probe, plan)
        audit = c.audit_compatibility(source, probe, fragment=c.fragment, plan=plan)
        self.assertFalse(audit['ok'])
        self.assert_names(audit['validation']['source'], ('WatchdogUSec',))
        self.assert_names(audit['validation']['probe'], ('WatchdogUSec',))
        self.assertFalse(any(row['property'] == 'WatchdogUSec' for row in audit['properties']))
        # A valid comparator inventory alone is never permission to execute.
        c.save.reset_mock()
        with self.assertRaisesRegex(self.D.Unsupported, 'WatchdogUSec'):
            self.gate(c, plan, current=source, probe=probe)
        c.save.assert_not_called()

    def test_factory_explicit_disabled_watchdog_preserves_root_caps_and_runtime(self):
        for old, caps in ((True, CAPS3), (False, CAPS4)):
            c = self.controller(old)
            before = copy.deepcopy((c.source, c.fragment, c.source_bytes, c.caps))
            for phase in ('plain', 'trace'):
                plan = self.plan(c, phase)
                self.assertEqual(plan['properties']['WatchdogSec'], '0')
                self.assertEqual([arg for arg in plan['command'] if arg.startswith('--property=Watchdog')],
                                 ['--property=WatchdogSec=0'])
                self.assertEqual((plan['properties']['User'], plan['properties']['Group']), ('root', 'root'))
                self.assertEqual(frozenset(plan['properties']['CapabilityBoundingSet'].split()), caps)
                self.assertEqual(plan['properties']['RuntimeMaxSec'], '8s')
                self.assertEqual(plan['properties']['ReadWritePaths'], '/opt/nathaya/logs')
                self.assertEqual(plan['properties']['StandardOutput'], 'append:' + str(plan['output']))
                self.assertEqual(plan['properties']['StandardError'], 'append:' + str(plan['output']))
            self.assertEqual((c.source, c.fragment, c.source_bytes, c.caps), before)
        for names in (self.D.RUNTIME_PROPERTIES, self.D.INTENDED_PROPERTIES,
                      self.D.OPTIONAL_LOG_PROPERTIES):
            self.assertNotIn('WatchdogUSec', names)

    def test_watchdog_plan_requires_dictionary_and_exactly_one_cli_assignment(self):
        c = self.controller()
        good = self.plan(c)
        probe = self.probe(c, good)
        for variant in ('dict-missing', 'dict-finite', 'cli-missing', 'cli-finite', 'duplicate', 'split'):
            plan = copy.deepcopy(good)
            if variant == 'dict-missing':
                del plan['properties']['WatchdogSec']
            elif variant == 'dict-finite':
                plan['properties']['WatchdogSec'] = '5s'
            elif variant == 'cli-missing':
                plan['command'].remove('--property=WatchdogSec=0')
            elif variant == 'cli-finite':
                index = plan['command'].index('--property=WatchdogSec=0')
                plan['command'][index] = '--property=WatchdogSec=5s'
            elif variant == 'duplicate':
                plan['command'].insert(plan['command'].index('--'), '--property=WatchdogSec=0')
            else:
                index = plan['command'].index('--property=WatchdogSec=0')
                plan['command'][index:index + 1] = ['-p', 'WatchdogSec=0']
            with self.subTest(variant=variant), self.assertRaisesRegex(
                    self.D.Unsupported, 'probe-watchdog-plan:WatchdogSec'):
                c.validate_probe(probe, plan)

    def test_watchdog_plan_must_not_accept_usec_alias_shadow_assignments(self):
        # Both the mapping and every supported property CLI spelling must
        # reject a WatchdogUSec alias shadowing the audited WatchdogSec=0.
        c = self.controller()
        good = self.plan(c)
        probe = self.probe(c, good)
        variants = (['--property=WatchdogUSec=5s'], ['--property', 'WatchdogUSec=5s'],
                    ['-p', 'WatchdogUSec=5s'], ['-pWatchdogUSec=5s'])
        for placement in ('dict', 'cli', 'both'):
            for args in variants:
                plan = copy.deepcopy(good)
                if placement in ('dict', 'both'):
                    plan['properties']['WatchdogUSec'] = '5s'
                if placement in ('cli', 'both'):
                    boundary = plan['command'].index('--')
                    plan['command'][boundary:boundary] = args
                with self.subTest(placement=placement, args=args), self.assertRaisesRegex(
                        self.D.Unsupported, 'probe-watchdog-plan:WatchdogUSec'):
                    c.validate_probe(probe, plan)

    def test_effective_disabled_spellings_validate_and_release_at_both_snapshots(self):
        for value in ('0', 'infinity'):
            c = self.controller(True)
            c.source['WatchdogUSec'] = value
            self.assertEqual(self.D.validate_effective(c.source, c.fragment), CAPS3)
            plan = self.plan(c)
            for effective in ('0', 'infinity'):
                probe = dict(self.probe(c, plan), WatchdogUSec=effective)
                live = dict(probe, WatchdogUSec='infinity' if effective == '0' else '0')
                c.validate_probe(probe, plan)
                c.save.reset_mock()
                self.gate(c, plan, probe=probe, live=live)
                c.save.assert_called_once_with('plain/go', b'')

    def test_detailed_watchdog_classification_uses_supplied_values_not_guesses(self):
        c = self.controller()
        plan = self.plan(c)
        cases = (
            ({}, {'WatchdogUSec': '0'}, 'missing-source', 'missing', 'zero', True),
            ({'WatchdogUSec': 'infinity'}, {}, 'missing-probe', 'infinity', 'missing', True),
            ({'WatchdogUSec': 'infinity'}, {'WatchdogUSec': '0'},
             'normalized-equal', 'infinity', 'zero', False),
            ({'WatchdogUSec': '0'}, {'WatchdogUSec': '5s'}, 'value-different', 'zero', 'finite', True),
            ({'WatchdogUSec': '5s'}, {'WatchdogUSec': '5s'}, 'unsupported-value', 'finite', 'finite', True),
            ({'WatchdogUSec': ''}, {'WatchdogUSec': '0'}, 'value-different', 'empty', 'zero', True),
            ({'WatchdogUSec': 'unexpected'}, {'WatchdogUSec': '0'},
             'value-different', 'unknown', 'zero', True),
            ({'WatchdogUSec': 0}, {'WatchdogUSec': '0'}, 'value-different', 'invalid-type', 'zero', True),
        )
        for left, right, classification, sk, pk, unsupported in cases:
            source, probe = dict(c.source), self.probe(c, plan)
            source.pop('WatchdogUSec')
            probe.pop('WatchdogUSec')
            source.update(left)
            probe.update(right)
            audit = c.audit_compatibility(source, probe, fragment=c.fragment, plan=plan)
            row = next(row for row in audit['properties'] if row['property'] == 'WatchdogUSec')
            with self.subTest(source_kind=sk, probe_kind=pk):
                self.assertEqual(row['classification'], classification)
                self.assertEqual((row['source_kind'], row['probe_kind']), (sk, pk))
                self.assertEqual((row['source_present'], row['probe_present']),
                                 ('WatchdogUSec' in left, 'WatchdogUSec' in right))
                self.assertEqual((row['source'], row['probe']), (left.get('WatchdogUSec'), right.get('WatchdogUSec')))
                self.assertEqual(row['unsupported'], unsupported)
                if classification == 'normalized-equal':
                    self.assertEqual((row['source_behavior'], row['probe_behavior']), ('disabled', 'disabled'))
                    self.assertFalse(row['raw_equal'])
                elif sk == pk == 'finite':
                    self.assertTrue(row['raw_equal'])
                    self.assertEqual(row['reason'], 'unsupported-normalization')

    def test_multi_mutations_persist_one_aggregate_before_first_or_live_refusal(self):
        names = ('NoNewPrivileges', 'SystemCallFilter', 'RootImage', 'FutureSecurityKnob',
                 'ExecStart', 'ExecStartPre', 'ExecStopEx', 'StandardOutput', 'WatchdogUSec')
        for stage in ('first', 'live'):
            c = self.controller(True)
            plan = self.plan(c)
            good = self.probe(c, plan)
            bad = dict(good, NoNewPrivileges='no', SystemCallFilter='@mount',
                       FutureSecurityKnob='synthetic-change', ExecStart='malformed',
                       ExecStartPre='malformed', ExecStopEx=exec_property(['/bin/true']),
                       StandardOutput='journal', WatchdogUSec='5s')
            del bad['RootImage']
            c.save.reset_mock()
            c.release_reservations = Mock()
            with self.subTest(stage=stage), self.assertRaises(self.D.Unsupported) as raised:
                self.gate(c, plan, probe=bad if stage == 'first' else good,
                          live=bad if stage == 'live' else good)
            name = 'plain/comparison.json' if stage == 'first' else 'plain/live-comparison.json'
            audit = self.artifact(c, name)
            self.assertFalse(audit['ok'])
            self.assert_names(audit['issues'], names)
            self.assert_names(audit['validation']['probe'],
                              ('NoNewPrivileges', 'SystemCallFilter', 'ExecStart', 'ExecStartPre',
                               'active-hook:ExecStopEx', 'StandardOutput', 'WatchdogUSec'))
            self.assertTrue(set(('FutureSecurityKnob', 'RootImage', 'WatchdogUSec')) <= set(audit['unsupported']))
            self.assertEqual(raised.exception.labels, tuple(audit['issues']))
            self.assertEqual(list(raised.exception.labels), sorted(set(raised.exception.labels)))
            c.release_reservations.assert_not_called()
            c.save.assert_not_called()
            if stage == 'first':
                self.assertFalse(any(call.args[0] == 'plain/live-comparison.json'
                                     for call in c.record.call_args_list))
            else:
                self.assertTrue(self.artifact(c, 'plain/comparison.json')['ok'])

    def test_default_validators_collect_independent_categories_without_early_exit(self):
        c = self.controller()
        plan = self.plan(c)
        source = dict(c.source, User='haproxy', Group='haproxy', CapabilityBoundingSet='bad',
                      RestrictAddressFamilies='AF_UNIX', SystemCallFilter='@mount',
                      ExecStart='malformed', ExecReloadEx='malformed',
                      ExecStopEx='active', WatchdogUSec='5s', StandardError='journal')
        with self.assertRaises(self.D.Unsupported) as raised:
            self.D.validate_effective(source, c.fragment)
        self.assert_names(raised.exception.labels, ('User', 'Group', 'CapabilityBoundingSet',
                          'RestrictAddressFamilies', 'SystemCallFilter', 'ExecStart', 'ExecReloadEx',
                          'active-hook:ExecStopEx', 'WatchdogUSec', 'StandardError'))
        probe = dict(self.probe(c, plan), User='haproxy', Group='haproxy', CapabilityBoundingSet='bad',
                     RestrictAddressFamilies='AF_UNIX', SystemCallFilter='@mount', ExecStart='malformed',
                     ExecStartPreEx='malformed', ExecStopEx='active', WatchdogUSec='5s', StandardError='journal')
        bad_plan = copy.deepcopy(plan)
        bad_plan['properties']['WatchdogSec'] = '5s'
        bad_plan['properties']['StandardOutput'] = 'journal'
        bad_plan['argv'] = ['/bin/true']
        bad_plan['pre'] = ['/bin/true']
        with self.assertRaises(self.D.Unsupported) as raised:
            c.validate_probe(probe, bad_plan)
        self.assert_names(raised.exception.labels, ('User', 'Group', 'CapabilityBoundingSet',
                          'RestrictAddressFamilies', 'SystemCallFilter', 'ExecStart', 'ExecStartPreEx',
                          'active-hook:ExecStopEx', 'WatchdogUSec', 'StandardError',
                          'probe-watchdog-plan', 'probe-output-plan:StandardOutput',
                          'probe-command-plan:ExecStart', 'probe-command-plan:ExecStartPre'))
        errors = []
        self.D.collect_unsupported(errors, self.D.watchdog_behavior, '5s')
        self.D.collect_unsupported(errors, self.D._require, source, {'User': 'root', 'Group': 'root'})
        self.D.collect_unsupported(errors, self.D._checked_empty_exec_fields, source, ('ExecStopEx',))
        self.assert_names(errors, ('WatchdogUSec', 'User', 'Group', 'active-hook:ExecStopEx'))
        left = {'WatchdogUSec': '5s', 'CapabilityBoundingSet': None, 'RestrictAddressFamilies': None}
        right = dict(left)
        with self.assertRaises(self.D.Unsupported) as raised:
            self.D.restriction_differences(left, right)
        self.assertEqual(set(raised.exception.labels),
                         {'WatchdogUSec', 'CapabilityBoundingSet', 'RestrictAddressFamilies'})

    def test_invalid_current_source_cannot_hide_probe_diff_or_original_issues(self):
        c = self.controller()
        plan = self.plan(c)
        current = dict(c.source, NoNewPrivileges='no', ExecReload='malformed', WatchdogUSec='5s')
        original = dict(c.source, ExecStart='malformed')
        probe = dict(self.probe(c, plan), ProtectSystem='no', StandardError='journal',
                     ExecStartPre='malformed', FutureSecurityKnob='synthetic-change')
        del probe['RootImage']
        audit = c.audit_compatibility(current, probe, fragment=c.fragment, plan=plan,
                                      original=original, original_fragment=c.fragment,
                                      original_bytes=c.source_bytes, current_bytes=c.source_bytes)
        self.assert_names(audit['validation']['source'], ('NoNewPrivileges', 'ExecReload', 'WatchdogUSec'))
        self.assert_names(audit['validation']['probe'], ('ProtectSystem', 'StandardError', 'ExecStartPre'))
        self.assert_names(audit['validation']['original'], ('ExecStart',))
        self.assertTrue(set(('FutureSecurityKnob', 'RootImage', 'WatchdogUSec')) <= set(audit['unsupported']))
        self.assertIn('source-profile-changed', audit['issues'])
        self.assertTrue(audit['source_profile_change']['changed'])
        self.assertFalse(audit['source_profile_change']['raw_fragment_changed'])
        self.assertIsNotNone(audit['original_inventory'])
        self.assertEqual(audit['hook_proof_valid'], {'source': False, 'probe': False})
        c.save.reset_mock()
        with self.assertRaises(self.D.Unsupported) as raised:
            self.gate(c, plan, current=current, probe=probe)
        gated = self.artifact(c, 'plain/comparison.json')
        self.assert_names(raised.exception.labels, ('NoNewPrivileges', 'ExecReload', 'WatchdogUSec',
                          'ProtectSystem', 'StandardError', 'ExecStartPre', 'FutureSecurityKnob', 'RootImage'))
        self.assertEqual(raised.exception.labels, tuple(gated['issues']))
        c.save.assert_not_called()

    def test_show_nonzero_and_timeout_persist_read_errors_without_fake_watchdog(self):
        for code in (1, None):
            c = self.controller()
            plan = self.plan(c)
            plan['created_at'] = 0
            # Even parseable partial stdout is NOT accepted as a successful read.
            c.command = Mock(return_value=(code, REPORTED_PARTIAL.encode(), b'PRIVATE_SYNTHETIC_STDERR'))
            c.save.reset_mock()
            c.release_reservations = Mock()
            with patch.object(self.D, '_no_lock'), \
                    patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})), \
                    patch.object(time, 'monotonic', return_value=1), \
                    self.assertRaises(self.D.Unsupported) as raised:
                c.gate(plan)
            audit = self.artifact(c, 'plain/comparison.json')
            self.assertIn('dbus-or-show-unavailable', audit['inspection_errors'])
            self.assertIn('snapshots-unavailable', audit['issues'])
            self.assertEqual(audit['properties'], [])
            self.assertFalse(audit['snapshot_pair_supplied'])
            self.assertEqual(audit['coverage'], 'partial')
            self.assertFalse(audit['complete'])
            self.assertNotIn('WatchdogUSec', ';'.join(audit['issues']))
            self.assertNotIn('PRIVATE_SYNTHETIC_STDERR', str(raised.exception))
            self.assertEqual(c.command.call_count, 2)
            for call in c.command.call_args_list:
                self.assertEqual(call.args[0][:4], ['/usr/bin/systemctl', 'show', '--all', '--no-pager'])
            c.release_reservations.assert_not_called()
            c.save.assert_not_called()

    def test_main_console_exposes_only_labels_not_private_raw_watchdog_values(self):
        c = self.controller(True)
        plan = self.plan(c)
        probe = dict(self.probe(c, plan), WatchdogUSec='PRIVATE_SYNTHETIC_WATCHDOG',
                     FutureSecurityKnob='PRIVATE_SYNTHETIC_SECURITY', ExecStart='PRIVATE_SYNTHETIC_COMMAND')
        c.prepare = Mock()
        c.run_phase = Mock(side_effect=lambda phase: self.gate(c, plan, probe=probe))
        c.cleanup = Mock(return_value=True)
        c.save.reset_mock()
        rc, out, err = self.main_with(c)
        self.assertEqual(rc, 2)
        self.assertEqual(err, '')
        self.assertIn('unsupported:', out)
        self.assertIn('WatchdogUSec', out)
        self.assertIn('FutureSecurityKnob', out)
        self.assertNotIn('PRIVATE_SYNTHETIC', out + err)
        audit = self.artifact(c, 'plain/comparison.json')
        row = next(row for row in audit['properties'] if row['property'] == 'WatchdogUSec')
        self.assertEqual(row['probe'], 'PRIVATE_SYNTHETIC_WATCHDOG')
        self.assertEqual(row['probe_kind'], 'unknown')
        self.assertEqual(row['source_kind'], 'infinity')
        self.assertEqual(row['classification'], 'value-different')
        c.run_phase.assert_called_once_with('plain')
        c.cleanup.assert_called_once_with()
        c.save.assert_not_called()


class PureContracts(Offline):
    def test_parse_show_preserves_equals_and_empty_values(self):
        self.assertEqual(self.D.parse_show('Id=fixture.service\nEmpty=\nValue=a=b\n'),
                         {'Id': 'fixture.service', 'Empty': '', 'Value': 'a=b'})

    def test_parse_show_rejects_missing_duplicate_malformed_and_oversize(self):
        for value in ('', None, 'Id=x\nId=y', 'no-equals', '=value',
                      'Bad-Key=value', 'Id=x\n\nValue=y', 'Id=\x00',
                      'Id=' + 'x' * self.D.SHOW_LIMIT):
            with self.subTest(kind=type(value).__name__), self.assertRaises(self.D.Unsupported):
                self.D.parse_show(value)

    def test_actual_renderer_current_and_old_three_caps(self):
        for old, expected in ((False, CAPS4), (True, CAPS3)):
            with self.subTest(old=old):
                fragment = self.D.validate_fragment(rendered(old))
                self.assertEqual(self.D.validate_effective(source_properties(old), fragment), expected)

    def test_unknown_duplicate_reset_and_changed_fragment_directives_fail_closed(self):
        base = rendered()
        for bad in (base.replace('[Service]', '[Socket]'), base + '[Service]\n',
                    base.replace('Type=simple', 'Type=simple\nDelegate=yes'),
                    base.replace('Type=simple', 'Type=simple\nType=simple'),
                    base.replace('User=root', 'User='), base.replace('User=root', 'User=haproxy'),
                    base.replace('PrivateTmp=true\n', ''), base.replace('User=root', 'User=root\\'),
                    base.replace('CAP_KILL', 'CAP_SYS_ADMIN'), base.replace('CAP_KILL', 'CAP_SETUID'),
                    base.replace('\n', '\r\n'), base + '\x00'):
            with self.subTest(case=bad[:20]), self.assertRaises(self.D.Unsupported):
                self.D.validate_fragment(bad)

    def test_effective_unknown_syscall_filters_and_changed_security_rejected(self):
        changes = [('SystemCallFilter', value) for value in
                   ('', '@system-service', '~@mount', 'setuid setgid', '@privileged', 'read write')]
        changes += [('DropInPaths', '/fixture/dropin.conf'), ('NeedDaemonReload', 'yes'),
                    ('NoNewPrivileges', 'no'), ('SecureBits', '1'), ('User', 'haproxy'),
                    ('PrivateNetwork', 'yes'), ('PrivateUsers', 'yes'),
                    ('JoinsNamespaceOf', 'another.service'), ('RootDirectory', '/elsewhere'),
                    ('RootImage', '/some.img'),
                    ('AmbientCapabilities', 'CAP_SETUID'), ('ReadWritePaths', '/tmp'),
                    ('CapabilityBoundingSet', ' '.join(sorted(CAPS3))),
                    ('RestrictAddressFamilies', 'AF_INET AF_UNIX'),
                    ('ExecStart', exec_property(['/bin/true'])), ('ExecStop', 'unexpected')]
        for key, value in changes:
            p = source_properties()
            p[key] = value
            with self.subTest(property=key), self.assertRaises(self.D.Unsupported):
                self.D.validate_effective(p, self.D.validate_fragment(rendered()))
        for key in ('User', 'SystemCallFilter'):
            p = source_properties()
            del p[key]
            with self.assertRaises(self.D.Unsupported):
                self.D.validate_effective(p, self.D.validate_fragment(rendered()))

    def test_effective_exec_extended_unknown_or_second_command_rejected(self):
        for suffix in (' ; unknown=PRIVATE_FIXTURE', ' } { path=/bin/true', ' ; ignore_errors=yes'):
            p = source_properties()
            p['ExecStartEx'] = p['ExecStart'][:-2] + suffix + ' }'
            with self.assertRaises(self.D.Unsupported):
                self.D.validate_effective(p, self.D.validate_fragment(rendered()))

    def test_restrictions_compare_all_nonwhitelisted_names_and_missing_even_metadata(self):
        a = source_properties()
        for key in ('ProtectSystem', 'SystemCallFilter', 'IPAddressDeny', 'MemoryMax',
                    'RestrictNamespaces', 'FutureSecurityKnob', 'StopWhenUnneeded',
                    'RefuseManualStart', 'JoinsNamespaceOf', 'JobTimeoutUSec', 'CollectMode'):
            with self.subTest(property=key):
                left, right = dict(a, **{key: 'old'}), dict(a, **{key: 'PRIVATE_FIXTURE'})
                self.assertEqual(self.D.restriction_differences(left, right), [key])
        self.assertEqual(self.D.restriction_differences({'Id': MAIN}, {}), ['Id'])
        self.assertEqual(self.D.restriction_differences({}, {'FutureSecurityKnob': 'x'}), ['FutureSecurityKnob'])

    def test_only_documented_equivalences_and_intended_runtime_changes_ignored(self):
        a, b = source_properties(), source_properties()
        b.update(MainPID='456', Restart='no', RuntimeMaxUSec='8s',
                 CapabilityBoundingSet=' '.join(reversed(a['CapabilityBoundingSet'].split())),
                 RestrictAddressFamilies='AF_UNIX AF_INET6 AF_INET')
        self.assertEqual(self.D.restriction_differences(a, b), [])
        b['NoNewPrivileges'] = 'no'
        self.assertEqual(self.D.restriction_differences(a, b), ['NoNewPrivileges'])
        self.assertEqual(self.D.restriction_differences({'SystemCallFilter': '~'},
                                                      {'SystemCallFilter': ''}), ['SystemCallFilter'])
        self.assertEqual(self.D.restriction_differences({'SystemCallFilter': ''},
                                                      {'SystemCallFilter': '~'}), ['SystemCallFilter'])

    def test_config_literal_loopback_high_port_and_same_unique_abstract_pair(self):
        text = self.D.make_config(49173, ABSTRACT)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        self.assertEqual([line for line in lines if line.startswith('bind ')],
                         ['bind 127.0.0.1:49173', 'bind abns@' + ABSTRACT])
        self.assertEqual([line for line in lines if line.startswith('server ')],
                         ['server local abns@' + ABSTRACT])
        self.assertEqual(text.count(ABSTRACT), 2)
        self.assertIn('user haproxy', lines)
        self.assertIn('group haproxy', lines)
        self.assertIn('tcp-request content reject', lines)
        for forbidden in ('0.0.0.0', '[::]', '.pem', 'crt ', '/etc/', ':80', ':443',
                          ':22', ':1194', 'send-proxy', 'nginx', 'xray'):
            self.assertNotIn(forbidden, text)
        another = self.D.make_config(49174, 'nathaya-probe-' + 'c' * 32)
        self.assertNotIn(ABSTRACT, another)

    def test_config_rejects_port_and_abstract_injection(self):
        for port in (0, 80, 443, 1023, 65536, True, '49173'):
            with self.assertRaises(ValueError):
                self.D.make_config(port, ABSTRACT)
        for name in ('/tmp/socket', 'nathaya-probe-short', ABSTRACT + '\nbind *:443', ABSTRACT.upper()):
            with self.assertRaises(ValueError):
                self.D.make_config(49173, name)

    def test_trace_command_is_narrow_and_sensitive_structures_are_raw(self):
        argv = ['/usr/sbin/haproxy', '-W', '-db', '-f',
                '/run/nathaya-haproxy-probe.fixture/trace/haproxy.cfg']
        command = self.D.trace_command(argv)
        self.assertEqual(command[-5:], argv)
        self.assertEqual(command[:4], ['/usr/bin/strace', '-f', '-e', 'signal=none'])
        selector = next(item for item in command if item.startswith('trace='))
        names = set(selector[6:].split(','))
        self.assertTrue({'setuid', 'setgid', 'capset', 'prctl', 'clone'} <= names)
        self.assertFalse(names & {'execve', 'execveat', 'read', 'write', 'readv', 'writev',
                                 'socket', 'connect', 'sendto', 'recvfrom', 'mmap', 'mprotect',
                                 'open', 'openat', 'all', '%process', '%network', '%memory', '%creds'})
        self.assertFalse(any(name.startswith(('%', '@')) for name in names))
        self.assertIn('raw=clone,clone3,prctl', command)
        for bad in (argv + ['-vv'], ['/bin/sh'] + argv[1:], argv[:-1] + ['/etc/private.pem']):
            with self.assertRaises(ValueError):
                self.D.trace_command(bad)

    def test_trace_errno_resumed_counts_never_return_args_pids_or_secrets(self):
        raw = '\n'.join((
            '123 setuid(98765) = -1 EPERM (PRIVATE_FIXTURE_VALUE)',
            '[pid 124] setgid(45678) = -1 EINVAL (PRIVATE_FIXTURE_VALUE)',
            '[pid 124] <... setgid resumed>) = -1 EINVAL (PRIVATE_FIXTURE_VALUE)',
            '125 setuid(123 <unfinished ...>',
            '126 execve("PRIVATE_FIXTURE_VALUE", ["secret"], 0) = -1 EPERM (denied)',
            'haproxy: PRIVATE_FIXTURE_VALUE setuid failure',
            '127 setuid(42) = -1 INVENTED_ERRNO (PRIVATE_FIXTURE_VALUE)',
        ))
        result = self.D.sanitise_trace(raw)
        self.assertEqual(result, {'available': True, 'identity_calls': 1, 'records': 3,
                                 'capset_records': 0, 'counts': [{'syscall': 'setgid', 'errno': 'EINVAL', 'count': 2},
                                            {'syscall': 'setuid', 'errno': 'EPERM', 'count': 1}]})
        encoded = json.dumps(result)
        for value in ('PRIVATE_FIXTURE_VALUE', '98765', '45678', '123', 'args', 'secret'):
            self.assertNotIn(value, encoded)

    def test_denied_or_incomplete_trace_is_unavailable_not_success(self):
        for denial in ('strace: ptrace(PTRACE_TRACEME): Operation not permitted',
                       'strace: Yama policy denies attach', 'strace: Permission denied'):
            self.assertFalse(self.D.sanitise_trace('setuid(123) = 0\n' + denial)['available'])
        for text in ('', 'setgid(123) = 0', 'setuid(123 <unfinished ...>',
                     'HAProxy setuid failed EPERM PRIVATE_FIXTURE_VALUE'):
            self.assertFalse(self.D.sanitise_trace(text)['available'])


class CaptureContracts(Offline):
    """Actual capture + identity, using integer-only virtual FDs, never host IO."""
    def stat_bytes(self, pid=101, start=1234):
        # Fields 3..21, then starttime (22); trailing memory fields must not save.
        return (str(pid) + ' (name with ) spaces) S ' + '0 ' * 18 +
                str(start) + ' 999999 PRIVATE_STAT_MEMORY\n').encode()

    def status_bytes(self, pid=101, parent=1, uid=0, gid=0, caps=0x4e0):
        return (f'Pid:\t{pid}\nPPid:\t{parent}\nUid:\t' + f'{uid} ' * 4 +
                '\nGid:\t' + f'{gid} ' * 4 + f'\nGroups:\t{gid}\n' +
                f'CapInh:\t0\nCapEff:\t{caps:x}\nCapPrm:\t{caps:x}\nCapBnd:\t4e0\n'
                'CapAmb:\t0\nNoNewPrivs:\t1\n').encode()

    def virtual_capture(self, c, unit=None, changes=None, procs=b'101\n', links=None,
                        extra=None, save_error=False, read_error=None, sample='plain/sample-000'):
        unit = unit or 'nathaya-haproxy-probe-' + NONCE + '-plain.service'
        member = ('0::/system.slice/' + unit + '\n').encode()
        files = {101: {'cgroup': [member, member],
                       'stat': [self.stat_bytes(), self.stat_bytes()],
                       'status': [self.status_bytes()],
                       'uid_map': [b'0 0 4294967295\n'],
                       'gid_map': [b'0 0 4294967295\n']}}
        files[101].update(changes or {})
        files.update(extra or {})
        links = links or {pid: ['/usr/sbin/haproxy'] * 2 for pid in files}
        live, names, opened, closed, events, sizes = {}, {}, [], [], [], []
        next_fd = 1000

        def take(values):
            self.assertTrue(values, 'Unexpected repeated access')
            value = values.pop(0)
            if isinstance(value, BaseException):
                raise value
            return value

        def opening(path, flags, *, dir_fd=None):
            nonlocal next_fd
            self.assertIsInstance(path, str)
            common = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if path.startswith('/proc/'):
                self.assertIsNone(dir_fd)
                self.assertEqual(flags, common | os.O_DIRECTORY)
                pid = int(path.removeprefix('/proc/'))
                self.assertIn(pid, files)
                # An anchored process dir must never be reopened by numeric PID.
                self.assertNotIn(path, [p for p, _ in opened])
                value = ('dir', pid)
            elif path.startswith('/sys/fs/cgroup/'):
                self.assertEqual(path, '/sys/fs/cgroup/system.slice/' + unit + '/cgroup.procs')
                self.assertIsNone(dir_fd)
                self.assertEqual(flags, common)
                value = ('file', procs)
            else:
                self.assertEqual(flags, common)
                self.assertIn(dir_fd, live)
                kind, pid = live[dir_fd]
                self.assertEqual(kind, 'dir')
                self.assertIn(path, {'cgroup', 'stat', 'status', 'uid_map', 'gid_map'})
                value = ('file', take(files[pid][path]))
            opened.append((path, dir_fd))
            events.append(('open', path, dir_fd))
            next_fd += 1
            live[next_fd] = value
            names[next_fd] = path
            return next_fd

        def reading(fd, size):
            self.assertIn(fd, live)
            kind, data = live[fd]
            self.assertEqual(kind, 'file')
            self.assertGreater(size, 0)
            self.assertLessEqual(size, 4096)
            if names[fd] == read_error:
                raise OSError(errno.ESRCH, 'PRIVATE_READ_ERROR')
            sizes.append(size)
            live[fd] = (kind, data[size:])
            return data[:size]

        def closing(fd):
            self.assertIn(fd, live)
            del live[fd]
            closed.append(fd)

        def readlink(path, *, dir_fd=None):
            self.assertEqual(path, 'exe')
            self.assertIn(dir_fd, live)
            kind, pid = live[dir_fd]
            self.assertEqual(kind, 'dir')
            events.append(('link', pid, dir_fd))
            return take(links[pid])

        def saving(name, data):
            # Every byte of process evidence follows the final membership read.
            self.assertEqual(events[-1][0:2], ('open', 'cgroup'))
            self.assertIsInstance(data, bytes)
            if save_error:
                raise OSError(errno.ENOSPC, 'PRIVATE_FIXTURE_VALUE')
            return c.directory / name

        c.save.side_effect = saving
        with patch.object(os, 'open', side_effect=opening), \
                patch.object(os, 'read', side_effect=reading), \
                patch.object(os, 'close', side_effect=closing), \
                patch.object(os, 'readlink', side_effect=readlink):
            try:
                result = c.capture(unit, sample)
            finally:
                self.assertEqual(live, {}, 'All FDs must close even on refusal/errors')
                self.assertEqual(len(closed), len(opened))
        self.assertFalse(any(path in ('maps', 'mem', 'environ', 'cmdline') for path, _ in opened))
        return result, opened, sizes

    def test_capture_refuses_main_foreign_nonce_and_malformed_names_before_io(self):
        c = self.controller()
        for unit in (MAIN, 'unrelated.service',
                     'nathaya-haproxy-probe-' + 'b' * 32 + '-plain.service',
                     'nathaya-haproxy-probe-' + NONCE + '-plain.service/../x'):
            with self.subTest(unit=unit), self.assertRaisesRegex(self.D.Unsupported, 'probe-ownership'):
                # Unpatched Offline guards would fail any attempted host read.
                c.capture(unit, 'plain/refused')
        for nonce in ('', 'A' * 32, 'a' * 31):
            c.nonce = nonce
            with self.assertRaisesRegex(self.D.Unsupported, 'probe-ownership'):
                c.capture('nathaya-haproxy-probe-' + NONCE + '-plain.service', 'plain/refused')
        c.save.assert_not_called()
        c.record.assert_not_called()

    def test_capture_outside_cgroup_never_opens_status_or_stat_or_exe(self):
        c = self.controller()
        result, opened, _ = self.virtual_capture(c, changes={'cgroup': [b'0::/outside\n']})
        self.assertEqual(result, [])
        self.assertEqual([p for p, fd in opened if fd is not None], ['cgroup'])
        c.save.assert_not_called()
        self.assertEqual(c.record.call_args.args[1]['errors'][0]['error'], 'membership-before')

    def test_capture_rechecks_membership_starttime_pid_and_executable_before_any_save(self):
        for changes, links, label in (
                ({'cgroup': [('0::/system.slice/nathaya-haproxy-probe-' + NONCE +
                              '-plain.service\n').encode(), b'0::/outside\n']}, None, 'membership-after'),
                ({'stat': [self.stat_bytes(), self.stat_bytes(start=999)]}, None, 'identity-after'),
                ({'stat': [self.stat_bytes(pid=999)]}, None, 'ValueError'),
                ({}, {101: ['/usr/sbin/haproxy', '/outside/exe']}, 'ValueError')):
            c = self.controller()
            with self.subTest(label=label):
                result, _, _ = self.virtual_capture(c, changes=changes, links=links)
                self.assertEqual(result, [])
                c.save.assert_not_called()
                self.assertEqual(c.record.call_args.args[1]['errors'][0]['error'], label)
                self.assertNotIn('PRIVATE_STAT_MEMORY', str(c.record.call_args))

    def test_capture_success_bounded_metadata_only_and_anchor_used_for_every_read(self):
        c = self.controller()
        result, opened, sizes = self.virtual_capture(c)
        self.assertEqual(result, [{'exe': self.D.HAPROXY,
                                   'status': self.D._status(self.status_bytes().decode())}])
        self.assertTrue(sizes)
        anchored = {fd for _, fd in opened if fd is not None}
        self.assertEqual(len(anchored), 1)
        saved = {call.args[0].rsplit('.', 1)[1]: call.args[1] for call in c.save.call_args_list}
        self.assertEqual(set(saved), {'status', 'cgroup', 'exe', 'uid_map', 'gid_map'})
        self.assertIn(b'CapEff:\t4e0', saved['status'])
        self.assertNotIn(b'PRIVATE_STAT_MEMORY', b''.join(saved.values()))
        self.assertEqual(c.record.call_args.args[1]['errors'], [])

    def test_capture_retains_first_unique_root_state_and_sample_after_later_capability_loss(self):
        c = self.controller()
        c.boundary_plans = [self.plan(c)]
        for index, caps in enumerate((0x4e0, 0x4e0, 0x460, 0x460)):
            self.virtual_capture(c, changes={'status': [self.status_bytes(caps=caps)]},
                                 sample=f'plain/sample-{index:03d}')
        self.assertEqual([r['stage'] for r in c.process_boundaries], ['plain:haproxy-root'] * 2)
        self.assertEqual([r['sample'] for r in c.process_boundaries],
                         ['plain/sample-000', 'plain/sample-002'])
        self.assertEqual([(r['status']['CapEff'], r['status']['CapPrm'])
                          for r in c.process_boundaries], [(0x4e0, 0x4e0), (0x460, 0x460)])
        c.read_boundaries = Mock(return_value=[])
        self.assertEqual(c.boundary_report(), 'plain:haproxy-root')
        report = c.record.call_args.args[1]
        self.assertEqual([r['sample'] for r in report['observations']],
                         ['plain/sample-000', 'plain/sample-002'])
        self.assertEqual([r['scope'] for r in report['observations']], ['unit-root'] * 2)
        self.assertTrue(report['observations'][0]['SETUID']['CapEff'])
        self.assertFalse(report['observations'][1]['SETUID']['CapEff'])

    def test_capture_exe_denied_preserves_caps_but_cannot_establish_identity(self):
        c = self.controller()
        result, _, _ = self.virtual_capture(c, links={101: [
            PermissionError(errno.EACCES, 'PRIVATE_FIXTURE_VALUE'),
            PermissionError(errno.EACCES, 'PRIVATE_FIXTURE_VALUE')]})
        self.assertEqual(result, [])
        saved = {call.args[0].rsplit('.', 1)[1]: call.args[1] for call in c.save.call_args_list}
        self.assertIn(b'CapEff:\t4e0', saved['status'])
        self.assertNotIn('exe', saved)
        self.assertIsNone(c.identity(result, {'MainPID': '101'}, False))
        self.assertEqual(c.record.call_args.args[1]['errors'],
                         [{'pid': 101, 'error': 'exeUnavailable', 'errno': errno.EACCES}])
        self.assertNotIn('PRIVATE_FIXTURE_VALUE', str(c.record.call_args))

    def test_capture_oversize_cgroup_and_status_are_bounded_and_never_saved(self):
        for procs, changes in ((b'101\n' * 2000, {}),
                               (b'101\n', {'status': [b'x' * 65537]}),
                               (b'101\n', {'cgroup': [b'x' * 4097]})):
            c = self.controller()
            result, _, _ = self.virtual_capture(c, procs=procs, changes=changes)
            self.assertEqual(result, [])
            c.save.assert_not_called()

    def test_capture_closes_fds_on_read_and_save_errors(self):
        for changes, save_error in (({'status': [OSError(errno.ESRCH, 'PRIVATE')]}, False),
                                    ({}, True)):
            c = self.controller()
            result, _, _ = self.virtual_capture(c, changes=changes, save_error=save_error)
            self.assertEqual(result, [])
            self.assertNotIn('PRIVATE', str(c.record.call_args))

    def test_capture_closes_open_metadata_fd_when_read_itself_fails(self):
        c = self.controller()
        result, _, _ = self.virtual_capture(c, read_error='status')
        self.assertEqual(result, [])
        c.save.assert_not_called()
        self.assertNotIn('PRIVATE_READ_ERROR', str(c.record.call_args))

    def test_capture_identity_integration_and_incomplete_exe_inventory(self):
        unit = 'nathaya-haproxy-probe-' + NONCE + '-plain.service'
        member = ('0::/system.slice/' + unit + '\n').encode()
        for denied_extra in (False, True):
            c = self.controller()
            c.uid, c.gid = 200, 201
            extra = {102: {'cgroup': [member, member],
                           'stat': [self.stat_bytes(102), self.stat_bytes(102)],
                           'status': [self.status_bytes(102, 101, 200, 201, 0)],
                           'uid_map': [b'0 0 4294967295\n'],
                           'gid_map': [b'0 0 4294967295\n']}}
            links = {101: [self.D.HAPROXY] * 2, 102: [self.D.HAPROXY] * 2}
            procs = b'101\n102\n'
            if denied_extra:
                extra[103] = {'cgroup': [member, member],
                              'stat': [self.stat_bytes(103), self.stat_bytes(103)],
                              'status': [self.status_bytes(103)],
                              'uid_map': [b'0 0 4294967295\n'],
                              'gid_map': [b'0 0 4294967295\n']}
                links[103] = [PermissionError(errno.EPERM, 'denied') for _ in range(2)]
                procs += b'103\n'
            result, _, _ = self.virtual_capture(c, extra=extra, procs=procs, links=links)
            identity = c.identity(result, {'MainPID': '101'}, False)
            self.assertEqual(identity, None if denied_extra else (101, (102,)))

    def test_capture_map_limits_and_read_errors_retain_valid_status_only(self):
        c = self.controller()
        result, _, _ = self.virtual_capture(c, changes={
            'uid_map': [b'x' * 65537], 'gid_map': [OSError(errno.EACCES, 'PRIVATE')]})
        self.assertEqual(len(result), 1)
        suffixes = {call.args[0].rsplit('.', 1)[1] for call in c.save.call_args_list}
        self.assertEqual(suffixes, {'status', 'cgroup', 'exe'})
        self.assertEqual({row['file'] for row in c.record.call_args.args[1]['errors']},
                         {'uid_map', 'gid_map'})
        self.assertNotIn('PRIVATE', str(c.record.call_args))

    def test_stat_parser_handles_comm_delimiters_and_rejects_missing_identity(self):
        self.assertEqual(self.D._proc_identity(self.stat_bytes()), (101, 1234))
        for raw in (b'', b'101 (comm) S 0', self.stat_bytes().replace(b'1234', b'nope')):
            with self.assertRaises(ValueError):
                self.D._proc_identity(raw)


class ControllerContracts(Offline):
    def test_factory_replicates_old_caps_does_not_add_kill_and_keeps_source_unchanged(self):
        for old, expected in ((True, CAPS3), (False, CAPS4)):
            c = self.controller(old)
            before = copy.deepcopy((c.source, c.fragment, c.source_bytes, c.caps))
            for phase in ('plain', 'trace'):
                plan = self.plan(c, phase)
                p = plan['properties']
                self.assertEqual(frozenset(p['CapabilityBoundingSet'].split()), expected)
                self.assertEqual(p['Restart'], 'no')
                self.assertLessEqual(float(p['RuntimeMaxSec'].removesuffix('s')), 15)
                self.assertEqual(p['NoNewPrivileges'], 'yes')
                self.assertIn('--no-block', plan['command'])
                self.assertNotIn(MAIN, plan['command'])
                self.assertEqual(plan['argv'][0], '/usr/bin/strace' if phase == 'trace' else '/usr/sbin/haproxy')
            self.assertTrue(before == (c.source, c.fragment, c.source_bytes, c.caps))
            self.assertTrue(c.save.call_args_list[0].args[0].startswith('plain/'))
            self.assertEqual(c.save.call_args_list[0].args[1], self.D.make_config(49173, ABSTRACT))

    def test_reserve_uses_only_mock_sockets_exact_padded_abstract_address(self):
        c = self.controller()
        tcp, unix = Mock(), Mock()
        tcp.getsockname.return_value = ('127.0.0.1', 49173)
        with patch.object(socket, 'socket', side_effect=[tcp, unix]) as factory, \
                patch.object(secrets, 'token_hex', return_value='b' * 32):
            self.assertEqual(c.reserve(), (49173, ABSTRACT))
        self.assertEqual(factory.call_args_list[0].args, (socket.AF_INET, socket.SOCK_STREAM))
        self.assertEqual(factory.call_args_list[1].args, (socket.AF_UNIX, socket.SOCK_STREAM))
        tcp.bind.assert_called_once_with(('127.0.0.1', 0))
        unix.bind.assert_called_once_with((b'\x00' + ABSTRACT.encode()).ljust(108, b'\x00'))
        c.release_reservations()
        tcp.close.assert_called_once_with()
        unix.close.assert_called_once_with()
        self.assertEqual(c.reservations, [])

    def test_show_property_failure_never_falls_back_to_cat_or_weakened_query(self):
        c = self.controller()
        for result in ((1, b'Id=x\nLoadState=loaded\n', b'PRIVATE_FIXTURE_VALUE'),
                       (0, b'Id=x\nId=y\n', b''), (0, b'Id=\xff', b''),
                       (None, b'', b'')):
            with patch.object(c, 'command', return_value=result) as command:
                with self.assertRaises(self.D.Unsupported):
                    c.show(MAIN)
                command.assert_called_once_with(
                    ['/usr/bin/systemctl', 'show', '--all', '--no-pager', MAIN], timeout=3)
        with patch.object(c, 'command', return_value=(1, b'LoadState=not-found\n', b'')):
            self.assertEqual(c.show(MAIN, absent=True)['LoadState'], 'not-found')

    def test_command_timeout_is_persisted_once_with_fixed_environment_and_no_retry(self):
        c = self.controller()
        exc = subprocess.TimeoutExpired(['fixture-only'], 3, output=b'partial', stderr=b'private')
        with patch.object(subprocess, 'run', side_effect=exc) as runner:
            self.assertEqual(c.command(['fixture-only'], timeout=99), (None, b'partial', b'private'))
        runner.assert_called_once_with(['fixture-only'], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=3,
                                      env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
                                      check=False)
        self.assertEqual(c.record.call_args.args[1]['state'], 'timeout')
        self.assertEqual(c.record.call_args.args[1]['returncode'], None)

    def test_gate_releases_only_after_real_validation_and_two_live_snapshots(self):
        c = self.controller(True)
        plan = self.plan(c)
        c.save.reset_mock()
        self.gate(c, plan)
        c.save.assert_called_once_with('plain/go', b'')
        comparison = next(call.args[1] for call in c.record.call_args_list
                          if call.args[0] == 'plain/comparison.json')
        self.assertEqual(comparison['unsupported'], [])

    def test_gate_unknown_security_difference_blocks_before_go(self):
        for key in ('SystemCallFilter', 'FutureSecurityKnob', 'MemoryMax', 'IPAddressDeny'):
            c = self.controller()
            plan = self.plan(c)
            c.source[key] = '~' if key == 'SystemCallFilter' else 'original'
            p = self.probe(c, plan)
            p[key] = '~@mount' if key == 'SystemCallFilter' else 'PRIVATE_FIXTURE_VALUE'
            c.save.reset_mock()
            with self.subTest(property=key), self.assertRaises(self.D.Unsupported):
                self.gate(c, plan, probe=p)
            c.save.assert_not_called()

    def test_gate_changed_source_or_live_prestart_never_releases(self):
        for variant in ('source', 'live'):
            c = self.controller()
            plan = self.plan(c)
            current, live = dict(c.source), self.probe(c, plan)
            if variant == 'source':
                current['MemoryMax'] = 'changed'
            else:
                live['SubState'] = 'running'
            c.save.reset_mock()
            with self.subTest(variant=variant), self.assertRaises(self.D.Unsupported):
                self.gate(c, plan, current=current, live=live)
            c.save.assert_not_called()

    def test_gate_expired_and_missed_prestart_are_not_haproxy_failure(self):
        # The aggregate gate now reads current evidence before the live check;
        # keep the mock clock expired for all live audit/deadline reads.
        for clock, inactive in ((10, False), ([1, 1, 1, 4, 4, 4], False), (1, True)):
            c = self.controller()
            plan = self.plan(c)
            p = self.probe(c, plan)
            if inactive:
                p['ActiveState'] = 'inactive'
            c.save.reset_mock()
            with self.assertRaisesRegex(self.D.Unsupported, 'prestart-'):
                self.gate(c, plan, probe=p, clock=clock)
            c.save.assert_not_called()

    def test_failed_creation_and_gate_timeout_never_observe_or_retry(self):
        for mode in ('property-failure', 'gate-timeout'):
            c = self.controller()
            plan = self.plan(c)
            c.factory = Mock(return_value=plan)
            c.show = Mock(return_value={'LoadState': 'not-found'})
            c.command = Mock(return_value=(1 if mode == 'property-failure' else 0, b'', b''))
            c.gate = Mock(side_effect=self.D.Unsupported('prestart-unavailable'))
            c.observe = Mock()
            with patch.object(self.D, '_no_lock'), self.assertRaises(self.D.Unsupported):
                c.run_phase('plain')
            c.command.assert_called_once_with(plan['command'])
            c.observe.assert_not_called()
            self.assertEqual(c.intents, [plan['unit']])
            self.assertEqual(c.gate.call_count, int(mode == 'gate-timeout'))

    def test_plain_phase_intent_precedes_runner_and_owned_cleanup_removes_intent(self):
        c = self.controller()
        plan = self.plan(c)
        c.factory = Mock(return_value=plan)
        c.show = Mock(return_value={'LoadState': 'not-found'})
        def created(argv):
            self.assertEqual(c.intents, [plan['unit']])
            self.assertEqual(c.record.call_args.args[0], 'plain/intent.json')
            return 0, b'', b''
        c.command = Mock(side_effect=created)
        c.gate = Mock()
        c.observe = Mock(return_value='observed-running')
        c.cleanup_one = Mock(return_value=True)
        with patch.object(self.D, '_no_lock'):
            self.assertEqual(c.run_phase('plain'), ('observed-running', None))
        c.gate.assert_called_once_with(plan)
        c.observe.assert_called_once_with(plan)
        c.cleanup_one.assert_called_once_with(plan['unit'])
        self.assertEqual(c.intents, [])
        self.assertIn(plan['unit'], c.creation_confirmed)

    def test_collision_never_creates_stops_or_claims_existing_unit(self):
        c = self.controller()
        plan = self.plan(c)
        c.factory = Mock(return_value=plan)
        c.show = Mock(return_value={'LoadState': 'loaded'})
        c.command = Mock()
        with patch.object(self.D, '_no_lock'), self.assertRaisesRegex(self.D.Unsupported, 'unit-name-conflict'):
            c.run_phase('plain')
        c.command.assert_not_called()
        self.assertEqual(c.intents, [])

    def test_ownership_is_conjunction_and_cleanup_never_stops_main_or_unrelated_units(self):
        c = self.controller()
        plan = self.plan(c)
        valid = self.probe(c, plan)
        self.assertTrue(self.D.owned_unit(valid, plan['unit'], NONCE))
        for key, value in (('Id', MAIN), ('Transient', 'no'), ('Description', 'foreign'),
                           ('FragmentPath', FRAGMENT), ('ControlGroup', '/system.slice/unrelated.service')):
            bad = dict(valid, **{key: value})
            self.assertFalse(self.D.owned_unit(bad, plan['unit'], NONCE))
            with patch.object(c, 'show', return_value=bad), patch.object(c, 'command') as command:
                self.assertFalse(c.cleanup_one(plan['unit']))
            command.assert_not_called()
        for unit in (MAIN, 'unrelated.service', plan['unit'].replace(NONCE, 'c' * 32)):
            with patch.object(c, 'show', return_value=valid), patch.object(c, 'command') as command:
                self.assertFalse(c.cleanup_one(unit))
            command.assert_not_called()

    def test_pending_absence_not_confirmed_until_creation_known(self):
        c = self.controller()
        unit = self.plan(c)['unit']
        with patch.object(c, 'show', return_value={'LoadState': 'not-found'}), \
                patch.object(c, 'command') as command:
            self.assertFalse(c.cleanup_one(unit))
            c.creation_confirmed.add(unit)
            self.assertTrue(c.cleanup_one(unit))
        command.assert_not_called()

    def test_cleanup_only_stops_owned_unit_and_rechecks_ownership(self):
        c = self.controller()
        plan = self.plan(c)
        owned = self.probe(c, plan)
        foreign = dict(owned, Description='foreign-after-stop')
        with patch.object(c, 'show', side_effect=[owned, foreign]), \
                patch.object(c, 'command') as command, patch.object(time, 'monotonic', return_value=1):
            self.assertFalse(c.cleanup_one(plan['unit']))
        command.assert_called_once_with(['/usr/bin/systemctl', 'stop', '--no-block', plan['unit']])

    def test_plain_is_default_trace_only_after_failure_and_profiles_not_mutated(self):
        for status, phases in (('observed-running', ['plain']), ('unavailable', ['plain']),
                               ('failed', ['plain', 'trace'])):
            c = self.controller(True)
            before = copy.deepcopy((c.source, c.fragment, c.source_bytes, c.caps))
            c.prepare = Mock()
            c.run_phase = Mock(side_effect=[(status, None), ('failed', {'available': False, 'counts': []})])
            c.cleanup = Mock(return_value=True)
            with patch.object(os.path, 'isfile', return_value=True), patch.object(self.D, '_secure_path'):
                rc, out, err = self.main_with(c)
            self.assertEqual([call.args[0] for call in c.run_phase.call_args_list], phases)
            self.assertEqual(rc, 0 if status == 'observed-running' else 2)
            self.assertEqual(err, '')
            self.assertTrue(before == (c.source, c.fragment, c.source_bytes, c.caps))
            c.cleanup.assert_called_once_with()
            if status == 'failed':
                self.assertLess(out.index('plain startup:'), out.index('trace startup:'))
                self.assertIn('does NOT represent the untraced run', out)
                self.assertIn('trace evidence: unavailable', out)

    def test_main_partial_unavailable_trace_still_prints_counts_without_private_data(self):
        c = self.controller()
        c.prepare = Mock()
        trace = self.D.sanitise_trace(
            '101 setuid(98765) = -1 EPERM (PRIVATE_FIXTURE_VALUE)\n'
            'strace: ptrace(PTRACE_TRACEME): Operation not permitted\n'
            'PRIVATE_FIXTURE_VALUE unstructured log\n')
        self.assertFalse(trace['available'])
        c.run_phase = Mock(side_effect=[('failed', None), ('failed', trace)])
        c.cleanup = Mock(return_value=True)
        with patch.object(os.path, 'isfile', return_value=True), patch.object(self.D, '_secure_path'):
            rc, out, err = self.main_with(c)
        self.assertEqual(rc, 2)
        self.assertEqual(err, '')
        self.assertIn('trace evidence: unavailable', out)
        self.assertIn('may be partial; not proof of untraced cause', out)
        self.assertIn('setuid EPERM count=1', out)
        for private in ('PRIVATE_FIXTURE_VALUE', '98765', '101', 'PTRACE_TRACEME'):
            self.assertNotIn(private, out)

    def test_unsupported_plain_gate_does_not_fall_back_to_trace(self):
        c = self.controller()
        c.prepare = Mock()
        c.run_phase = Mock(side_effect=self.D.Unsupported('properties:FutureSecurityKnob'))
        c.cleanup = Mock(return_value=True)
        rc, out, _ = self.main_with(c)
        self.assertEqual(rc, 2)
        c.run_phase.assert_called_once_with('plain')
        self.assertNotIn('trace startup:', out)
        c.cleanup.assert_called_once_with()

    def test_missing_tracer_never_tries_an_alternate_tracer_or_second_plain_run(self):
        c = self.controller()
        c.prepare = Mock()
        c.run_phase = Mock(return_value=('failed', None))
        c.cleanup = Mock(return_value=True)
        with patch.object(os.path, 'isfile', return_value=False):
            rc, out, _ = self.main_with(c)
        self.assertEqual(rc, 2)
        c.run_phase.assert_called_once_with('plain')
        self.assertIn('trace evidence: unavailable (strace not installed)', out)

    def test_unconfirmed_cleanup_cannot_report_success(self):
        c = self.controller()
        c.prepare = Mock()
        c.run_phase = Mock(return_value=('observed-running', None))
        c.cleanup = Mock(return_value=False)
        rc, out, _ = self.main_with(c)
        self.assertEqual(rc, 2)
        self.assertIn('cleanup: unconfirmed', out)


class CapabilityBoundaryContracts(Offline):
    """Fixed Python controls and metadata only; helpers are never executed."""

    def control(self, c, phase='cap-gated'):
        return self.D.control_plan(c.directory, c.nonce, c.caps, phase)

    def control_probe(self, c, plan):
        p = self.probe(c, plan)
        if plan['phase'] == 'cap-direct':
            p.update(ActiveState='active', SubState='running', MainPID='42', ControlPID='0')
        return p

    def boundary(self, c, phase='cap-gated', stage='control-entry', **changes):
        r = dict(tag=self.D.BOUNDARY_TAG, stage=stage, token=str(c.directory / phase),
                 status=CaptureContracts.status_bytes(self).decode() + 'TracerPid:\t0\nSeccomp:\t2\n',
                 exe='/usr/bin/python3.12', env_present=dict.fromkeys(self.D.ENV_NAMES, False))
        r.update(changes)
        return r

    def records(self, c, phase):
        stages = (['gate-entry', 'gate-exit'] if phase == 'cap-gated' else [])
        stages += ['control-entry', 'after-exec']
        raw = '\n'.join(json.dumps(self.boundary(c, phase, stage)) for stage in stages)
        return self.D.boundary_records(raw, str(c.directory / phase), control=True)

    def test_control_plans_share_exact_restrictions_without_listener_or_application_payload(self):
        for old in (True, False):
            c = self.controller(old)
            before = copy.deepcopy((c.source, c.fragment, c.caps))
            plain = self.plan(c)
            for phase in ('cap-gated', 'cap-direct'):
                plan = self.control(c, phase)
                self.assertEqual(plan['argv'], ['/usr/bin/python3', '-I', '-B',
                                 str(c.directory / 'control.py'), str(c.directory / phase / 'control-go')])
                expected = self.D.restriction_properties(c.caps)
                self.assertEqual({k: plan['properties'][k] for k in expected}, expected)
                self.assertEqual({k: plain['properties'][k] for k in expected}, expected)
                self.assertEqual(plan['command'], self.D.transient_command(
                    plan['unit'], plan['properties'], plan['argv']))
                if phase == 'cap-gated':
                    self.assertEqual(plan['pre'], ['/usr/bin/python3', '-I', '-B',
                                     str(c.directory / 'gate.py'), str(c.directory / phase / 'go')])
                    self.assertEqual(plan['properties']['ExecStartPre'], ' '.join(plan['pre']))
                else:
                    self.assertEqual(plan['pre'], [])
                    self.assertNotIn('ExecStartPre', plan['properties'])
                    self.assertEqual(plan['go'], plan['control_go'])
                for forbidden in ('/usr/sbin/haproxy', '/usr/bin/strace', 'haproxy.cfg',
                                  '127.0.0.1', 'abns@', '/bin/sh'):
                    self.assertNotIn(forbidden, ' '.join(plan['command']))
                self.assertNotIn('-c', plan['command'])
            self.assertEqual((c.source, c.fragment, c.caps), before)
        for phase, nonce, directory in (('plain', NONCE, c.directory),
                                        ('cap-direct', 'A' * 32, c.directory),
                                        ('cap-gated', NONCE, Path('/tmp/untrusted'))):
            with self.assertRaises(self.D.Unsupported):
                self.D.control_plan(directory, nonce, CAPS3, phase)

    def test_validate_control_exact_plans_reject_arbitrary_argv_and_shadow_properties(self):
        c = self.controller()
        for phase in ('cap-gated', 'cap-direct'):
            good = self.control(c, phase)
            probe = self.control_probe(c, good)
            c.validate_control(probe, good)
            self.assertTrue(c.audit_compatibility(c.source, probe, fragment=c.fragment, plan=good)['ok'])
            for key in ('argv', 'pre', 'go', 'control_go', 'unit', 'output', 'properties', 'command'):
                bad = copy.deepcopy(good)
                if key in ('argv', 'pre'):
                    bad[key] = ['/bin/true']
                elif key == 'properties':
                    bad[key]['User'] = 'haproxy'
                elif key == 'command':
                    bad[key].insert(bad[key].index('--'), '--property=User=haproxy')
                else:
                    bad[key] = 'untrusted'
                with self.subTest(phase=phase, key=key), self.assertRaisesRegex(
                        self.D.Unsupported, 'control-plan:' + key):
                    c.validate_control(probe, bad)
            bad = copy.deepcopy(good)
            bad['argv'] = ['/bin/true']
            bad['command'] = self.D.transient_command(bad['unit'], bad['properties'], bad['argv'])
            with self.assertRaises(self.D.Unsupported):
                c.validate_control(dict(probe, ExecStart=exec_property(bad['argv'])), bad)

    def test_control_effective_root_security_and_capability_widening_are_not_authorized(self):
        for old in (True, False):
            c = self.controller(old)
            plan = self.control(c)
            good = self.control_probe(c, plan)
            for key, value in (('User', 'haproxy'), ('Group', 'haproxy'),
                               ('NoNewPrivileges', 'no'), ('SystemCallFilter', '@mount'),
                               ('AmbientCapabilities', 'CAP_SETUID'), ('RootDirectory', '/tmp'),
                               ('CapabilityBoundingSet', ' '.join(sorted(c.caps | {'CAP_SYS_ADMIN'})))):
                with self.subTest(old=old, key=key), self.assertRaisesRegex(self.D.Unsupported, key):
                    c.validate_control(dict(good, **{key: value}), plan)
            if old:
                widened = dict(good, CapabilityBoundingSet=' '.join(sorted(CAPS4)))
                # This validator must bind the effective set to this source's
                # plan, not merely accept either globally supported profile.
                with self.assertRaisesRegex(self.D.Unsupported, 'CapabilityBoundingSet'):
                    c.validate_control(widened, plan)
                audit = c.audit_compatibility(c.source, widened, fragment=c.fragment, plan=plan)
                self.assertFalse(audit['ok'])
                self.assertIn('CapabilityBoundingSet', audit['unsupported'])
                bad = copy.deepcopy(plan)
                bad['properties']['CapabilityBoundingSet'] = ' '.join(sorted(CAPS4))
                bad['command'] = self.D.transient_command(bad['unit'], bad['properties'], bad['argv'])
                with self.assertRaisesRegex(self.D.Unsupported, 'control-plan:'):
                    c.validate_control(widened, bad)

    def test_control_pre_aliases_and_hidden_hooks_cannot_escape_validation(self):
        c = self.controller()
        for phase in ('cap-gated', 'cap-direct'):
            plan = self.control(c, phase)
            good = self.control_probe(c, plan)
            if plan['pre']:
                c.validate_control(dict(good, ExecStartPreEx=good['ExecStartPre']), plan)
            else:
                for key in ('ExecStartPre', 'ExecStartPreEx'):
                    absent = dict(good)
                    absent.pop(key, None)
                    c.validate_control(absent, plan)
            for key in ('ExecStartEx', 'ExecStartPre', 'ExecStartPreEx', 'ExecStopEx', 'ExecCondition'):
                with self.subTest(phase=phase, key=key), self.assertRaisesRegex(self.D.Unsupported, key):
                    c.validate_control(dict(good, **{key: exec_property(['/bin/true'])}), plan)
            hooks = ('ExecStopEx', 'ExecStartPost', 'ExecReloadEx')
            if phase == 'cap-direct':
                hooks += ('ExecStartPre', 'ExecStartPreEx')
            for key in hooks:
                for form in (None, ['--property=' + key + '='], ['--property', key + '='],
                             ['-p', key + '='], ['-p' + key + '=']):
                    bad = copy.deepcopy(plan)
                    if form is None:
                        bad['properties'][key] = ''
                    else:
                        index = bad['command'].index('--')
                        bad['command'][index:index] = form
                    with self.subTest(phase=phase, key=key, form=form), self.assertRaises(self.D.Unsupported):
                        c.validate_control(good, bad)

    def test_normal_probe_validator_never_accepts_control_or_omitted_gate(self):
        c = self.controller()
        for phase in ('cap-gated', 'cap-direct'):
            plan = self.control(c, phase)
            with self.assertRaisesRegex(self.D.Unsupported, 'probe-command-plan'):
                c.validate_probe(self.control_probe(c, plan), plan)
        for phase in ('plain', 'trace'):
            plan = self.plan(c, phase)
            probe = self.probe(c, plan)
            plan['pre'] = []
            plan['properties'].pop('ExecStartPre')
            plan['command'] = [a for a in plan['command'] if not a.startswith('--property=ExecStartPre=')]
            probe.pop('ExecStartPre')
            with self.assertRaisesRegex(self.D.Unsupported, 'ExecStartPre'):
                c.validate_probe(probe, plan)

    def test_status_requires_inheritable_and_parses_all_five_masks(self):
        raw = CaptureContracts.status_bytes(self).decode()
        raw = raw.replace('CapInh:\t0', 'CapInh:\t80').replace('CapAmb:\t0', 'CapAmb:\tA')
        status = self.D._status(raw)
        self.assertEqual({k: status[k] for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')},
                         dict(CapInh=0x80, CapPrm=0x4e0, CapEff=0x4e0, CapBnd=0x4e0, CapAmb=10))
        for bad in (raw.replace('CapInh:\t80\n', ''), raw + 'CapInh:\t0\n',
                    raw.replace('CapInh:\t80', 'CapInh:\tzz'),
                    raw.replace('CapInh:\t80', 'CapInh:\t' + 'f' * 17)):
            with self.assertRaisesRegex(ValueError, 'proc-status'):
                self.D._status(bad)

    def test_embedded_helpers_emit_presence_only_and_hardcoded_isolated_python_self_exec(self):
        for program in (self.D.BOUNDARY_PROGRAM, self.D.GATE_PROGRAM, self.D.CONTROL_PROGRAM):
            tree = ast.parse(program)
            compile(tree, 'boundary-helper-static-contract', 'exec')
            self.assertIn("'CapInh','CapPrm','CapEff'", program)
            self.assertIn("'CapBnd','CapAmb'", program)
            self.assertIn('len(data) > 8192', program)
            self.assertIn('env_present={n: n in os.environ for n in env}', program)
            self.assertNotIn('os.environ[', program)
            self.assertNotIn('os.environ.get', program)
            self.assertNotIn('subprocess', program)
            self.assertNotIn('socket', program)
        self.assertIn("emit('gate-entry', str(p.parent))", self.D.GATE_PROGRAM)
        self.assertIn("emit('gate-exit', str(p.parent))", self.D.GATE_PROGRAM)
        self.assertIn("emit('control-entry', str(p.parent))", self.D.CONTROL_PROGRAM)
        self.assertIn("emit('after-exec', str(p.parent))", self.D.CONTROL_PROGRAM)
        calls = [n for n in ast.walk(ast.parse(self.D.CONTROL_PROGRAM))
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'execv']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.literal_eval(calls[0].args[0]), '/usr/bin/python3')
        argv = calls[0].args[1].elts
        self.assertEqual([ast.literal_eval(n) for n in argv[:3]], ['/usr/bin/python3', '-I', '-B'])
        self.assertEqual(ast.literal_eval(argv[-1]), 'after-exec')
        self.assertIsInstance(argv[3], ast.Name)
        self.assertEqual(argv[3].id, '__file__')
        self.assertNotIn('execv', self.D.GATE_PROGRAM)

    def test_boundary_records_accept_only_bounded_stage_schema_and_boolean_environment(self):
        c = self.controller()
        records = self.records(c, 'cap-gated')
        self.assertEqual([r['stage'] for r in records],
                         ['gate-entry', 'gate-exit', 'control-entry', 'after-exec'])
        for r in records:
            self.assertEqual(r['status']['CapInh'], 0)
            self.assertEqual(r['optional_status'], {'TracerPid': 0, 'Seccomp': 2})
            self.assertEqual(r['env_present'], dict.fromkeys(self.D.ENV_NAMES, False))
        raw = '\n'.join(json.dumps(self.boundary(c, stage=stage)) for stage in
                        ('gate-entry', 'gate-exit', 'control-entry', 'after-exec'))
        self.assertEqual([r['stage'] for r in self.D.boundary_records(raw, str(c.directory / 'cap-gated'))],
                         ['gate-entry', 'gate-exit'])

    def test_boundary_records_discard_wrong_tokens_stages_duplicate_keys_and_bad_records(self):
        c = self.controller()
        good = self.boundary(c)
        bad = [dict(good, token='wrong'), dict(good, tag='wrong'), dict(good, stage='pre-exec'),
               dict(good, exe='/tmp/python3'), dict(good, status='not status'),
               dict(good, status=good['status'].replace('CapInh:\t0\n', '')),
               dict(good, env_present=dict.fromkeys(self.D.ENV_NAMES, 'PRIVATE_ENV_VALUE')),
               dict(good, env_present=dict.fromkeys(self.D.ENV_NAMES, 0)),
               dict(good, env_present={}), dict(good, extra='PRIVATE_EXTRA'), [], None]
        lines = [json.dumps(r) for r in bad]
        lines += ['{"tag":"shadow",' + json.dumps(good)[1:],
                  json.dumps(good).replace('"LD_PRELOAD": false', '"LD_PRELOAD": false, "LD_PRELOAD": true'),
                  'not-json', json.dumps(good) + ' ' * 8193]
        for line in lines:
            with self.subTest(kind=line[:30]):
                self.assertEqual(self.D.boundary_records(line, good['token'], control=True), [])
        accepted = self.D.boundary_records('\n'.join(lines + [json.dumps(good)]), good['token'], control=True)
        self.assertEqual(len(accepted), 1)
        self.assertNotIn('PRIVATE_', json.dumps(accepted))

    def test_trace_selector_counts_capset_once_and_prctl_queries_do_not_imply_mutation(self):
        c = self.controller()
        plan = self.plan(c, 'trace')
        selectors = [a for a in plan['argv'] if a.startswith('trace=')]
        self.assertEqual(len(selectors), 1)
        self.assertEqual(selectors[0][6:].split(',').count('capset'), 1)
        self.assertEqual(self.D.SYSCALLS.count('capset'), 1)
        query = self.D.sanitise_trace('prctl(0x17, 0x7, 0, 0, 0) = 1\ngetuid() = 0\n')
        self.assertEqual(query, dict(available=True, identity_calls=1, records=2, capset_records=0, counts=[]))
        caps = self.D.sanitise_trace('capset(0, 0) = 0\ncapset(0, 0) = -1 EPERM (private)\n'
                                     '<... capset resumed>) = 0\ncapset(0 <unfinished ...>\n')
        self.assertEqual(caps, dict(available=False, identity_calls=0, records=3, capset_records=3,
                                   counts=[dict(syscall='capset', errno='EPERM', count=1)]))
        c.factory = Mock(return_value=plan)
        c.show = Mock(return_value={'LoadState': 'loaded'})
        c.command = Mock()
        with patch.object(self.D, '_no_lock'), self.assertRaisesRegex(self.D.Unsupported, 'unit-name-conflict'):
            c.run_phase('trace')
        evidence = next(call.args[1] for call in c.record.call_args_list if call.args[0] == 'trace/selector.json')
        self.assertEqual(evidence['capset_selector_count'], 1)
        self.assertIn('prctl 0x17 is PR_CAPBSET_READ (query, not mutation)', evidence['notes'])
        c.command.assert_not_called()

    def test_fixed_snapshot_limits_pid_and_anchors_bounded_reads_with_presence_only_environment(self):
        with patch.object(os, 'getpid', return_value=99), patch.object(os, 'open') as opening:
            with self.assertRaisesRegex(ValueError, 'fixed-pid'):
                self.D.fixed_snapshot(100)
        opening.assert_not_called()
        for pid in (1, 99):
            opened, streams, sizes = [], [], []
            class BoundedStream(io.BytesIO):
                def read(stream, size=-1):
                    self.assertIn(size, (4097, 65537))
                    sizes.append(size)
                    return super().read(size)
            def opening(path, flags, *, dir_fd=None):
                opened.append((path, flags, dir_fd))
                if path == '/proc/' + str(pid):
                    self.assertEqual(flags, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    self.assertIsNone(dir_fd)
                    return 10
                self.assertEqual(dir_fd, 10)
                self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW)
                self.assertIn(path, ('stat', 'status'))
                return 11 if path == 'stat' else 12
            def fdopen(fd, mode):
                self.assertEqual(mode, 'rb')
                data = (CaptureContracts.stat_bytes(self, pid) if fd == 11 else
                        CaptureContracts.status_bytes(self, pid))
                stream = BoundedStream(data)
                streams.append(stream)
                return stream
            with patch.object(os, 'getpid', return_value=99), \
                    patch.object(os, 'open', side_effect=opening), patch.object(os, 'fdopen', side_effect=fdopen), \
                    patch.object(os, 'readlink', return_value='/usr/bin/python3.12') as link, \
                    patch.object(os, 'close') as close, \
                    patch.dict(os.environ, {'LD_PRELOAD': 'PRIVATE_ENV_VALUE'}, clear=True):
                snapshot = self.D.fixed_snapshot(pid, environment=True)
            self.assertTrue(snapshot['available'])
            self.assertEqual(snapshot['status']['Pid'], pid)
            self.assertEqual(snapshot['status']['CapInh'], 0)
            self.assertTrue(snapshot['env_present']['LD_PRELOAD'])
            self.assertFalse(snapshot['env_present']['PYTHONPATH'])
            self.assertNotIn('PRIVATE_ENV_VALUE', json.dumps(snapshot))
            self.assertEqual([p for p, _, _ in opened], ['/proc/' + str(pid), 'stat', 'status', 'stat'])
            self.assertEqual(link.call_count, 2)
            link.assert_called_with('exe', dir_fd=10)
            close.assert_called_once_with(10)
            self.assertTrue(all(s.closed for s in streams))
            self.assertEqual(sizes, [4097, 65537, 4097])

    def test_executable_metadata_trusts_only_root_symlinks_and_distinguishes_missing_filecap_from_denial(self):
        file = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=0,
                               st_nlink=1, st_dev=2, st_ino=3, st_size=4, st_mtime_ns=5)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
        for refusal in (None, 'link-owner', 'parent-owner', 'parent-writable'):
            for error in (errno.ENODATA, errno.EPERM):
                def info(path):
                    if str(path) == '/usr/bin/python3':
                        return SimpleNamespace(**{**vars(link), 'st_uid': 1000 if refusal == 'link-owner' else 0})
                    if str(path) == '/usr/bin/python3.12':
                        return file
                    if str(path) == '/usr/bin' and refusal == 'parent-owner':
                        return SimpleNamespace(**{**vars(directory), 'st_uid': 1000})
                    if str(path) == '/usr/bin' and refusal == 'parent-writable':
                        return SimpleNamespace(**{**vars(directory), 'st_mode': stat.S_IFDIR | 0o777})
                    return directory
                with patch.object(Path, 'lstat', autospec=True, side_effect=info), \
                        patch.object(Path, 'stat', autospec=True, side_effect=info), \
                        patch.object(os, 'readlink', return_value='python3.12'), \
                        patch.object(os, 'open', return_value=20) as opening, \
                        patch.object(os, 'fstat', return_value=file), patch.object(os, 'close') as close, \
                        patch.object(os, 'getxattr', side_effect=OSError(error, 'PRIVATE_XATTR')) as xattr:
                    result = self.D.executable_metadata('/usr/bin/python3')
                with self.subTest(refusal=refusal, error=error):
                    if refusal:
                        self.assertFalse(result['available'])
                        opening.assert_not_called()
                        close.assert_not_called()
                    else:
                        self.assertTrue(result['available'])
                        self.assertEqual(result['resolved'], '/usr/bin/python3.12')
                        self.assertEqual(result['filecap'], {'available': error == errno.ENODATA,
                                         'present': False if error == errno.ENODATA else None, 'errno': error})
                        opening.assert_called_once_with(Path('/usr/bin/python3.12'),
                                                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        xattr.assert_called_once_with(20, 'security.capability')
                        close.assert_called_once_with(20)
                    self.assertNotIn('PRIVATE_XATTR', json.dumps(result))

    def test_prepare_cap_boundaries_keeps_root_arch_pid1_and_os_checks(self):
        for stage in ('root', 'arch', 'pid1', 'os'):
            c = self.D.Controller()
            c.command = Mock()
            with ExitStack() as stack:
                for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                    stack.enter_context(patch.object(os, name, return_value=1000 if stage == 'root' else 0))
                stack.enter_context(patch.object(platform, 'machine', return_value='aarch64' if stage == 'arch' else 'x86_64'))
                stack.enter_context(patch.object(Path, 'read_text', return_value='other' if stage == 'pid1' else 'systemd'))
                stack.enter_context(patch.object(self.D, '_read_private_source', return_value=(b'ID=ubuntu\nVERSION_ID=22.04\n', {})))
                snapshot = stack.enter_context(patch.object(self.D, 'fixed_snapshot'))
                with self.subTest(stage=stage), self.assertRaises(self.D.Unsupported):
                    c.prepare(cap_boundaries=True)
            snapshot.assert_not_called()
            c.command.assert_not_called()
            self.assertIsNone(c.directory)

    def test_prepare_cap_boundaries_audits_source_without_haproxy_vv_strace_or_accounts(self):
        c = self.controller(True)
        c.command = Mock(side_effect=AssertionError('No inventory command in controls mode'))
        c._audit_show = Mock(return_value=c.source)
        c._audit_fragment = Mock(return_value=(c.source_bytes, c.fragment, []))
        with ExitStack() as stack:
            for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
                stack.enter_context(patch.object(os, name, return_value=0))
            stack.enter_context(patch.object(platform, 'machine', return_value='x86_64'))
            stack.enter_context(patch.object(Path, 'read_text', return_value='systemd'))
            private = stack.enter_context(patch.object(self.D, '_read_private_source',
                                                      return_value=(b'ID=ubuntu\nVERSION_ID=24.04\n', {})))
            snapshots = stack.enter_context(patch.object(self.D, 'fixed_snapshot', return_value={'available': False}))
            stack.enter_context(patch.object(self.D, '_no_lock'))
            stack.enter_context(patch.object(self.D, '_secure_path'))
            stack.enter_context(patch.object(os, 'umask'))
            stack.enter_context(patch.object(tempfile, 'mkdtemp', return_value=str(c.directory)))
            stack.enter_context(patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)))
            metadata = stack.enter_context(patch.object(self.D, 'executable_metadata', return_value={'available': False}))
            c.prepare(cap_boundaries=True)
        private.assert_called_once_with('/usr/lib/os-release', 65536)
        self.assertEqual(snapshots.call_count, 2)
        self.assertEqual(c.caps, CAPS3)
        c.command.assert_not_called()
        c._audit_show.assert_called_once_with(MAIN, [])
        self.assertIn('/usr/bin/python3', [call.args[0] for call in metadata.call_args_list])
        saved = {call.args[0]: call.args[1] for call in c.save.call_args_list}
        self.assertEqual(saved['gate.py'], self.D.GATE_PROGRAM)
        self.assertEqual(saved['control.py'], self.D.CONTROL_PROGRAM)
        self.assertIsNone(c.uid)
        self.assertIsNone(c.gid)

    def test_control_gate_requires_both_effective_snapshots_before_exact_release(self):
        for phase in ('cap-gated', 'cap-direct'):
            for changed in (False, True):
                c = self.controller(True)
                plan = self.control(c, phase)
                probe = self.control_probe(c, plan)
                live = dict(probe, NoNewPrivileges='no') if changed else dict(probe)
                c.save.reset_mock()
                c.read_boundaries = Mock(return_value=self.records(c, phase))
                with self.subTest(phase=phase, changed=changed):
                    if changed:
                        with self.assertRaisesRegex(self.D.Unsupported, 'NoNewPrivileges'):
                            self.gate(c, plan, probe=probe, live=live)
                        c.save.assert_not_called()
                    else:
                        self.gate(c, plan, probe=probe, live=live)
                        c.save.assert_called_once_with(phase + '/' + ('control-go' if phase == 'cap-direct' else 'go'), b'')
                        audits = {call.args[0]: call.args[1] for call in c.record.call_args_list}
                        self.assertTrue(audits[phase + '/comparison.json']['ok'])
                        self.assertTrue(audits[phase + '/live-comparison.json']['ok'])

    def test_run_controls_orders_intent_audits_helper_and_cleans_up_incomplete_sequences(self):
        for incomplete in (False, True):
            c = self.controller()
            c.command = Mock()
            c.cleanup_one = Mock(return_value=True)
            profiles = {p: self.control_probe(c, self.control(c, p)) for p in ('cap-gated', 'cap-direct')}
            for p in profiles.values():
                p.update(ActiveState='active', SubState='running', ControlPID='0', MainPID='42')
            c.gate = Mock(side_effect=lambda plan: profiles[plan['phase']])
            c.show = Mock(side_effect=lambda unit, **kw: {'LoadState': 'not-found'} if kw.get('absent')
                          else profiles['cap-gated' if '-cap-gated.' in unit else 'cap-direct'])
            counts = collections.Counter()
            def reading(plan):
                phase = plan['phase']
                counts[phase] += 1
                records = self.records(c, phase)
                if counts[phase] == 1 and phase == 'cap-gated':
                    return records[:-1]
                return records[1:] if incomplete and phase == 'cap-gated' else records
            c.read_boundaries = Mock(side_effect=reading)
            def command(argv):
                unit = next(a.split('=', 1)[1] for a in argv if a.startswith('--unit='))
                self.assertIn(unit, c.intents)
                self.assertEqual(c.record.call_args.args[0],
                                 ('cap-gated' if '-cap-gated.' in unit else 'cap-direct') + '/intent.json')
                return 0, b'', b''
            c.command.side_effect = command
            with patch.object(Path, 'mkdir') as mkdir, patch.object(self.D, '_no_lock'), \
                    patch.object(time, 'monotonic', return_value=1), patch.object(time, 'sleep'):
                outcomes = c.run_controls()
            self.assertEqual(outcomes, {'cap-gated': 'unavailable' if incomplete else 'recorded', 'cap-direct': 'recorded'})
            self.assertEqual(c.intents, [])
            self.assertEqual(c.cleanup_one.call_count, 2)
            self.assertEqual(c.command.call_count, 2)
            self.assertEqual(mkdir.call_count, 2)
            self.assertIn('cap-gated/control-go', [call.args[0] for call in c.save.call_args_list])
            self.assertNotIn('cap-direct/control-go', [call.args[0] for call in c.save.call_args_list])
            names = [call.args[0] for call in c.record.call_args_list]
            self.assertIn('cap-gated/helper-comparison.json', names)
            self.assertEqual('boundaries.control-comparison.json' in names, not incomplete)
            results = {call.args[0]: call.args[1] for call in c.record.call_args_list
                       if call.args[0].endswith('/control-result.json')}
            self.assertEqual(results['cap-gated/control-result.json'],
                             {'status': 'unavailable', 'issues': ['control-record-sequence']}
                             if incomplete else {'status': 'recorded'})
            self.assertEqual(results['cap-direct/control-result.json'], {'status': 'recorded'})

    def test_boundary_report_excludes_independent_contexts_and_nonroot_workers_from_headline(self):
        for healthy_root, expected in ((True, 'not-observed'), (False, 'unavailable')):
            c = self.controller()
            missing = self.D._status(CaptureContracts.status_bytes(self, caps=0).decode())
            worker = self.D._status(CaptureContracts.status_bytes(self, uid=200, gid=201, caps=0).decode())
            c.boundaries = [{'stage': stage, 'status': missing} for stage in ('controller', 'manager')]
            c.boundaries += [{'stage': 'plain:haproxy-worker', 'status': worker},
                             {'stage': 'plain:other', 'available': False}]
            scopes = ['independent-context', 'independent-context', 'unit-nonroot', 'unavailable']
            if healthy_root:
                c.boundaries.append({'stage': 'plain:haproxy-root',
                                     'status': self.D._status(CaptureContracts.status_bytes(self).decode())})
                scopes.append('unit-root')
            with self.subTest(healthy_root=healthy_root):
                self.assertEqual(c.boundary_report(), expected)
                report = c.record.call_args.args[1]
                self.assertEqual(report['first_observed_missing_SETUID_EP'], expected)
                self.assertEqual([r['scope'] for r in report['observations']], scopes)
                self.assertEqual(report['headline_scope'],
                                 'root unit tasks only; independent contexts and non-root workers excluded')

    def test_boundary_report_all_masks_are_observations_not_inheritance_or_cause(self):
        c = self.controller()
        status = self.D._status(CaptureContracts.status_bytes(self).decode())
        c.boundaries = [{'stage': 'controller', 'status': status}]
        c.control_records = {p: self.records(c, p) for p in ('cap-gated', 'cap-direct')}
        c.boundary_plans = [self.control(c, p) for p in ('cap-gated', 'cap-direct')]
        c.read_boundaries = Mock(side_effect=lambda plan: c.control_records[plan['phase']])
        self.assertEqual(c.boundary_report(), 'not-observed')
        report = c.record.call_args.args[1]
        self.assertFalse(report['gated_direct_differ'])
        self.assertEqual(report['ordering'], 'observation stages, not a causal inheritance chain')
        self.assertEqual(report['observations'][0]['SETUID'],
                         dict(CapInh=False, CapPrm=True, CapEff=True, CapBnd=True, CapAmb=False))
        c.control_records['cap-direct'][-1]['status']['CapEff'] = 0
        self.assertEqual(c.boundary_report(), 'cap-direct:after-exec')
        report = c.record.call_args.args[1]
        self.assertTrue(report['gated_direct_differ'])
        self.assertIn('missing masks alone do not establish root cause', report['limits'])

    def test_main_cap_boundary_mode_dispatches_only_controls_and_respects_cleanup(self):
        for recorded, clean in ((True, True), (False, True), (True, False)):
            c = self.controller()
            c.prepare = Mock()
            c.run_controls = Mock(return_value={'cap-gated': 'recorded' if recorded else 'unavailable',
                                                'cap-direct': 'recorded'})
            c.run_phase = Mock(side_effect=AssertionError('No application phase in controls mode'))
            c.cleanup = Mock(return_value=clean)
            c.boundary_report = Mock(return_value='not-observed')
            rc, out, err = self.main_with(c, ['--cap-boundaries'])
            self.assertEqual(rc, 0 if recorded and clean else 2)
            self.assertEqual(err, '')
            c.prepare.assert_called_once_with(cap_boundaries=True)
            c.run_controls.assert_called_once_with()
            c.run_phase.assert_not_called()
            c.cleanup.assert_called_once_with()
            c.boundary_report.assert_called_once_with()
            self.assertIn('control gated/direct:', out)
            self.assertIn('(not a root cause)', out)
            self.assertNotIn('plain startup:', out)
            self.assertNotIn('trace startup:', out)


if __name__ == '__main__':
    unittest.main()
