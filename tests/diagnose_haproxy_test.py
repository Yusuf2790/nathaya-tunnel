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
from types import ModuleType
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
                  'stat', 'lstat', 'access', 'listdir', 'scandir',
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
            'ExecStart': exec_property(plan['argv']), 'ExecStartPre': exec_property(plan['pre']),
            'ExecReload': '',
        })
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

    def main_with(self, c):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(self.D, 'Controller', return_value=c), patch.object(signal, 'signal'), \
                patch.object(sys, 'stdout', out), patch.object(sys, 'stderr', err):
            rc = self.D.main(['--run'])
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
        self.assertIn('1:--run) ;;', prefix)
        self.assertIn('exec /usr/bin/env -i PATH=', prefix)  # TERM/INT reach controller PID.
        self.assertIn('/usr/bin/python3 -I -B - --run', prefix)
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
        for key in ('User', 'SystemCallFilter', 'ExecStartPre'):
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
                                 'counts': [{'syscall': 'setgid', 'errno': 'EINVAL', 'count': 2},
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
                f'CapEff:\t{caps:x}\nCapPrm:\t{caps:x}\nCapBnd:\t4e0\n'
                'CapAmb:\t0\nNoNewPrivs:\t1\n').encode()

    def virtual_capture(self, c, unit=None, changes=None, procs=b'101\n', links=None,
                        extra=None, save_error=False, read_error=None):
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
                result = c.capture(unit, 'plain/sample-000')
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
        for clock, inactive in ((10, False), ([1, 1, 1, 4], False), (1, True)):
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


if __name__ == '__main__':
    unittest.main()
