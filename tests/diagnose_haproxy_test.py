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
from contextlib import ExitStack, contextmanager
from functools import wraps
import copy
import errno
import grp
import hashlib
import importlib.util
import io
import json
import linecache
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import shlex
import signal
import socket
import stat
import subprocess
import tempfile
import time
import traceback
from types import FunctionType, ModuleType, SimpleNamespace
import unittest
import urllib.request
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
# Checkout source reads happen during discovery or unguarded failure reporting.
# No renderer CLI, load_ports(), account lookup, runtime path or probe is invoked.
SHELL = (ROOT / 'tools/diagnose-haproxy.sh').read_text(encoding='utf-8')
MARKER = 'NATHAYA_HAPROXY_DIAG_PY'
OPENERS = list(re.finditer(r"<<[ \t]*'" + MARKER + r"'[ \t]*\n", SHELL))
DELIMITERS = list(re.finditer(r'(?m)^' + MARKER + r'$', SHELL))
if len(OPENERS) != 1 or len(DELIMITERS) != 1 or OPENERS[0].end() >= DELIMITERS[0].start():
    raise AssertionError('Expected exactly one quoted diagnostic heredoc')
START = OPENERS[0].group(0)
PYTHON = SHELL[OPENERS[0].end():DELIMITERS[0].start()].removesuffix('\n')
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
    text = HostBoundary().invoke(
        R.render_core, 'vpn.example.org', copy.deepcopy(PORTS),
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


class HostBoundary:
    """Deny host effects only during diagnostic execution, never reporting.

    Reentrant calls share the outer guards and its explicit in-memory fakes.
    Every stack unwinds before exceptions reach assertRaises/subTest/unittest.
    """
    def __init__(self):
        self.depth = 0

    @contextmanager
    def guard(self, patchers=()):
        with ExitStack() as stack:
            outer = self.depth == 0
            self.depth += 1
            try:
                if outer:
                    self._deny(stack)
                for patcher in patchers:
                    stack.enter_context(patcher)
                yield
            finally:
                self.depth -= 1

    @staticmethod
    def _deny(stack):
        def forbidden(*args, **kwargs):
            raise AssertionError('Real host operation forbidden in diagnostic fixtures')
        # Blanket filesystem denial, including /proc and temporary files.
        targets = (
            (builtins, ('open',)), (io, ('open',)),
            # Python 3.9/3.10 pathlib accessors cache OS functions, so the OS
            # guards alone cannot deny these filesystem gateways.
            (Path, ('open', 'stat', 'lstat', 'mkdir', 'unlink', 'rmdir', 'rename',
                    'replace', 'chmod', 'lchmod', 'touch', 'symlink_to', 'link_to',
                    'hardlink_to', 'readlink', 'resolve', 'exists', 'is_dir', 'is_file')),
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
                    if obj is Path:
                        # A function keeps later invocation-local autospec
                        # fakes usable; autospec cannot replace a Mock guard.
                        stack.enter_context(patch.object(obj, name, new=forbidden))
                    else:
                        stack.enter_context(patch.object(obj, name, side_effect=forbidden))
        stack.enter_context(patch.object(secrets, 'token_hex', return_value=NONCE))

    def invoke(self, operation, /, *args, patchers=(), **kwargs):
        with self.guard(patchers):
            return operation(*args, **kwargs)

    def wrap(self, operation):
        @wraps(operation)
        def guarded(*args, **kwargs):
            return self.invoke(operation, *args, **kwargs)
        return guarded

    def wrap_module(self, module):
        # Preserve classes (especially exceptions), imported APIs and descriptors.
        for name, value in list(vars(module).items()):
            if isinstance(value, FunctionType) and value.__module__ == module.__name__:
                setattr(module, name, self.wrap(value))
        for name, value in list(vars(module.Controller).items()):
            if isinstance(value, FunctionType) and value.__module__ == module.__name__:
                setattr(module.Controller, name, self.wrap(value))


class Offline(unittest.TestCase):
    def setUp(self):
        self.host = HostBoundary()
        self.D = ModuleType('nathaya_haproxy_diagnostic_fixture')
        self.D.__file__ = 'diagnose-haproxy.sh:embedded'
        with self.host.guard():
            exec(CODE, self.D.__dict__)
        self.host.wrap_module(self.D)

    def invoke(self, operation, /, *args, patchers=(), **kwargs):
        return self.host.invoke(operation, *args, patchers=patchers, **kwargs)

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
        mkdir = Mock()
        result = self.invoke(c.factory, phase, patchers=(
            patch.object(Path, 'mkdir', mkdir),
            patch.object(c, 'reserve', return_value=(49173, ABSTRACT)),
        ))
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
        self.invoke(c.gate, plan, patchers=(
            patch.object(c, 'show', side_effect=[p, current, p if live is None else live]),
            patch.object(self.D, '_no_lock'),
            patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})),
            patch.object(time, 'monotonic', **(
                {'side_effect': clock} if isinstance(clock, list) else {'return_value': clock})),
        ))

    def main_with(self, c, args=None, *, patchers=()):
        out, err = io.StringIO(), io.StringIO()
        rc = self.invoke(self.D.main, ['--run'] if args is None else args, patchers=(
            patch.object(self.D, 'Controller', return_value=c),
            patch.object(signal, 'signal'),
            patch.object(sys, 'stdout', out), patch.object(sys, 'stderr', err),
        ) + tuple(patchers))
        return rc, out.getvalue(), err.getvalue()


def assert_launcher_contract(case, shell):
    """Check shell structure/tokens, not indentation or continuation layout."""
    openers = list(re.finditer(r"<<[ \t]*'" + MARKER + r"'[ \t]*\n", shell))
    case.assertEqual(len(openers), 1, 'Exactly one quoted heredoc opener')
    closers = list(re.finditer(r'(?m)^' + MARKER + r'$', shell))
    case.assertEqual(len(closers), 1, 'Exactly one heredoc delimiter')
    opener, closer = openers[0], closers[0]
    case.assertLess(opener.end(), closer.start())
    # The dispatch prefix intentionally EXCLUDES the heredoc opener.
    prefix = shell[:opener.start()]
    case.assertNotIn("<<'" + MARKER, prefix)
    flat = re.sub(r'\\\n', '', prefix)
    structure = re.search(
        r'nathaya_diagnose_haproxy_main\s*\(\s*\)\s*\{\s*'
        r'case\s+"\$#:\$\{1-\}"\s+in\s*'
        r'1:--help\s*\)(?P<help>.*?)\s*;;\s*'
        r'1:--run\s*\|\s*1:--cap-boundaries\s*\|\s*1:--cap-matrix\s*\)\s*;;\s*'
        r'\*\s*\)(?P<default>.*?)\s*;;\s*'
        r'esac\s+(?P<dispatch>.*?)\s*\Z', flat, re.S)
    case.assertIsNotNone(structure, 'One-argument allowlist before dispatch')
    help_tokens = shlex.split(structure['help'], posix=False)
    case.assertEqual(help_tokens[:2], ['builtin', 'printf'])
    case.assertEqual(help_tokens[2], "'%s\\n'")
    case.assertEqual(help_tokens[-2:], ['return', '0'])
    case.assertTrue(all(re.fullmatch(r"'[^']*'", arg) for arg in help_tokens[2:-2]))
    case.assertRegex(structure['help'], r'--help\s+is\s+read-only')
    case.assertRegex(structure['default'],
                     r"^\s*builtin\s+printf\s+'%s\\n'\s+'[^']*'\s*>\s*&2\s*;\s*return\s+64\s*$")
    case.assertEqual(shlex.split(structure['dispatch'], posix=False), [
        'exec', '/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
        'LANG=C', 'LC_ALL=C', '/usr/bin/python3', '-I', '-B', '-', '"$1"',
    ])
    case.assertNotRegex(prefix, r'\b(?:source|systemctl|systemd-run|sudo|apt|curl|wget)\b')
    tail = shell[closer.end():]
    case.assertRegex(tail,
                     r'\}\s*if\s+\[\[\s*"\$\{BASH_SOURCE\[0\]\}"\s*==\s*"\$0"\s*\]\]\s*;\s*then\s+'
                     r'nathaya_diagnose_haproxy_main\s+"\$@"\s*fi\s*$')


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
        assert_launcher_contract(self, SHELL)

    def test_launcher_contract_accepts_layout_not_dispatch_changes(self):
        # Text-only variants: never source the shell or launch its Python.
        variants = (
            SHELL.replace(') ;;', ')\n            ;;')
                 .replace('return 64 ;;', 'return\t64\n            ;;')
                 .replace('    exec /usr/bin/env', '\texec\t/usr/bin/env'),
            SHELL.replace('1:--run|1:--cap-boundaries|1:--cap-matrix)',
                          '1:--run | 1:--cap-boundaries | 1:--cap-matrix )')
                 .replace('case "$#:${1-}" in', 'case\t"$#:${1-}"\tin')
                 .replace(' -i PATH=', '  -i\tPATH=')
                 .replace(' -I -B - "$1"', '\t-I  -B\t-  "$1"')
                 .replace("<<'" + MARKER + "'\n", "<<  '" + MARKER + "'  \n"),
        )
        for variant in variants:
            self.assertNotEqual(variant, SHELL, 'Layout mutation must exercise the prefix')
            assert_launcher_contract(self, variant)
        for before, after in (('-i PATH=', 'PATH='), (' -I -B ', ' -B '),
                              ('- "$1"', '- $1'), ('- "$1"', '- "$@"'),
                              ('return 64 ;;', 'return 0 ;;'),
                              ('1:--run|1:--cap-boundaries|1:--cap-matrix)', '*)'),
                              ('\n' + MARKER + '\n', '\n' + MARKER + ' \n'),
                              ('\n' + MARKER + '\n', '\n' + MARKER + '\t\n')):
            mutated = SHELL.replace(before, after)
            self.assertNotEqual(mutated, SHELL, 'Negative mutation must not be a no-op')
            with self.subTest(change=after), self.assertRaises(AssertionError):
                assert_launcher_contract(self, mutated)

    def test_host_guards_reject_accidental_real_operations(self):
        for operation in (lambda: Path('/proc/1/comm').read_text(),
                          lambda: Path('/run/fixture-forbidden').mkdir(),
                          lambda: subprocess.run(['fixture-forbidden']),
                          lambda: socket.socket(), lambda: pwd.getpwnam('haproxy'),
                          lambda: grp.getgrnam('haproxy'), lambda: tempfile.mkdtemp()):
            with self.assertRaisesRegex(AssertionError, 'Real host operation forbidden'):
                self.invoke(operation)

    def test_main_invalid_arguments_never_construct_controller(self):
        factory = Mock()
        for args in ([], ['--help'], ['--run', 'extra'], ['--trace'],
                     ['--cap-matrix', 'extra'], ['--cap-matrix=PrivateTmp']):
            result = self.invoke(self.D.main, args, patchers=(
                patch.object(self.D, 'Controller', factory),
                patch.object(sys, 'stderr', io.StringIO()),
            ))
            self.assertEqual(result, 64)
        factory.assert_not_called()

    def test_rooted_run_on_unsupported_host_stops_before_proc_or_commands(self):
        # Real main + real prepare, fake root identities and unsupported arch.
        c = self.D.Controller()
        c.command = Mock(side_effect=AssertionError('No command before host validation'))
        rc, out, err = self.main_with(c, patchers=tuple(
            patch.object(os, name, return_value=0)
            for name in ('getuid', 'geteuid', 'getgid', 'getegid')
        ) + (patch.object(platform, 'machine', return_value='aarch64'),))
        self.assertEqual(rc, 2)
        self.assertIn('unsupported: root-Ubuntu-24.04-amd64-required', out)
        self.assertEqual(err, '')
        self.assertIsNone(c.directory)
        c.command.assert_not_called()

    def test_non_systemd_pid1_is_inspected_only_through_mock(self):
        c = self.D.Controller()
        read = Mock(return_value='not-systemd\n')
        with self.assertRaisesRegex(self.D.Unsupported, 'systemd-PID1-required'):
            self.invoke(c.prepare, patchers=tuple(
                patch.object(os, name, return_value=0)
                for name in ('getuid', 'geteuid', 'getgid', 'getegid')
            ) + (patch.object(platform, 'machine', return_value='x86_64'),
                 patch.object(Path, 'read_text', read)))
        read.assert_called_once_with()
        self.assertIsNone(c.directory)

    def test_root_systemd_but_unsupported_os_stops_before_tempwork(self):
        c = self.D.Controller()
        c.command = Mock()
        read = Mock(return_value=(b'ID=ubuntu\nVERSION_ID=22.04\n', {}))
        with self.assertRaisesRegex(self.D.Unsupported, 'Ubuntu-24.04-required'):
            self.invoke(c.prepare, patchers=tuple(
                patch.object(os, name, return_value=0)
                for name in ('getuid', 'geteuid', 'getgid', 'getegid')
            ) + (patch.object(platform, 'machine', return_value='x86_64'),
                 patch.object(Path, 'read_text', return_value='systemd\n'),
                 patch.object(self.D, '_read_private_source', read)))
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
        show = Mock(side_effect=[probe, c.source])
        mock_no_lock = Mock(side_effect=self.D.Unsupported(label))
        with self.assertRaises(self.D.Unsupported) as raised:
            self.invoke(c.gate, plan, patchers=(
                patch.object(c, 'show', show),
                patch.object(self.D, '_no_lock', mock_no_lock),
                patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})),
                patch.object(time, 'monotonic', return_value=1),
            ))
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
                show = Mock(side_effect=[probe, c.source, live])
                mock_no_lock = Mock(side_effect=refusals)
                clock = Mock(side_effect=ticks)
                with self.assertRaises(self.D.Unsupported) as raised:
                    self.invoke(c.gate, plan, patchers=(
                        patch.object(c, 'show', show),
                        patch.object(self.D, '_no_lock', mock_no_lock),
                        patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})),
                        patch.object(time, 'monotonic', clock),
                    ))
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
            with self.assertRaises(self.D.Unsupported) as raised:
                self.invoke(c.gate, plan, patchers=(
                    patch.object(self.D, '_no_lock'),
                    patch.object(self.D, '_read_private_source', return_value=(c.source_bytes, {})),
                    patch.object(time, 'monotonic', return_value=1),
                ))
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
        try:
            result = self.invoke(c.capture, unit, sample, patchers=(
                patch.object(os, 'open', side_effect=opening),
                patch.object(os, 'read', side_effect=reading),
                patch.object(os, 'close', side_effect=closing),
                patch.object(os, 'readlink', side_effect=readlink),
            ))
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
        factory = Mock(side_effect=[tcp, unix])
        result = self.invoke(c.reserve, patchers=(
            patch.object(socket, 'socket', factory),
            patch.object(secrets, 'token_hex', return_value='b' * 32),
        ))
        self.assertEqual(result, (49173, ABSTRACT))
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
        runner = Mock(side_effect=exc)
        result = self.invoke(c.command, ['fixture-only'], timeout=99, patchers=(
            patch.object(subprocess, 'run', runner),
        ))
        self.assertEqual(result, (None, b'partial', b'private'))
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
        command = Mock()
        result = self.invoke(c.cleanup_one, plan['unit'], patchers=(
            patch.object(c, 'show', side_effect=[owned, foreign]),
            patch.object(c, 'command', command),
            patch.object(time, 'monotonic', return_value=1),
        ))
        self.assertFalse(result)
        command.assert_called_once_with(['/usr/bin/systemctl', 'stop', '--no-block', plan['unit']])

    def test_plain_is_default_trace_only_after_failure_and_profiles_not_mutated(self):
        for status, phases in (('observed-running', ['plain']), ('unavailable', ['plain']),
                               ('failed', ['plain', 'trace'])):
            c = self.controller(True)
            before = copy.deepcopy((c.source, c.fragment, c.source_bytes, c.caps))
            c.prepare = Mock()
            c.run_phase = Mock(side_effect=[(status, None), ('failed', {'available': False, 'counts': []})])
            c.cleanup = Mock(return_value=True)
            rc, out, err = self.main_with(c, patchers=(
                patch.object(os.path, 'isfile', return_value=True),
                patch.object(self.D, '_secure_path'),
            ))
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
        rc, out, err = self.main_with(c, patchers=(
            patch.object(os.path, 'isfile', return_value=True),
            patch.object(self.D, '_secure_path'),
        ))
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
        rc, out, _ = self.main_with(c, patchers=(
            patch.object(os.path, 'isfile', return_value=False),
        ))
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
        opening = Mock()
        with self.assertRaisesRegex(ValueError, 'fixed-pid'):
            self.invoke(self.D.fixed_snapshot, 100, patchers=(
                patch.object(os, 'getpid', return_value=99),
                patch.object(os, 'open', opening),
            ))
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
            link = Mock(return_value='/usr/bin/python3.12')
            close = Mock()
            snapshot = self.invoke(self.D.fixed_snapshot, pid, environment=True, patchers=(
                patch.object(os, 'getpid', return_value=99),
                patch.object(os, 'open', side_effect=opening),
                patch.object(os, 'fdopen', side_effect=fdopen),
                patch.object(os, 'readlink', link), patch.object(os, 'close', close),
                patch.dict(os.environ, {'LD_PRELOAD': 'PRIVATE_ENV_VALUE'}, clear=True),
            ))
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
                opening = Mock(return_value=20)
                close = Mock()
                xattr = Mock(side_effect=OSError(error, 'PRIVATE_XATTR'))
                result = self.invoke(self.D.executable_metadata, '/usr/bin/python3', patchers=(
                    patch.object(Path, 'lstat', autospec=True, side_effect=info),
                    patch.object(Path, 'stat', autospec=True, side_effect=info),
                    patch.object(os, 'readlink', return_value='python3.12'),
                    patch.object(os, 'open', opening),
                    patch.object(os, 'fstat', return_value=file),
                    patch.object(os, 'close', close), patch.object(os, 'getxattr', xattr),
                ))
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
            snapshot = Mock()
            with self.subTest(stage=stage), self.assertRaises(self.D.Unsupported):
                self.invoke(c.prepare, cap_boundaries=True, patchers=tuple(
                    patch.object(os, name, return_value=1000 if stage == 'root' else 0)
                    for name in ('getuid', 'geteuid', 'getgid', 'getegid')
                ) + (
                    patch.object(platform, 'machine', return_value='aarch64' if stage == 'arch' else 'x86_64'),
                    patch.object(Path, 'read_text', return_value='other' if stage == 'pid1' else 'systemd'),
                    patch.object(self.D, '_read_private_source', return_value=(b'ID=ubuntu\nVERSION_ID=22.04\n', {})),
                    patch.object(self.D, 'fixed_snapshot', snapshot),
                ))
            snapshot.assert_not_called()
            c.command.assert_not_called()
            self.assertIsNone(c.directory)

    def test_prepare_cap_boundaries_audits_source_without_haproxy_vv_strace_or_accounts(self):
        c = self.controller(True)
        c.command = Mock(side_effect=AssertionError('No inventory command in controls mode'))
        c._audit_show = Mock(return_value=c.source)
        c._audit_fragment = Mock(return_value=(c.source_bytes, c.fragment, []))
        private = Mock(return_value=(b'ID=ubuntu\nVERSION_ID=24.04\n', {}))
        snapshots = Mock(return_value={'available': False})
        metadata = Mock(return_value={'available': False})
        self.invoke(c.prepare, cap_boundaries=True, patchers=tuple(
            patch.object(os, name, return_value=0)
            for name in ('getuid', 'geteuid', 'getgid', 'getegid')
        ) + (
            patch.object(platform, 'machine', return_value='x86_64'),
            patch.object(Path, 'read_text', return_value='systemd'),
            patch.object(self.D, '_read_private_source', private),
            patch.object(self.D, 'fixed_snapshot', snapshots),
            patch.object(self.D, '_no_lock'), patch.object(self.D, '_secure_path'),
            patch.object(os, 'umask'),
            patch.object(tempfile, 'mkdtemp', return_value=str(c.directory)),
            patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)),
            patch.object(self.D, 'executable_metadata', metadata),
        ))
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
            mkdir = Mock()
            outcomes = self.invoke(c.run_controls, patchers=(
                patch.object(Path, 'mkdir', mkdir), patch.object(self.D, '_no_lock'),
                patch.object(time, 'monotonic', return_value=1), patch.object(time, 'sleep'),
            ))
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


class CapabilityMatrixContracts(Offline):
    """Synthetic requested-profile experiments, not live capability evidence."""

    KNOBS = ('NoNewPrivileges', 'PrivateTmp', 'ProtectSystem', 'ProtectHome',
             'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectControlGroups',
             'RestrictSUIDSGID', 'LockPersonality', 'RestrictAddressFamilies', 'ReadWritePaths')

    def mx_plan(self, c, enabled=(), index=0):
        return self.D.matrix_plan(c.directory, c.nonce, c.caps, index, enabled)

    def mx_profile(self, c, plan):
        # Show is separate evidence, not the request mapping itself. Individual
        # tests deliberately override this synthetic request-matching default.
        p = self.probe(c, plan)
        p.update({k: plan['properties'][k] for k in self.KNOBS})
        p.update(ActiveState='active', SubState='running', MainPID='101', ControlPID='0')
        return p

    def mx_records(self, c, *, missing=False, nnp=1, phase='mx00'):
        mask = 0x4c0 if c.caps == CAPS3 else 0x4e0
        active = mask & ~0x80 if missing else mask
        raw = CaptureContracts.status_bytes(self, caps=active).decode()
        raw = re.sub(r'CapBnd:\t[0-9a-f]+', 'CapBnd:\t%x' % mask, raw)
        raw = raw.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t%d' % nnp)
        rows = [dict(tag=self.D.BOUNDARY_TAG, stage=stage,
                     token=str(c.directory / phase), status=raw + 'TracerPid:\t0\nSeccomp:\t2\n',
                     exe='/usr/bin/python3.12', env_present=dict.fromkeys(self.D.ENV_NAMES, False))
                for stage in ('control-entry', 'after-exec')]
        return self.D.boundary_records('\n'.join(json.dumps(r) for r in rows),
                                       str(c.directory / phase), control=True)

    @staticmethod
    def python_metadata():
        return dict(available=True, resolved='/usr/bin/python3.12', uid=0, gid=0,
                    mode='0o755', device=2, inode=3, size=4, mtime_ns=5,
                    filecap={'available': True, 'present': False, 'errno': errno.ENODATA})

    def attempt_fixture(self, c, *, missing=False, forced_nnp=False, clean=True,
                        show_nnp=None, proc_nnp=None):
        """Configure IO only; run the REAL matrix_attempt and validators."""
        c.matrix_report = {'attempts': []}
        plan = self.mx_plan(c)
        profile = self.mx_profile(c, plan)
        if forced_nnp or show_nnp is not None:
            profile['NoNewPrivileges'] = 'yes' if show_nnp is None else show_nnp
        records = self.mx_records(c, missing=missing,
                                  nnp=(1 if forced_nnp else 0) if proc_nnp is None else proc_nnp)
        c.matrix_source = Mock(return_value=c.source)
        c.matrix_python = Mock(return_value=self.python_metadata())
        c.show = Mock(side_effect=[{'LoadState': 'not-found'}, profile, dict(profile),
                                  {'LoadState': 'not-found'}])
        c.read_boundaries = Mock(side_effect=[records[:1], records])
        c.command = Mock(return_value=(0, b'', b''))
        c.cleanup_one = Mock(return_value=clean)
        c.reserve = Mock(side_effect=AssertionError('No matrix listener reservation'))
        patchers = (patch.object(Path, 'mkdir'), patch.object(self.D, '_no_lock'),
                    patch.object(time, 'monotonic', return_value=1))
        return plan, profile, records, patchers

    def schedule(self, missing, *, unstable=False):
        """Mock attempts, not the scheduler/edge comparator. Copy raw show data."""
        c = self.controller()
        requests = []
        counts = collections.Counter()

        def attempt(enabled):
            requested = frozenset(enabled)
            counts[requested] += 1
            plan = self.mx_plan(c, enabled, len(requests))
            c.matrix_plans[plan['phase']] = plan
            requests.append(requested)
            absent = missing(requested)
            if unstable and counts[requested] > 1:
                absent = not absent
            nnp = int('NoNewPrivileges' in requested)
            records = self.mx_records(c, missing=absent, nnp=nnp, phase=plan['phase'])
            result = dict(phase=plan['phase'], enabled=list(plan['enabled']),
                          profile=copy.deepcopy(self.mx_profile(c, plan)),
                          state=self.D.matrix_entry_state(records, c.caps, '/usr/bin/python3.12'),
                          layers={'NoNewPrivileges': {'requested': plan['properties']['NoNewPrivileges'],
                                                      'show': plan['properties']['NoNewPrivileges'],
                                                      'proc_entry': nnp, 'proc_after_exec': nnp}},
                          actual_NNP_off=not bool(nnp))
            c.matrix_report['attempts'].append(dict(phase=plan['phase'], enabled=list(plan['enabled']),
                                                    status='recorded', missing=absent))
            return result

        c.matrix_attempt = Mock(side_effect=attempt)
        return c, requests, (
            patch.object(self.D, 'executable_metadata', return_value=self.python_metadata()),
            # Scheduler-only fixtures have no host manager evidence. Do not
            # turn an unqueried version into a fabricated v255 proof.
            patch.object(c, 'matrix_mount_manager', return_value={'available': False}),
        )

    def test_fixed_eleven_explicit_off_and_source_production_on_plans_are_immutable(self):
        self.assertEqual(self.D.MATRIX_KNOBS, self.KNOBS)
        self.assertEqual(len(self.KNOBS), 11)
        for old, mask in ((True, 0x4c0), (False, 0x4e0)):
            c = self.controller(old)
            before = copy.deepcopy((c.source, c.fragment, c.source_bytes, c.caps))
            minimal, production = self.mx_plan(c), self.mx_plan(c, self.KNOBS, 1)
            for key in self.KNOBS:
                self.assertEqual(minimal['properties'][key],
                                 '' if key in ('RestrictAddressFamilies', 'ReadWritePaths') else 'no')
                self.assertEqual(production['properties'][key], c.source[key])
            for plan in (minimal, production):
                p = plan['properties']
                self.assertEqual(frozenset(p['CapabilityBoundingSet'].split()), c.caps)
                self.assertEqual(sum(1 << self.D.CAP_BITS[k] for k in c.caps), mask)
                self.assertEqual((p['User'], p['Group'], p['AmbientCapabilities']), ('root', 'root', ''))
                self.assertEqual({k: p[k] for k in ('RuntimeMaxSec', 'TimeoutStartSec', 'TimeoutStopSec',
                                                   'TimeoutAbortSec', 'WatchdogSec', 'Restart')},
                                 dict(RuntimeMaxSec='8s', TimeoutStartSec='5s', TimeoutStopSec='2s',
                                      TimeoutAbortSec='2s', WatchdogSec='0', Restart='no'))
                self.assertEqual(plan['required_effective_defaults'], {'SecureBits': '0', 'SystemCallFilter': '~'})
                self.assertEqual(plan['pre'], [])
                self.assertEqual(plan['argv'], ['/usr/bin/python3', '-I', '-B',
                                 str(c.directory / 'control.py'), str(plan['control_go'])])
                self.assertEqual(plan['command'], self.D.transient_command(plan['unit'], p, plan['argv']))
                for key in ('StandardOutput', 'StandardError'):
                    self.assertEqual(p[key], 'append:' + str(plan['output']))
                for forbidden in ('/usr/sbin/haproxy', '/usr/bin/strace', '/bin/sh', 'abns@', '127.0.0.1', '-c'):
                    self.assertNotIn(forbidden, plan['command'])
            self.assertEqual((c.source, c.fragment, c.source_bytes, c.caps), before)

    def test_all_twenty_eight_roles_are_owned_and_unknown_inputs_rejected(self):
        c = self.controller()
        for index in range(28):
            plan = self.mx_plan(c, index=index)
            profile = self.mx_profile(c, plan)
            self.assertEqual(plan['phase'], 'mx%02d' % index)
            self.assertTrue(self.D.owned_unit(profile, plan['unit'], c.nonce))
            self.assertTrue(self.D._capture_unit(plan['unit'], c.nonce))
            c.validate_matrix(profile, plan)
        for directory, nonce in ((Path('/tmp/foreign'), c.nonce), (c.directory, 'A' * 32),
                                 (c.directory, 'a' * 31), (c.directory, None)):
            with self.subTest(nonce=nonce), self.assertRaises(self.D.Unsupported):
                self.D.matrix_plan(directory, nonce, c.caps, 0, ())
        for index in (-1, 28, 29, True, '0', None):
            with self.subTest(index=index), self.assertRaises(self.D.Unsupported):
                self.mx_plan(c, index=index)
        for enabled in (('FutureKnob',), ('NoNewPrivileges', 'NoNewPrivileges'), 'PrivateTmp', None):
            with self.subTest(enabled=enabled), self.assertRaises(self.D.Unsupported):
                self.mx_plan(c, enabled)
        for role in ('mx28', 'mx99', 'mx1', 'mx000', 'foreign'):
            unit = 'nathaya-haproxy-probe-' + c.nonce + '-' + role + '.service'
            self.assertFalse(self.D._capture_unit(unit, c.nonce))
            self.assertFalse(self.D.owned_unit(self.mx_profile(c, self.mx_plan(c)), unit, c.nonce))
            c.command = Mock()
            with self.assertRaises(self.D.Unsupported):
                c.show(unit)
            c.command.assert_not_called()
        with self.assertRaises(ValueError):
            self.D.matrix_plan(c.directory, c.nonce, CAPS4 | {'CAP_SYS_ADMIN'}, 0, ())

    def test_effective_knobs_require_requested_known_domains_except_implicit_nnp(self):
        c = self.controller()
        off, on = self.mx_plan(c), self.mx_plan(c, self.KNOBS, 1)
        for plan, opposite in ((off, on), (on, off)):
            good = self.mx_profile(c, plan)
            for key in self.KNOBS:
                value = opposite['properties'][key]
                with self.subTest(enabled=plan['enabled'], key=key):
                    self.assertTrue(self.invoke(self.D._matrix_allowed, key, value))
                    changed = dict(good, **{key: value})
                    if key == 'NoNewPrivileges' and plan is off:
                        self.invoke(c.validate_matrix, changed, plan)
                    else:
                        with self.assertRaisesRegex(self.D.Unsupported, '^matrix-effective-value:' + key + '$'):
                            self.invoke(c.validate_matrix, changed, plan)
        # Known aliases are equality, not permission to switch another knob.
        for plan in (off, on):
            aliases = self.mx_profile(c, plan)
            for key in self.KNOBS:
                if aliases[key] in ('yes', 'no'):
                    aliases[key] = 'true' if aliases[key] == 'yes' else 'false'
            if plan is on:
                aliases['RestrictAddressFamilies'] = 'AF_UNIX AF_INET6 AF_INET'
            self.invoke(c.validate_matrix, aliases, plan)
        invalid = [('ReadWritePaths', '/foreign'), ('ReadWritePaths', '/opt/nathaya/logs /foreign'),
                   ('ProtectSystem', 'weird'), ('ProtectSystem', 'yes'),
                   ('RestrictAddressFamilies', 'AF_INET'),
                   ('RestrictAddressFamilies', 'AF_INET AF_INET6'),
                   ('RestrictAddressFamilies', 'AF_INET AF_INET6 AF_UNIX AF_UNIX'),
                   ('RestrictAddressFamilies', 'AF_PACKET')]
        invalid += [(key, 'unknown') for key in self.KNOBS]
        good = self.mx_profile(c, off)
        for key, value in invalid:
            bad = dict(good, **{key: value})
            with self.subTest(key=key, value=value):
                self.assertFalse(self.invoke(self.D._matrix_allowed, key, value))
                with self.assertRaisesRegex(self.D.Unsupported, '^matrix-effective-value:' + key + '$'):
                    self.invoke(c.validate_matrix, bad, off)
                # Even equal unknown values must block variable inventory.
                for left, right in ((good, bad), (bad, good), (bad, dict(bad))):
                    inventory = self.invoke(c.matrix_inventory, left, right, variable=True)
                    self.assertIn(key, inventory['matrix_issues'])
                    row = next(r for r in inventory['properties'] if r['property'] == key)
                    self.assertFalse(row['known_matrix_values'])
                    self.assertEqual(row['classification'], 'matrix-unsupported-value')

    def test_matrix_ownership_defaults_private_append_and_safety_values_remain_mandatory(self):
        for old in (True, False):
            c = self.controller(old)
            plan = self.mx_plan(c)
            good = self.mx_profile(c, plan)
            changes = dict(Id=MAIN, Transient='no', Description='foreign', FragmentPath=FRAGMENT,
                           ControlGroup='/system.slice/foreign.service', User='haproxy', Group='haproxy',
                           SecureBits='1', AmbientCapabilities='CAP_SETUID', UMask='0000',
                           PrivateNetwork='yes', PrivateUsers='yes', RootImage='/foreign',
                           SystemCallFilter='@mount', RuntimeMaxUSec='infinity', Restart='always',
                           TimeoutStartUSec='infinity', TimeoutStopUSec='infinity', TimeoutAbortUSec='infinity',
                           KillMode='process', SendSIGKILL='no', WatchdogUSec='5s',
                           StandardOutput='journal', StandardErrorFile='/opt/nathaya/logs/production.log',
                           CapabilityBoundingSet=' '.join(sorted(c.caps | {'CAP_SYS_ADMIN'})))
            for key, value in changes.items():
                with self.subTest(old=old, key=key), self.assertRaises(self.D.Unsupported):
                    c.validate_matrix(dict(good, **{key: value}), plan)
            for key in self.KNOBS + ('User', 'Group', 'SystemCallFilter', 'WatchdogUSec'):
                bad = dict(good)
                del bad[key]
                with self.subTest(missing=key), self.assertRaises(self.D.Unsupported):
                    c.validate_matrix(bad, plan)
            if old:
                with self.assertRaises(self.D.Unsupported):
                    c.validate_matrix(dict(good, CapabilityBoundingSet=' '.join(sorted(CAPS4))), plan)

    def test_matrix_command_aliases_and_all_unused_hook_declarations_fail_closed(self):
        c = self.controller()
        plan = self.mx_plan(c)
        good = self.mx_profile(c, plan)
        c.validate_matrix(dict(good, ExecStartEx=good['ExecStart']), plan)
        hooks = self.D.PROBE_EMPTY_EXEC_HOOKS + ('ExecStartPre',)
        for name in ('ExecStart',) + hooks:
            for suffix in ('', 'Ex'):
                key = name + suffix
                with self.subTest(key=key), self.assertRaises(self.D.Unsupported):
                    c.validate_matrix(dict(good, **{key: exec_property(['/bin/true'])}), plan)
        for name in hooks:
            for suffix in ('', 'Ex'):
                key = name + suffix
                absent = dict(good)
                absent.pop(key, None)
                c.validate_matrix(absent, plan)
                for form in (None, ['--property=' + key + '='], ['--property', key + '='],
                             ['-p', key + '='], ['-p' + key + '=']):
                    bad = copy.deepcopy(plan)
                    if form is None:
                        bad['properties'][key] = ''
                    else:
                        i = bad['command'].index('--')
                        bad['command'][i:i] = form
                    with self.subTest(key=key, form=form), self.assertRaises(self.D.Unsupported):
                        c.validate_matrix(good, bad)
        for key in ('argv', 'command', 'unit', 'phase', 'go', 'output', 'properties'):
            bad = copy.deepcopy(plan)
            if key == 'argv':
                bad[key] = ['/bin/true']
            elif key == 'command':
                bad[key].append('--unexpected')
            elif key == 'properties':
                bad[key]['RuntimeMaxSec'] = 'infinity'
            else:
                bad[key] = 'foreign'
            with self.subTest(plan_key=key), self.assertRaises(self.D.Unsupported):
                c.validate_matrix(good, bad)

    def test_inventory_covers_every_property_and_only_present_known_knobs_may_vary(self):
        c = self.controller()
        a = self.mx_profile(c, self.mx_plan(c))
        b = self.mx_profile(c, self.mx_plan(c, self.KNOBS, 1))
        before = copy.deepcopy((a, b))
        inventory = c.matrix_inventory(a, b, variable=True)
        self.assertEqual({r['property'] for r in inventory['properties']}, set(a) | set(b))
        self.assertEqual(inventory['matrix_issues'], [])
        self.assertTrue(set(self.KNOBS) <= set(inventory['effective_differences']))
        self.assertEqual((a, b), before)
        for key in ('FutureSecurityKnob', 'SystemCallFilter', 'RootImage', 'MemoryMax',
                    'IPAddressDeny', 'ExecFutureHook', 'NoNewPrivileges'):
            left = dict(a, **{key: 'required'})
            right = dict(left, **{key: 'changed'})
            row = c.matrix_inventory(left, right, variable=True)
            self.assertIn(key, row['matrix_issues'])
            for first, second in ((left, {k: v for k, v in left.items() if k != key}),
                                  ({k: v for k, v in left.items() if k != key}, left)):
                self.assertIn(key, c.matrix_inventory(first, second, variable=True)['matrix_issues'])
        aliases = dict(a, PrivateTmp='false', RestrictAddressFamilies='')
        self.assertEqual(c.matrix_inventory(a, aliases)['matrix_issues'], [])

    def test_matrix_does_not_relax_legacy_production_or_control_gates(self):
        c = self.controller()
        for key in self.KNOBS:
            changed = dict(c.source, **{key: '' if key in ('RestrictAddressFamilies', 'ReadWritePaths') else 'no'})
            with self.subTest(key=key), self.assertRaises(self.D.Unsupported):
                self.D.validate_effective(changed, c.fragment)
        for phase in ('plain', 'trace'):
            plan = self.plan(c, phase)
            with self.assertRaises(self.D.Unsupported):
                c.validate_probe(dict(self.probe(c, plan), NoNewPrivileges='no'), plan)
        for phase in ('cap-gated', 'cap-direct'):
            plan = self.D.control_plan(c.directory, c.nonce, c.caps, phase)
            with self.assertRaises(self.D.Unsupported):
                c.validate_control(dict(self.probe(c, plan), NoNewPrivileges='no'), plan)
        matrix = self.mx_plan(c)
        with self.assertRaises(self.D.Unsupported):
            c.validate_probe(self.mx_profile(c, matrix), matrix)

    def test_entry_setuid_bit_is_bit_seven_not_cap_kill_and_rejects_anomalies(self):
        for old, mask in ((True, 0x4c0), (False, 0x4e0)):
            c = self.controller(old)
            for missing in (False, True):
                records = self.mx_records(c, missing=missing)
                before = copy.deepcopy(records)
                state = self.D.matrix_entry_state(records, c.caps, '/usr/bin/python3.12')
                self.assertEqual(state['missing'], missing)
                self.assertFalse(state['selfexec_capability_changed'])
                self.assertEqual(state['entry'], state['after_exec'])
                self.assertIsNot(state['entry'], state['after_exec'])
                self.assertEqual(state['entry']['CapBnd'], mask)
                self.assertEqual(state['entry']['CapEff'], mask & ~0x80 if missing else mask)
                self.assertEqual(bool(state['entry']['CapEff'] & 0x20), not old)
                self.assertEqual(records, before)
            records = self.mx_records(c)
            for stage in (0, 1):
                for key, value in (('Uid', (0, 1, 0, 0)), ('Gid', (0, 1, 0, 0)),
                                   ('CapBnd', mask | 1), ('CapInh', 0x80), ('CapAmb', 0x80),
                                   ('CapEff', mask | 1), ('CapPrm', mask & ~0x80), ('NoNewPrivs', 2)):
                    bad = copy.deepcopy(records)
                    bad[stage]['status'][key] = value
                    with self.subTest(old=old, stage=stage, key=key), self.assertRaisesRegex(
                            self.D.Unsupported, '^matrix-anomalous-credentials$'):
                        self.invoke(self.D.matrix_entry_state, bad, c.caps, '/usr/bin/python3.12')
            for kind in ('tracer', 'exe', 'environment', 'pid', 'sequence', 'duplicate'):
                bad = copy.deepcopy(records)
                if kind == 'tracer':
                    bad[0]['optional_status']['TracerPid'] = 9
                elif kind == 'exe':
                    bad[0]['exe'] = '/tmp/python3'
                elif kind == 'environment':
                    bad[0]['env_present']['LD_PRELOAD'] = True
                elif kind == 'pid':
                    bad[1]['status']['Pid'] += 1
                elif kind == 'sequence':
                    bad.reverse()
                else:
                    bad.append(copy.deepcopy(bad[-1]))
                with self.subTest(kind=kind), self.assertRaises(self.D.Unsupported):
                    self.D.matrix_entry_state(bad, c.caps, '/usr/bin/python3.12')

    def test_entry_only_optional_coverage_and_selfexec_invariants(self):
        executable = '/usr/bin/python3.12'
        for old, mask in ((True, 0x4c0), (False, 0x4e0)):
            c = self.controller(old)
            for entry_missing in (False, True):
                for after_missing in (False, True):
                    for seccomp in (0, 1, 2):
                        records = self.mx_records(c, missing=entry_missing, nnp=0)
                        after = mask & ~0x80 if after_missing else mask
                        records[1]['status'].update(CapEff=after, CapPrm=after)
                        for record in records:
                            record['optional_status']['Seccomp'] = seccomp
                        with self.subTest(old=old, entry=entry_missing, after=after_missing, seccomp=seccomp):
                            state = self.invoke(self.D.matrix_entry_state, records, c.caps, executable)
                            self.assertEqual(state['missing'], entry_missing)
                            self.assertEqual(state['selfexec_capability_changed'], entry_missing != after_missing)
                            self.assertEqual(state['after_exec']['CapEff'], after)
                            entry = self.invoke(self.D.matrix_entry_state, records[:1], c.caps,
                                                executable, entry_only=True)
                            self.assertEqual(entry['entry'], state['entry'])
                            self.assertEqual(entry['missing'], entry_missing)
                            self.assertIsNone(entry['after_exec'])
                            self.assertIsNone(entry['selfexec_capability_changed'])
            records = self.mx_records(c)
            for wrong in ([], records, records[1:], list(reversed(records))):
                with self.assertRaisesRegex(self.D.Unsupported, '^matrix-record-sequence$'):
                    self.invoke(self.D.matrix_entry_state, wrong, c.caps, executable, entry_only=True)
            for stage in (0, 1):
                for key in ('TracerPid', 'Seccomp'):
                    bad = copy.deepcopy(records)
                    del bad[stage]['optional_status'][key]
                    with self.subTest(old=old, stage=stage, missing=key):
                        with self.assertRaisesRegex(self.D.Unsupported, '^matrix-status-coverage$'):
                            self.invoke(self.D.matrix_entry_state, bad, c.caps, executable)
                        if stage == 0:
                            with self.assertRaisesRegex(self.D.Unsupported, '^matrix-status-coverage$'):
                                self.invoke(self.D.matrix_entry_state, bad[:1], c.caps,
                                            executable, entry_only=True)
                for key, value in (('TracerPid', 9), ('Seccomp', 3)):
                    bad = copy.deepcopy(records)
                    bad[stage]['optional_status'][key] = value
                    with self.assertRaisesRegex(self.D.Unsupported, '^matrix-anomalous-credentials$'):
                        self.invoke(self.D.matrix_entry_state, bad, c.caps, executable)
            for key, value in (('Pid', 202), ('PPid', 2), ('Groups', (0, 1)), ('NoNewPrivs', 0)):
                bad = copy.deepcopy(records)
                bad[1]['status'][key] = value
                with self.subTest(old=old, transition=key), self.assertRaisesRegex(
                        self.D.Unsupported, '^matrix-selfexec-unstable$'):
                    self.invoke(self.D.matrix_entry_state, bad, c.caps, executable)
            bad = copy.deepcopy(records)
            bad[1]['optional_status']['Seccomp'] = 1
            with self.assertRaisesRegex(self.D.Unsupported, '^matrix-selfexec-unstable$'):
                self.invoke(self.D.matrix_entry_state, bad, c.caps, executable)

    def test_selfexec_after_status_is_recorded_not_assumed_identical_to_entry(self):
        c = self.controller()
        records = self.mx_records(c, missing=True, nnp=0)
        records[1]['status'].update(CapEff=0x4e0, CapPrm=0x4e0)
        original = copy.deepcopy(records)
        # A valid later recovery is evidence, not an unstable ENTRY. This
        # regression intentionally requires distinct before/after observations.
        state = self.D.matrix_entry_state(records, c.caps, '/usr/bin/python3.12')
        self.assertTrue(state['missing'])
        self.assertTrue(state['selfexec_capability_changed'])
        self.assertEqual(state['entry']['NoNewPrivs'], 0)
        self.assertEqual(state['entry']['CapEff'], 0x460)
        self.assertEqual(state['after_exec']['CapEff'], 0x4e0)
        self.assertEqual(records, original)
        # The full attempt must retain both observations too, even if the unit
        # has already vanished by the final show read.
        _, _, records, patchers = self.attempt_fixture(c, missing=True)
        records[1]['status'].update(CapEff=0x4e0, CapPrm=0x4e0)
        result = self.invoke(c.matrix_attempt, (), patchers=patchers)
        self.assertTrue(result['state']['missing'])
        self.assertTrue(result['state']['selfexec_capability_changed'])
        self.assertTrue(result['actual_NNP_off'])
        self.assertEqual(result['state']['after_exec']['CapEff'], 0x4e0)
        saved = {call.args[0]: call.args[1] for call in c.record.call_args_list}
        self.assertEqual(saved['mx00/boundaries.json'], records)

    def test_attempt_requested_nnp_no_show_yes_proc_one_is_not_actual_off(self):
        c = self.controller(True)
        plan, profile, records, patchers = self.attempt_fixture(c, missing=True, forced_nnp=True)
        release_evidence = []

        def save(name, content):
            if name.endswith('/control-go'):
                release_evidence.append(dict(
                    records=[call.args[0] for call in c.record.call_args_list],
                    source=[call.args[1] for call in c.matrix_source.call_args_list],
                    python=[call.args[1] for call in c.matrix_python.call_args_list]))
            return c.directory / name

        c.save.side_effect = save
        result = self.invoke(c.matrix_attempt, (), patchers=patchers)
        layer = result['layers']['NoNewPrivileges']
        self.assertEqual((layer['requested'], layer['show'], layer['proc_entry'], layer['proc_after_exec']),
                         ('no', 'yes', 1, 1))
        self.assertFalse(layer['request_matches_show'])
        self.assertTrue(layer['show_matches_proc'])
        self.assertTrue(layer['forced_or_inherited'])
        self.assertFalse(result['actual_NNP_off'])
        self.assertIn('NoNewPrivileges', result['unexpected_requested_values'])
        self.assertEqual(result['state']['entry']['CapEff'], 0x440)
        self.assertEqual(result['state']['entry']['CapBnd'], 0x4c0)
        self.assertEqual(c.matrix_source.call_args_list[0].args[0]['phase'], plan['phase'])
        self.assertEqual([call.args[1] for call in c.matrix_source.call_args_list], ['source-before', 'source-release'])
        self.assertEqual([call.args[1] for call in c.matrix_python.call_args_list], ['before', 'release', 'after'])
        self.assertEqual(len(release_evidence), 1)
        self.assertEqual(release_evidence[0]['source'], ['source-before', 'source-release'])
        self.assertEqual(release_evidence[0]['python'], ['before', 'release'])
        for name in ('entry.json', 'entry.show.json', 'source-comparison.json',
                     'release.show.json', 'release-comparison.json'):
            self.assertIn('mx00/' + name, release_evidence[0]['records'])
        c.command.assert_called_once_with(plan['command'])
        c.cleanup_one.assert_called_once_with(plan['unit'])
        c.reserve.assert_not_called()
        self.assertEqual(c.intents, [])
        self.assertEqual(c.matrix_report['attempts'][0]['status'], 'recorded')
        evidence = {call.args[0]: call.args[1] for call in c.record.call_args_list}
        self.assertEqual(evidence['mx00/boundaries.json'], records)
        self.assertEqual(evidence['mx00/after.show.json'], {'LoadState': 'not-found'})
        self.assertEqual(evidence['mx00/result.json']['profile'], profile)

    def test_attempt_entry_refusals_precede_show_and_nnp_consistency_precedes_go(self):
        # Core/coverage refusals must not even ask for the helper profile, let
        # alone release control-go. All host overrides are invocation-local.
        cases = [('Uid', (0, 1, 0, 0)), ('CapBnd', 0), ('CapEff', 0),
                 ('CapInh', 0x80), ('CapAmb', 0x80), ('NoNewPrivs', 2),
                 ('exe', '/tmp/python3'), ('environment', True),
                 ('TracerPid', None), ('Seccomp', None)]
        for key, value in cases:
            c = self.controller()
            plan, _, records, patchers = self.attempt_fixture(c)
            if key in ('TracerPid', 'Seccomp'):
                del records[0]['optional_status'][key]
                label = 'matrix-status-coverage'
            elif key == 'exe':
                records[0]['exe'] = value
                label = 'matrix-anomalous-credentials'
            elif key == 'environment':
                records[0]['env_present']['PYTHONPATH'] = value
                label = 'matrix-environment-confounded'
            else:
                records[0]['status'][key] = value
                label = 'matrix-anomalous-credentials'
            with self.subTest(entry=key), self.assertRaisesRegex(self.D.Unsupported, '^' + label + '$'):
                self.invoke(c.matrix_attempt, (), patchers=patchers)
            c.show.assert_called_once_with(plan['unit'], absent=True)
            c.read_boundaries.assert_called_once()
            self.assertEqual([call.args[1] for call in c.matrix_python.call_args_list], ['before'])
            evidence = {call.args[0]: call.args[1] for call in c.record.call_args_list}
            self.assertEqual(evidence['mx00/entry.json'], records[:1])
            self.assertNotIn('mx00/entry.show.json', evidence)
            self.assertNotIn('mx00/control-go', [call.args[0] for call in c.save.call_args_list])
            c.cleanup_one.assert_not_called()
        for spelling in ('yes', 'true'):
            c = self.controller()
            plan, profile, records, patchers = self.attempt_fixture(c, show_nnp=spelling, proc_nnp=0)
            with self.subTest(show=spelling), self.assertRaisesRegex(
                    self.D.Unsupported, '^matrix-NNP-inconsistent$'):
                self.invoke(c.matrix_attempt, (), patchers=patchers)
            # Refusal retains the private root process and show evidence, not
            # just a classification with its contradictory inputs discarded.
            evidence = {call.args[0]: call.args[1] for call in c.record.call_args_list}
            self.assertEqual(evidence['mx00/entry.json'], records[:1])
            self.assertEqual(evidence['mx00/entry.show.json'], profile)
            self.assertEqual(profile['User'], 'root')
            self.assertEqual(records[0]['status']['Uid'], (0,) * 4)
            self.assertEqual(c.show.call_count, 2)
            c.read_boundaries.assert_called_once()
            self.assertNotIn('mx00/control-go', [call.args[0] for call in c.save.call_args_list])
            self.assertNotIn('mx00/release.show.json', evidence)
            c.cleanup_one.assert_not_called()
        for spelling, proc_nnp in (('false', 0), ('true', 1)):
            c = self.controller()
            _, _, _, patchers = self.attempt_fixture(c, show_nnp=spelling, proc_nnp=proc_nnp)
            result = self.invoke(c.matrix_attempt, (), patchers=patchers)
            with self.subTest(normalized_show=spelling):
                self.assertEqual(result['actual_NNP_off'], proc_nnp == 0)
                self.assertTrue(result['layers']['NoNewPrivileges']['show_matches_proc'])
                self.assertEqual(result['layers']['NoNewPrivileges']['forced_or_inherited'], proc_nnp == 1)

    def test_attempt_source_python_logs_inventory_and_live_validation_precede_release(self):
        for failure in ('source', 'python', 'sequence', 'environment', 'credentials',
                        'logging', 'unknown', 'live', 'pid'):
            c = self.controller()
            plan, profile, records, patchers = self.attempt_fixture(c)
            if failure == 'source':
                c.matrix_source.side_effect = self.D.Unsupported('fixture-source')
            elif failure == 'python':
                c.matrix_python.side_effect = self.D.Unsupported('fixture-python')
            elif failure == 'sequence':
                c.read_boundaries.side_effect = [records]
            elif failure == 'environment':
                records[0]['env_present']['PYTHONPATH'] = True
            elif failure == 'credentials':
                records[0]['status']['Uid'] = (0, 1, 0, 0)
            elif failure in ('logging', 'unknown'):
                profile['StandardOutputFile' if failure == 'logging' else 'FutureSecurityKnob'] = 'foreign'
            elif failure == 'live':
                c.show.side_effect = [{'LoadState': 'not-found'}, profile, dict(profile, SystemCallFilter='@mount')]
            else:
                profile['MainPID'] = '202'
                c.show.side_effect = [{'LoadState': 'not-found'}, profile, dict(profile)]
            with self.subTest(failure=failure), self.assertRaises(self.D.Unsupported):
                self.invoke(c.matrix_attempt, (), patchers=patchers)
            self.assertNotIn('mx00/control-go', [call.args[0] for call in c.save.call_args_list])
            self.assertEqual(len(c.matrix_report['attempts']), 1)
            self.assertEqual(c.matrix_report['attempts'][0]['status'], 'unavailable')
            c.cleanup_one.assert_not_called()

    def test_source_and_python_revalidation_do_not_invent_unchanged_evidence(self):
        c = self.controller()
        # Production run_matrix owns this initialization before any matrix
        # helper. This isolated helper fixture deliberately bypasses that entry.
        report = {'status': 'unavailable', 'attempts': []}
        c.matrix_report = report
        # Synthetic raw data makes report-row checks non-vacuous. This is not
        # host evidence or a proof of the origin of this mount dependency.
        c.source['RequiresMountsFor'] = '/var/tmp'
        plan = self.mx_plan(c)
        c._audit_fragment = Mock(return_value=(c.source_bytes, c.fragment, []))
        c._audit_show = Mock(return_value=c.source)

        def recorded_comparison(stem):
            saved = {call.args[0]: call.args[1] for call in c.record.call_args_list}
            artifact = 'mx00/' + stem + '.comparison.json'
            audit = saved['mx00/' + stem + '.audit.json']
            inventory = saved[artifact]
            self.assertIs(c.matrix_report, report)
            self.assertIs(inventory, audit['source_profile_change'])
            detail = report['comparisons'][-1]
            self.assertEqual((detail['artifact'], detail['phase'], detail['stage']),
                             (artifact, 'mx00', stem))
            self.assertEqual(detail['roles'], ['production-original', 'production-current'])
            rows = [r for r in inventory['properties'] if r['property'] == 'RequiresMountsFor']
            self.assertEqual(len(rows), 1)
            self.assertEqual(detail['rows'], rows)
            self.assertIs(detail['rows'][0], rows[0])
            self.assertTrue(rows[0]['source_present'])
            self.assertTrue(rows[0]['probe_present'])
            self.assertEqual((rows[0]['source'], rows[0]['probe']), ('/var/tmp', '/var/tmp'))
            self.assertIs(detail['mount_dependency_audit'], inventory['mount_dependency_audit'])
            self.assertFalse(detail['mount_dependency_audit']['verified'])
            return inventory, audit

        self.assertEqual(self.invoke(c.matrix_source, plan, 'before', patchers=(
            patch.object(self.D, '_no_lock'),)), c.source)
        inventory, audit = recorded_comparison('before')
        self.assertTrue(audit['ok'])
        self.assertFalse(inventory['changed'])
        self.assertFalse(inventory['raw_fragment_changed'])
        self.assertEqual(inventory['unsupported'], [])
        self.assertEqual(len(report['comparisons']), 1)
        for kind in ('bytes', 'security', 'missing'):
            count = len(report['comparisons'])
            c._audit_fragment.return_value = (c.source_bytes + (b'\n' if kind == 'bytes' else b''), c.fragment, [])
            c._audit_show.return_value = (None if kind == 'missing' else
                                         dict(c.source, NoNewPrivileges='no') if kind == 'security' else c.source)
            with self.subTest(kind=kind):
                with self.assertRaises(self.D.Unsupported):
                    self.invoke(c.matrix_source, plan, kind, patchers=(patch.object(self.D, '_no_lock'),))
                saved = {call.args[0]: call.args[1] for call in c.record.call_args_list}
                audit = saved['mx00/' + kind + '.audit.json']
                self.assertFalse(audit['ok'])
                if kind == 'missing':
                    self.assertIsNone(saved['mx00/missing.show.json'])
                    self.assertIsNone(audit['source_profile_change'])
                    self.assertEqual(len(report['comparisons']), count)
                    self.assertNotIn('mx00/missing.comparison.json', saved)
                else:
                    inventory, audit = recorded_comparison(kind)
                    self.assertEqual(len(report['comparisons']), count + 1)
                    self.assertTrue(inventory['changed'])
                    self.assertEqual(inventory['raw_fragment_changed'], kind == 'bytes')
                    if kind == 'security':
                        self.assertTrue(audit['validation']['source'])
                        self.assertIn('NoNewPrivileges', inventory['unsupported'])
        c.matrix_python_initial = self.python_metadata()
        self.assertEqual(self.invoke(c.matrix_python, plan, 'before', patchers=(
            patch.object(self.D, 'executable_metadata', return_value=self.python_metadata()),)), self.python_metadata())
        for changed in ({'available': False}, dict(self.python_metadata(), inode=99),
                        dict(self.python_metadata(), filecap={'available': False, 'present': None})):
            with self.assertRaisesRegex(self.D.Unsupported, 'matrix-python-changed'):
                self.invoke(c.matrix_python, plan, 'changed', patchers=(
                    patch.object(self.D, 'executable_metadata', return_value=changed),))
        self.assertIs(c.matrix_report, report)
        self.assertEqual(report['status'], 'unavailable')
        self.assertEqual(report['attempts'], [])
        self.assertEqual(len(report['comparisons']), 3)

    def test_initial_python_filecap_must_be_known_absent_before_any_attempt(self):
        for metadata in ({'available': False}, dict(self.python_metadata(), filecap={}),
                         dict(self.python_metadata(), filecap={'available': False, 'present': None}),
                         dict(self.python_metadata(), filecap={'available': True, 'present': True})):
            c = self.controller()
            c.matrix_attempt = Mock()
            with self.assertRaisesRegex(self.D.Unsupported, 'matrix-python-filecap-unavailable-or-present'):
                self.invoke(c.run_matrix, patchers=(
                    patch.object(c, 'matrix_mount_manager', return_value={'available': False}),
                    patch.object(self.D, 'executable_metadata', return_value=metadata),))
            c.matrix_attempt.assert_not_called()
            self.assertEqual(c.matrix_report['attempts'], [])
        # Actual ENODATA versus EPERM handling is covered by the real metadata
        # API test above; an unknown result is never replaced with this fixture.

    def test_failed_creation_consumes_all_twenty_eight_slots_and_cleanup_failure_stops(self):
        c = self.controller()
        _, _, _, patchers = self.attempt_fixture(c)
        c.show.side_effect = None
        c.show.return_value = {'LoadState': 'not-found'}
        c.command.return_value = (1, b'', b'')
        for index in range(28):
            with self.assertRaisesRegex(self.D.Unsupported, 'transient-create-unavailable'):
                self.invoke(c.matrix_attempt, (), patchers=patchers)
            self.assertEqual(len(c.matrix_report['attempts']), index + 1)
        with self.assertRaisesRegex(self.D.Unsupported, 'matrix-attempt-limit'):
            c.matrix_attempt(())
        self.assertEqual(c.command.call_count, 28)
        self.assertEqual(len(set(c.intents)), 28)
        self.assertTrue(all(row['status'] == 'unavailable' for row in c.matrix_report['attempts']))
        c = self.controller()
        _, _, _, patchers = self.attempt_fixture(c, clean=False)
        with self.assertRaisesRegex(self.D.Unsupported, 'cleanup-unconfirmed'):
            self.invoke(c.run_matrix, patchers=patchers + (
                patch.object(c, 'matrix_mount_manager', return_value={'available': False}),
                patch.object(self.D, 'executable_metadata', return_value=self.python_metadata()),))
        self.assertFalse(c.cleanup_confirmed)
        self.assertEqual(len(c.matrix_report['attempts']), 1)
        self.assertEqual(c.command.call_count, 1, 'No production attempt after unconfirmed cleanup')
        self.assertEqual(len(c.intents), 1)

    def test_scheduler_minimal_already_missing_confirms_and_stops_after_three(self):
        c, requests, patchers = self.schedule(lambda enabled: True)
        self.assertEqual(self.invoke(c.run_matrix, patchers=patchers), 0)
        self.assertEqual(requests, [frozenset(), frozenset(self.KNOBS), frozenset()])
        self.assertEqual(c.matrix_report['status'], 'confirmed-zero-optional-settings')
        self.assertEqual(c.matrix_report['minimum_tested_requested_profile'], [])
        self.assertTrue(any('after Python initialization' in s for s in c.matrix_report['limits']))
        self.assertTrue(any('not a global minimum' in s for s in c.matrix_report['limits']))

    def test_scheduler_nnp_single_repeats_reference_candidate_then_minus_nnp_supplement(self):
        nnp = self.KNOBS[0]
        c, requests, patchers = self.schedule(lambda enabled: nnp in enabled)
        self.assertEqual(self.invoke(c.run_matrix, patchers=patchers), 0)
        self.assertEqual(requests, [frozenset(), frozenset(self.KNOBS), frozenset((nnp,)),
                                    frozenset(), frozenset((nnp,)), frozenset(self.KNOBS[1:])])
        self.assertEqual(c.matrix_report['minimum_tested_requested_profile'], [nnp])
        self.assertFalse(c.matrix_report['interaction']['production_fix_claimed'])
        self.assertFalse(c.matrix_report['interaction']['missing'])
        self.assertEqual(c.matrix_report['status'], 'confirmed-tested-requested-profile')

    def test_scheduler_non_nnp_single_gets_only_nnp_interaction_supplement(self):
        nnp, knob = self.KNOBS[:2]
        c, requests, patchers = self.schedule(lambda enabled: knob in enabled)
        self.assertEqual(self.invoke(c.run_matrix, patchers=patchers), 0)
        self.assertEqual(requests, [frozenset(), frozenset(self.KNOBS), frozenset((nnp,)),
                                    frozenset((knob,)), frozenset(), frozenset((knob,)),
                                    frozenset((nnp, knob))])
        self.assertEqual(c.matrix_report['minimum_tested_requested_profile'], [knob])
        self.assertTrue(c.matrix_report['interaction']['missing'])
        self.assertFalse(c.matrix_report['interaction']['production_fix_claimed'])

    def test_scheduler_nnp_pair_requires_both_healthy_components_and_repeats_pair(self):
        pair = frozenset(self.KNOBS[:2])
        c, requests, patchers = self.schedule(lambda enabled: pair <= enabled)
        self.assertEqual(self.invoke(c.run_matrix, patchers=patchers), 0)
        self.assertEqual(requests[:2], [frozenset(), frozenset(self.KNOBS)])
        self.assertEqual(requests[2:13], [frozenset((k,)) for k in self.KNOBS])
        self.assertEqual(requests[13:], [pair, frozenset((self.KNOBS[1],)), pair])
        self.assertEqual(c.matrix_report['minimum_tested_requested_profile'], sorted(pair))
        self.assertEqual(len(c.matrix_report['interaction']['healthy_components']), 2)
        edges = [call.args[1] for call in c.record.call_args_list if '/against-' in call.args[0]]
        self.assertTrue(all(len(edge['request_delta']) <= 1 for edge in edges))
        self.assertEqual(sum(edge['observation'] == 'mx13' for edge in edges), 2)

    def test_scheduler_none_found_has_only_twenty_three_directed_explorations(self):
        c, requests, patchers = self.schedule(lambda enabled: len(enabled) == 11)
        self.assertEqual(self.invoke(c.run_matrix, patchers=patchers), 2)
        expected = [frozenset(), frozenset(self.KNOBS)] + [frozenset((k,)) for k in self.KNOBS]
        expected += [frozenset((self.KNOBS[0], k)) for k in self.KNOBS[1:]]
        self.assertEqual(requests, expected)
        self.assertEqual(len(requests), 23)
        self.assertLessEqual(len(requests), c.matrix_report['attempt_limit'])
        self.assertEqual(c.matrix_report['status'], 'higher-order-unresolved')
        self.assertIsNone(c.matrix_report['minimum_tested_requested_profile'])
        c, requests, patchers = self.schedule(lambda enabled: False)
        self.assertEqual(self.invoke(c.run_matrix, patchers=patchers), 2)
        self.assertEqual(len(requests), 2)
        self.assertEqual(c.matrix_report['status'], 'not-reproduced-inconclusive')

    def test_scheduler_unstable_repeat_aborts_before_candidate_or_supplement_continuation(self):
        c, requests, patchers = self.schedule(lambda enabled: self.KNOBS[0] in enabled, unstable=True)
        with self.assertRaisesRegex(self.D.Unsupported, 'matrix-repeat-unstable'):
            self.invoke(c.run_matrix, patchers=patchers)
        self.assertEqual(len(requests), 4)
        self.assertNotIn('interaction', c.matrix_report)
        # Repetition also rejects a full-inventory change with unchanged masks.
        a = c.matrix_attempt(self.KNOBS[:1])
        b = copy.deepcopy(a)
        b['profile']['FutureSecurityKnob'] = 'changed'
        with self.assertRaises(self.D.Unsupported):
            c.matrix_edge(a, b, repeat=True)
        b = copy.deepcopy(a)
        b['enabled'] = list(self.KNOBS[1:3])
        with self.assertRaisesRegex(self.D.Unsupported, 'matrix-request-delta'):
            c.matrix_edge(a, b)

    # These are deliberately complete SYNTHETIC mount contexts, not recovered
    # VPS values. The workspace has only partial watchdog evidence and synthetic
    # snapshots; the archive is uninspected and its provenance remains unknown.
    MOUNT_PRODUCERS = ('WorkingDirectory', 'RootDirectory', 'RootImage',
                       'RuntimeDirectory', 'StateDirectory', 'CacheDirectory',
                       'LogsDirectory', 'ConfigurationDirectory')

    def mount_source(self, c):
        c.source.update(dict.fromkeys(self.MOUNT_PRODUCERS, ''))
        c.source['RequiresMountsFor'] = '/var/tmp'
        c.matrix_report = {'attempts': []}
        runner = Mock(return_value=(0, b'Version=255.4-1ubuntu8\n', b''))
        self.invoke(c.matrix_mount_manager, patchers=(patch.object(c, 'command', runner),))
        runner.assert_called_once_with(
            ['/usr/bin/systemctl', '--system', 'show', '--property=Version'])

    def mount_pair(self, old=False):
        c = self.controller(old)
        self.mount_source(c)
        on = self.mx_plan(c, self.KNOBS, 1)
        off = self.mx_plan(c)
        for plan in (on, off):
            c.matrix_plans[plan['phase']] = plan
        return c, on, off

    def mount_row(self, inventory):
        return next(r for r in inventory['properties'] if r['property'] == 'RequiresMountsFor')

    def test_mount_manager_is_one_readonly_exact_version_sample_not_host_inference(self):
        cases = [(0, ('Version=' + version + '\n').encode(), True, verified)
                 for version, verified in (('255', True), ('255.4-1ubuntu8', True),
                                           ('254', False), ('256', False),
                                           ('2550', False), ('unknown', False))]
        cases += [(1, b'Version=255\n', False, False), (None, b'', False, False),
                  (0, b'', False, False), (0, b'Version=\n', False, False),
                  (0, b'Version=255\nVersion=255\n', False, False),
                  (0, b'Version=255\nOther=value\n', False, False),
                  (0, b'Version=\xff\n', False, False),
                  (0, b'Version=255' + b'x' * 4096, False, False)]
        for code, out, available, verified in cases:
            c, on, off = self.mount_pair()
            c.matrix_mount_manager_sample = None
            runner = Mock(return_value=(code, out, b'PRIVATE_FIXTURE_VALUE'))
            with self.subTest(code=code, out=out[:40]):
                sample = self.invoke(c.matrix_mount_manager, patchers=(
                    patch.object(c, 'command', runner),))
                self.assertEqual((sample['available'], sample['verified_255']), (available, verified))
                self.assertEqual(sample['version'], out.decode().strip().split('=', 1)[1] if available else None)
                self.assertIs(c.matrix_mount_manager(), sample)
                self.assertIs(c.matrix_report['mount_manager'], sample)
                runner.assert_called_once_with(
                    ['/usr/bin/systemctl', '--system', 'show', '--property=Version'])
                inventory = c.matrix_inventory(c.source, dict(self.mx_profile(c, off), RequiresMountsFor=''),
                                               variable=True, source=True, probe_plan=off)
                self.assertEqual(inventory['mount_dependency_audit']['verified'], verified)
                self.assertEqual('RequiresMountsFor' in inventory['matrix_issues'], not verified)
                if not verified:
                    self.assertIn('system-manager-255-unproved',
                                  inventory['mount_dependency_audit']['sides']['source']['reasons'])
                self.assertNotIn('PRIVATE_FIXTURE_VALUE', repr(sample))

    def test_mount_private_tmp_derivation_is_scoped_to_both_fixed_plans_not_global(self):
        for old in (True, False):
            c, on, off = self.mount_pair(old)
            a = self.mx_profile(c, on)
            b = dict(self.mx_profile(c, off), RequiresMountsFor='')
            # A pure mount proof needs no /proc PID identity lookup; the full
            # attempt separately binds entry PID, ownership and release state.
            pidless = {k: v for k, v in b.items() if k not in ('MainPID', 'ControlPID')}
            self.assertTrue(c.matrix_mount_audit(c.source, pidless, source=True, probe_plan=off)['verified'])
            before = copy.deepcopy((c.source, a, b, on, off))
            for left, kwargs in ((c.source, {'source': True, 'probe_plan': off}),
                                 (a, {'source_plan': on, 'probe_plan': off})):
                inventory = c.matrix_inventory(left, b, variable=True, **kwargs)
                row, proof = self.mount_row(inventory), inventory['mount_dependency_audit']
                self.assertEqual(inventory['matrix_issues'], [])
                self.assertFalse(row['raw_equal'])
                self.assertEqual(row['classification'], 'verified-generated-private-tmp')
                self.assertTrue(proof['verified'])
                self.assertEqual(proof['sides']['source']['expected_paths'], ['/var/tmp'])
                self.assertEqual(proof['sides']['probe']['expected_paths'], [])
                self.assertEqual(proof['sides']['probe']['requested_cli_requires'],
                                 {'available': True, 'present': False, 'raw': None})
            for kwargs in ({}, {'source_plan': on}, {'probe_plan': off}):
                self.assertIn('RequiresMountsFor', c.matrix_inventory(a, b, variable=True, **kwargs)['matrix_issues'])
            self.assertIn('RequiresMountsFor', self.D.restriction_differences(a, b))
            self.assertEqual((c.source, a, b, on, off), before)

    def test_mount_exact_paths_reject_injection_duplicates_and_same_wrong_value(self):
        c, on, off = self.mount_pair()
        a, b = self.mx_profile(c, on), self.mx_profile(c, off)
        bad_paths = ('/tmp', '/tmp /var/tmp', '/var/tmp /var/tmp', '/var/tmp /etc',
                     '/var/tmp\n/etc', '/var/tmp\\x20/etc', '%t', '/var/../tmp',
                     '/var/tmp/', ' /var/tmp', '/var/tmp ', '/etc',
                     '/opt/nathaya/logs', str(off['output']), None, False)
        for value in bad_paths:
            for left in (a, dict(a, RequiresMountsFor=value)):
                with self.subTest(value=value, same=left['RequiresMountsFor'] == value):
                    inventory = c.matrix_inventory(left, dict(b, RequiresMountsFor=value), variable=True,
                                                   source_plan=on, probe_plan=off)
                    self.assertIn('RequiresMountsFor', inventory['matrix_issues'])
                    self.assertFalse(inventory['mount_dependency_audit']['verified'])
                    self.assertEqual(self.mount_row(inventory)['classification'], 'unsupported')
        for plan, value in ((on, ''), (off, '/var/tmp')):
            wrong = dict(self.mx_profile(c, plan), RequiresMountsFor=value)
            inventory = c.matrix_inventory(wrong, dict(wrong), source_plan=plan, probe_plan=plan)
            self.assertIn('RequiresMountsFor', inventory['matrix_issues'])

    def test_mount_requires_raw_presence_and_all_producers_verified_empty(self):
        c, on, off = self.mount_pair()
        good = dict(self.mx_profile(c, off), RequiresMountsFor='')
        for side in ('source', 'probe'):
            for key in self.MOUNT_PRODUCERS + ('RequiresMountsFor',):
                for absent, value in ((True, None), (False, None), (False, '/foreign')):
                    left, right = dict(c.source), dict(good)
                    target = left if side == 'source' else right
                    if absent:
                        target.pop(key)
                    else:
                        target[key] = value
                    with self.subTest(side=side, key=key, absent=absent, value=value):
                        inventory = c.matrix_inventory(left, right, variable=True, source=True, probe_plan=off)
                        proof = inventory['mount_dependency_audit']
                        self.assertFalse(proof['verified'])
                        self.assertIn('RequiresMountsFor', inventory['matrix_issues'])
                        raw = (proof['sides'][side]['effective_requires'] if key == 'RequiresMountsFor'
                               else proof['sides'][side]['producer_context'][key])
                        self.assertEqual(raw, {'present': not absent, 'raw': value})
        # Availability False/None is not an observed effective empty string.
        missing = dict(good)
        del missing['RequiresMountsFor']
        proof = c.matrix_mount_audit(c.source, missing, probe_plan=off, source=True)
        self.assertEqual(proof['sides']['probe']['effective_requires'], {'present': False, 'raw': None})
        self.assertEqual(proof['sides']['probe']['requested_requires'], {'present': False, 'raw': None})
        self.assertEqual(c.matrix_mount_audit(c.source, good, probe_plan=off, source=True)
                         ['sides']['probe']['effective_requires'], {'present': True, 'raw': ''})

    def test_mount_source_requires_full_trusted_fragment_no_declarations_dropins_or_reload(self):
        c, on, off = self.mount_pair()
        good = dict(self.mx_profile(c, off), RequiresMountsFor='')
        fragment = copy.deepcopy(c.fragment)
        for value in ('', '/var/tmp'):
            raw = rendered().replace('[Unit]\n', '[Unit]\nRequiresMountsFor=' + value + '\n')
            with self.subTest(explicit=value), self.assertRaises(self.D.Unsupported):
                self.D.validate_fragment(raw)
        fragments = (None, {}, dict(fragment, RequiresMountsFor=''),
                     dict(fragment, RequiresMountsFor='/var/tmp'), dict(fragment, FutureDirective='no'),
                     {k: v for k, v in fragment.items() if k != 'ExecReload'},
                     dict(fragment, User='haproxy'))
        for bad in fragments:
            c.fragment = bad
            with self.subTest(fragment=bad):
                proof = c.matrix_mount_audit(c.source, good, probe_plan=off, source=True)
                self.assertFalse(proof['verified'])
                self.assertFalse(proof['sides']['source']['explicit_request_absence_proved'])
        c.fragment = fragment
        for key, value in (('DropInPaths', '/etc/systemd/system/foreign.conf'),
                           ('NeedDaemonReload', 'yes'), ('DropInPaths', None),
                           ('StandardOutput', 'journal')):
            proof = c.matrix_mount_audit(dict(c.source, **{key: value}), good,
                                        source=True, probe_plan=off)
            self.assertFalse(proof['verified'])
            self.assertFalse(proof['sides']['source']['explicit_request_absence_proved'])
        for key in ('DropInPaths', 'NeedDaemonReload'):
            missing = dict(c.source)
            del missing[key]
            self.assertFalse(c.matrix_mount_audit(missing, good, source=True, probe_plan=off)['verified'])

    def test_mount_plan_registration_cli_aliases_shadow_argv_and_log_paths_are_not_proof(self):
        c, on, off = self.mount_pair()
        good = dict(self.mx_profile(c, off), RequiresMountsFor='')
        variants = []
        for value in ('', '/var/tmp'):
            for form in (None, ['--property=RequiresMountsFor=' + value],
                         ['--property', 'RequiresMountsFor=' + value],
                         ['-p', 'RequiresMountsFor=' + value], ['-pRequiresMountsFor=' + value]):
                bad = copy.deepcopy(off)
                if form is None:
                    bad['properties']['RequiresMountsFor'] = value
                else:
                    boundary = bad['command'].index('--')
                    bad['command'][boundary:boundary] = form
                variants.append(bad)
        for key in ('argv', 'output', 'properties', 'command'):
            bad = copy.deepcopy(off)
            if key == 'argv':
                bad['argv'].append('--unexpected')
                bad['command'] = self.D.transient_command(bad['unit'], bad['properties'], bad['argv'])
            elif key == 'output':
                bad['output'] = c.directory / 'foreign.log'
            elif key == 'properties':
                bad['properties']['StandardOutput'] = 'append:/foreign.log'
                bad['command'] = self.D.transient_command(bad['unit'], bad['properties'], bad['argv'])
            else:
                bad['command'].insert(bad['command'].index('--'), '--property=PrivateTmp=yes')
            variants.append(bad)
        for registered in (False, True):
            for bad in variants:
                c.matrix_plans[off['phase']] = bad if registered else off
                with self.subTest(registered=registered, command=bad['command']):
                    proof = c.matrix_mount_audit(c.source, good, source=True, probe_plan=bad)
                    self.assertFalse(proof['verified'])
                    self.assertFalse(proof['sides']['probe']['provenance_valid'])
        c.matrix_plans.clear()
        self.assertFalse(c.matrix_mount_audit(c.source, good, source=True, probe_plan=off)['verified'])
        c.matrix_plans[off['phase']] = off
        for key, value in (('ExecStartEx', exec_property(['/bin/true'])), ('Id', MAIN),
                           ('StandardOutputFile', '/foreign.log'), ('StandardOutput', 'journal')):
            proof = c.matrix_mount_audit(c.source, dict(good, **{key: value}), source=True, probe_plan=off)
            self.assertFalse(proof['verified'])
        proof = c.matrix_mount_audit(c.source, good, source=True, probe_plan=off)
        self.assertTrue(proof['verified'])
        self.assertEqual(proof['sides']['probe']['expected_paths'], [])
        self.assertEqual(proof['sides']['probe']['log_context']['requested']['StandardOutput']['raw'],
                         'append:' + str(off['output']))
        self.assertNotIn(str(off['output']), proof['sides']['probe']['observed_paths'])

    def test_mount_private_diagnostics_copy_raw_values_presence_and_context_each_stage(self):
        c, on, off = self.mount_pair()
        good = dict(self.mx_profile(c, off), RequiresMountsFor='')
        for stage in ('source-before', 'source-comparison', 'release', 'after', 'edge', 'repeat'):
            for absent in (False, True):
                right = dict(good, RequiresMountsFor='/etc/fixture-private')
                if absent:
                    del right['RequiresMountsFor']
                inventory = c.matrix_inventory(c.source, right, variable=True, source=True, probe_plan=off)
                artifact = 'mx00/' + stage + '.comparison.json'
                c.record_matrix_inventory(inventory, artifact, 'mx00', stage,
                                          ['production-source', 'matrix-probe'])
                detail = c.matrix_report['comparisons'][-1]
                with self.subTest(stage=stage, absent=absent):
                    c.record.assert_called_with(artifact, inventory)
                    self.assertEqual((detail['artifact'], detail['phase'], detail['stage']),
                                     (artifact, 'mx00', stage))
                    self.assertEqual(c.matrix_report['mount_mismatches'][-1], detail)
                    row = detail['rows'][0]
                    self.assertEqual((row['source_present'], row['source']), (True, '/var/tmp'))
                    self.assertEqual((row['probe_present'], row['probe']),
                                     (not absent, None if absent else '/etc/fixture-private'))
                    proof = detail['mount_dependency_audit']
                    self.assertEqual(proof, inventory['mount_dependency_audit'])
                    self.assertEqual(proof['sides']['source']['requested_requires'],
                                     {'present': False, 'raw': None})
                    self.assertEqual(proof['sides']['probe']['requested_private_tmp'],
                                     {'present': True, 'raw': 'no'})
                    self.assertTrue(proof['sides']['source']['requested_context_available'])
                    self.assertEqual(set(proof['sides']['probe']['producer_context']), set(self.MOUNT_PRODUCERS))
                    self.assertEqual(proof['manager']['version'], '255.4-1ubuntu8')

    def test_mount_attempt_pipeline_proves_only_complete_synthetic_context_and_keeps_unknown_strict(self):
        for full in (False, True):
            c = self.controller()
            if full:
                self.mount_source(c)
            plan, profile, _, patchers = self.attempt_fixture(c)
            if full:
                profile['RequiresMountsFor'] = ''
            c.show.side_effect = [{'LoadState': 'not-found'}, profile, dict(profile), dict(profile)]
            no_query = Mock(side_effect=AssertionError('No manager query during held helper'))
            result = self.invoke(c.matrix_attempt, (), patchers=patchers + (
                patch.object(c, 'matrix_mount_manager', no_query),))
            no_query.assert_not_called()
            self.assertEqual(result['phase'], 'mx00')
            self.assertEqual(c.matrix_plans['mx00']['command'], plan['command'])
            saved = {call.args[0]: call.args[1] for call in c.record.call_args_list}
            for name in ('source-comparison', 'release-comparison', 'after-comparison'):
                proof = saved['mx00/' + name + '.json']['mount_dependency_audit']
                self.assertEqual(proof['verified'], full)
                if not full:
                    self.assertEqual(proof['coverage'], 'unknown-both-effective-keys-absent')
                    self.assertEqual(proof['classification'], 'unproved')
                    self.assertIsNone(proof['manager']['version'])
                    self.assertNotIn('RequiresMountsFor', c.source)
                    self.assertNotIn('RequiresMountsFor', profile)
            self.assertIn('mx00/control-go', [call.args[0] for call in c.save.call_args_list])
            self.assertEqual(c.intents, [])
            c.cleanup_one.assert_called_once_with(plan['unit'])

    def test_mount_attempt_refusal_persists_top_context_before_raise_at_source_release_and_after(self):
        for stage in ('source-comparison', 'release', 'after'):
            c = self.controller()
            self.mount_source(c)
            plan, profile, _, patchers = self.attempt_fixture(c)
            profile['RequiresMountsFor'] = ''
            live, after = dict(profile), dict(profile)
            target = {'source-comparison': profile, 'release': live, 'after': after}[stage]
            target['RequiresMountsFor'] = '/etc/fixture-private'
            c.show.side_effect = [{'LoadState': 'not-found'}, profile, live, after]
            with self.subTest(stage=stage), self.assertRaises(self.D.Unsupported):
                self.invoke(c.matrix_attempt, (), patchers=patchers)
            detail = c.matrix_report['comparisons'][-1]
            self.assertEqual(detail['stage'], stage)
            self.assertEqual(detail['rows'][0]['probe'], '/etc/fixture-private')
            self.assertTrue(detail['rows'][0]['probe_present'])
            self.assertIn(detail, c.matrix_report['mount_mismatches'])
            self.assertEqual(detail['mount_dependency_audit']['sides']['probe']['effective_requires'],
                             {'present': True, 'raw': '/etc/fixture-private'})
            self.assertEqual(c.matrix_report['attempts'][0]['status'], 'unavailable')
            self.assertEqual('mx00/control-go' in [call.args[0] for call in c.save.call_args_list], stage == 'after')
            c.cleanup_one.assert_not_called()
            # Main's sanitized stdout must not leak raw paths/values. The private
            # failed comparison above already exists before main catches it.
            c.prepare = Mock()
            c.matrix_report['status'] = 'unavailable'
            c.run_matrix = Mock(side_effect=self.D.Unsupported('RequiresMountsFor'))
            c.cleanup = Mock(return_value=True)
            rc, out, err = self.main_with(c, ['--cap-matrix'])
            self.assertEqual((rc, err), (2, ''))
            self.assertNotIn('/etc/fixture-private', out)
            self.assertNotIn('/var/tmp', out)
            report = next(call.args[1] for call in c.record.call_args_list if call.args[0] == 'matrix.report.json')
            self.assertTrue(report['cleanup_confirmed'])
            self.assertEqual(report['attempts'][0]['enabled'], [])
            self.assertEqual(report['attempts'][0]['status'], 'unavailable')

    def test_mount_attempt_real_source_revalidation_is_strict_even_for_derivable_drift(self):
        for stage in ('source-before', 'source-release'):
            for kind in ('same', 'mount', 'private-tmp', 'log'):
                c = self.controller()
                self.mount_source(c)
                plan, profile, _, patchers = self.attempt_fixture(c)
                profile['RequiresMountsFor'] = ''
                c.show.side_effect = [{'LoadState': 'not-found'}, profile, dict(profile), {'LoadState': 'not-found'}]
                # Restore the real source validator, not a mock that waives drift.
                del c.matrix_source
                current = dict(c.source)
                if kind in ('mount', 'private-tmp'):
                    current['RequiresMountsFor'] = ''
                if kind == 'private-tmp':
                    current['PrivateTmp'] = 'no'
                if kind == 'log':
                    for key in ('StandardOutputFile', 'StandardErrorFile'):
                        current[key] = '/opt/nathaya/logs/other.log'
                original_fragment = (c.source_bytes, c.fragment, [])
                changed_bytes = c.source_bytes
                if kind == 'log':
                    original_log = b'append:/opt/nathaya/logs/%N.log'
                    self.assertIn(original_log, c.source_bytes)
                    changed_bytes = c.source_bytes.replace(original_log, b'append:/opt/nathaya/logs/other.log')
                    self.assertNotEqual(changed_bytes, c.source_bytes, 'Log drift must change actual fragment bytes')
                changed_fragment = (changed_bytes, self.D.validate_fragment(changed_bytes.decode()), [])
                c._audit_fragment = Mock(side_effect=([changed_fragment, changed_fragment]
                                                     if stage == 'source-before' else
                                                     [original_fragment, changed_fragment]))
                c._audit_show = Mock(side_effect=([current, current] if stage == 'source-before'
                                                 else [c.source, current]))
                no_query = Mock(side_effect=AssertionError('Version must already be sampled'))
                with self.subTest(stage=stage, kind=kind):
                    if kind == 'same':
                        self.invoke(c.matrix_attempt, (), patchers=patchers + (
                            patch.object(c, 'matrix_mount_manager', no_query),))
                    else:
                        with self.assertRaises(self.D.Unsupported):
                            self.invoke(c.matrix_attempt, (), patchers=patchers + (
                                patch.object(c, 'matrix_mount_manager', no_query),))
                        self.assertNotIn('mx00/control-go', [call.args[0] for call in c.save.call_args_list])
                        detail = c.matrix_report['comparisons'][-1]
                        self.assertEqual((detail['stage'], detail['roles']),
                                         (stage, ['production-original', 'production-current']))
                        self.assertEqual(detail['rows'][0]['source'], '/var/tmp')
                        self.assertEqual(detail['rows'][0]['probe'], current['RequiresMountsFor'])
                        self.assertFalse(detail['mount_dependency_audit']['scope_requested'])
                        self.assertFalse(detail['mount_dependency_audit']['verified'])
                        for side in detail['mount_dependency_audit']['sides'].values():
                            self.assertTrue(side['fragment_context_available'])
                            self.assertEqual(side['provenance_basis'], 'strict-production-fragment-drift-comparison')
                        saved = {call.args[0]: call.args[1] for call in c.record.call_args_list}
                        self.assertFalse(saved['mx00/' + stage + '.audit.json']['ok'])
                    no_query.assert_not_called()
                # Only the fixed transient command is possible after source-before;
                # no manager query is slipped into the held release deadline.
                self.assertEqual(c.command.call_count, int(kind == 'same' or stage == 'source-release'))

    def test_main_matrix_dispatch_has_no_application_trace_controls_or_reservations(self):
        for clean in (True, False):
            c = self.controller()
            c.prepare = Mock()
            c.matrix_report = {'status': 'confirmed-zero-optional-settings', 'attempts': []}
            c.run_matrix = Mock(return_value=0)
            c.cleanup = Mock(return_value=clean)
            c.run_phase, c.run_controls, c.reserve, c.command = Mock(), Mock(), Mock(), Mock()
            c.boundary_report = Mock()
            rc, out, err = self.main_with(c, ['--cap-matrix'])
            self.assertEqual(rc, 0 if clean else 2)
            self.assertEqual(err, '')
            c.prepare.assert_called_once_with(cap_boundaries=True)
            c.run_matrix.assert_called_once_with()
            c.cleanup.assert_called_once_with()
            for operation in (c.run_phase, c.run_controls, c.reserve, c.command, c.boundary_report):
                operation.assert_not_called()
            report = next(call.args[1] for call in c.record.call_args_list if call.args[0] == 'matrix.report.json')
            self.assertEqual(report['cleanup_confirmed'], clean)
            self.assertEqual(report['attempt_count'], 0)
            self.assertNotIn('plain startup:', out)
            self.assertNotIn('trace startup:', out)
            self.assertNotIn('control gated/direct:', out)


class HostBoundaryRegressions(unittest.TestCase):
    """Reporting uses an ordinary TestCase, outside the diagnostic boundary."""

    @staticmethod
    def references():
        return tuple((obj, name, getattr(obj, name)) for obj, name in (
            (builtins, 'open'), (io, 'open'), (os, 'stat'), (os, 'open'),
            (os, 'fdopen'), (Path, 'stat'), (Path, 'read_text'),
            (Path, 'open'), (Path, 'lstat'), (Path, 'mkdir'),
            (Path, 'readlink'), (Path, 'resolve'),
        ))

    def assert_restored(self, references):
        for obj, name, original in references:
            self.assertIs(getattr(obj, name), original, name)

    def test_assertion_unwinds_local_overrides_before_real_traceback_formatting(self):
        references = self.references()
        fixture = Offline()
        fixture.setUp()
        opening = Mock(side_effect=AssertionError('controlled-boundary-failure'))
        retained = None
        try:
            fixture.invoke(lambda: builtins.open('fixture-only'), patchers=(
                patch.object(builtins, 'open', opening),
            ))
        except AssertionError:
            # assertRaises clears exception.__traceback__; keep the REAL one.
            retained = sys.exc_info()
        self.assert_restored(references)
        self.assertEqual(fixture.host.depth, 0)
        self.assertIsNotNone(retained)
        self.assertIsNotNone(retained[2])
        opening.assert_called_once_with('fixture-only')
        filename = HostBoundary.invoke.__code__.co_filename
        missing = object()
        cached = linecache.cache.get(filename, missing)
        real_updatecache = linecache.updatecache
        fetched = []

        def updatecache(*args, **kwargs):
            self.assert_restored(references)  # BEFORE actual checkout source IO.
            self.assertEqual(fixture.host.depth, 0)
            lines = real_updatecache(*args, **kwargs)
            if (args[0] if args else kwargs['filename']) == filename:
                self.assertTrue(lines, 'Real source lines must be retrieved')
                source = ''.join(lines)
                self.assertRegex(source, r'(?m)^\s*class\s+HostBoundary\s*:')
                self.assertRegex(source, r'\breturn\s+operation\s*\(\s*\*args\s*,\s*\*\*kwargs\s*\)')
                fetched.append(lines)
            return lines

        try:
            # Reporting is outside the boundary: no host IO is patched here.
            # Each formatter must retrieve actual source from a cold cache.
            with patch.object(linecache, 'updatecache', side_effect=updatecache):
                linecache.cache.pop(filename, None)
                structured = ''.join(traceback.TracebackException(*retained).format())
                linecache.cache.pop(filename, None)
                formatted = ''.join(traceback.format_exception(*retained))
            self.assertIs(linecache.updatecache, real_updatecache)
            self.assertGreaterEqual(len(fetched), 2)
            for text in (structured, formatted):
                self.assertIn('controlled-boundary-failure', text)
                self.assertIn('diagnose_haproxy_test.py', text)
                self.assertRegex(text, r'\breturn\s+operation\s*\(\s*\*args\s*,\s*\*\*kwargs\s*\)')
            self.assert_restored(references)
        finally:
            if cached is missing:
                linecache.cache.pop(filename, None)
            else:
                linecache.cache[filename] = cached

    def test_nested_invocations_preserve_local_fakes_and_constructor_api(self):
        references = self.references()
        fixture = Offline()
        fixture.setUp()
        outer_entropy = Mock(return_value='c' * 32)
        inner_entropy = Mock(return_value='d' * 32)
        opening = Mock(return_value='virtual')
        observations = []

        def grouped():
            observations.append(fixture.D.Controller().nonce)
            child = fixture.invoke(fixture.D.Controller, patchers=(
                patch.object(secrets, 'token_hex', inner_entropy),
            ))
            observations.append(child.nonce)
            observations.append(fixture.D.Controller().nonce)
            observations.append(builtins.open('fixture-only'))
            # Nested wrappers must not reinstall guards over these local fakes.
            observations.append(fixture.D.parse_show('Id=fixture.service\n'))
            raise AssertionError('controlled-nested-failure')

        with self.assertRaisesRegex(AssertionError, 'controlled-nested-failure'):
            fixture.invoke(grouped, patchers=(
                patch.object(secrets, 'token_hex', outer_entropy),
                patch.object(builtins, 'open', opening),
            ))
        self.assert_restored(references)
        self.assertEqual(fixture.host.depth, 0)
        self.assertEqual(observations, ['c' * 32, 'd' * 32, 'c' * 32,
                                       'virtual', {'Id': 'fixture.service'}])
        self.assertEqual(outer_entropy.call_count, 2)
        inner_entropy.assert_called_once_with(16)
        opening.assert_called_once_with('fixture-only')
        self.assertIsInstance(fixture.D.Controller, type)
        self.assertIs(fixture.D.Path, Path)
        self.assertTrue(issubclass(fixture.D.Unsupported, ValueError))
        self.assertFalse(hasattr(fixture.D.Unsupported, '__wrapped__'))
        errors = []
        fixture.D.collect_unsupported(errors=errors, operation=fixture.D.watchdog_behavior, value='5s')
        self.assertEqual(errors, ['WatchdogUSec'])
        for value in vars(fixture.D).values():
            if isinstance(value, FunctionType) and value.__module__ == fixture.D.__name__:
                self.assertTrue(hasattr(value, '__wrapped__'))
        for value in vars(fixture.D.Controller).values():
            if isinstance(value, FunctionType) and value.__module__ == fixture.D.__name__:
                self.assertTrue(hasattr(value, '__wrapped__'))
        self.assertEqual(fixture.D.Controller().nonce, NONCE)
        self.assertEqual(fixture.D.Controller().nonce, NONCE)
        self.assert_restored(references)

    def test_import_failure_unwinds_before_handler_and_allows_fresh_setup(self):
        references = self.references()
        fixture = Offline()
        failed_import = compile("raise RuntimeError('controlled-import-failure')",
                                'fixture-import-failure', 'exec')
        # Only the diagnostic code object changes; no host override surrounds
        # the assertion handler, and setUp itself must unwind on import failure.
        with patch.dict(Offline.setUp.__globals__, {'CODE': failed_import}):
            with self.assertRaisesRegex(RuntimeError, 'controlled-import-failure'):
                fixture.setUp()
        self.assert_restored(references)
        self.assertEqual(fixture.host.depth, 0)
        fixture.setUp()
        self.assertEqual(fixture.D.parse_show('Id=fixture.service\n'), {'Id': 'fixture.service'})
        self.assert_restored(references)

    def test_forbidden_operations_still_fail_only_inside_invocation(self):
        references = self.references()
        boundary = HostBoundary()
        # No operation is attempted outside invoke, not even as a guard probe.
        path_operations = tuple(
            lambda name=name, args=args: getattr(Path('/fixture-forbidden'), name)(*args)
            for name, args in (
                ('open', ()), ('stat', ()), ('lstat', ()), ('mkdir', ()),
                ('unlink', ()), ('rmdir', ()), ('rename', ('/fixture-target',)),
                ('replace', ('/fixture-target',)), ('chmod', (0o600,)),
                ('lchmod', (0o600,)), ('touch', ()),
                ('symlink_to', ('/fixture-target',)), ('link_to', ('/fixture-target',)),
                ('hardlink_to', ('/fixture-target',)), ('readlink', ()),
                ('resolve', ()), ('exists', ()), ('is_dir', ()), ('is_file', ()),
            ) if hasattr(Path, name)
        )
        for operation in (lambda: builtins.open('/fixture-forbidden'),
                          lambda: io.open('/fixture-forbidden'),
                          lambda: os.stat('/fixture-forbidden'),
                          lambda: os.open('/fixture-forbidden', os.O_RDONLY),
                          lambda: os.fdopen(-1),
                          lambda: Path('/fixture-forbidden').read_text(),
                          lambda: subprocess.run(['fixture-forbidden']),
                          lambda: socket.socket()) + path_operations:
            with self.assertRaisesRegex(AssertionError, 'Real host operation forbidden'):
                boundary.invoke(operation)
            self.assert_restored(references)
            self.assertEqual(boundary.depth, 0)

    def test_offline_failure_and_subtest_reporting_see_original_host_functions(self):
        references = self.references()
        outer = self

        class ReportingResult(unittest.TestResult):
            def addFailure(result, test, err):
                outer.assert_restored(references)  # BEFORE real traceback formatting.
                super().addFailure(test, err)

            def addSubTest(result, test, subtest, err):
                outer.assert_restored(references)  # BEFORE real subtest formatting.
                super().addSubTest(test, subtest, err)

        for as_subtest in (False, True):
            opening = Mock(side_effect=AssertionError('expected-inner-failure'))

            class FailingOffline(Offline):
                def runTest(inner):
                    def fail():
                        builtins.open('fixture-only')
                    if as_subtest:
                        with inner.subTest(stage='expected-failure'):
                            inner.invoke(fail, patchers=(patch.object(builtins, 'open', opening),))
                    else:
                        inner.invoke(fail, patchers=(patch.object(builtins, 'open', opening),))

            result = ReportingResult()
            FailingOffline().run(result)
            self.assert_restored(references)
            self.assertEqual(result.testsRun, 1)
            self.assertEqual(result.errors, [])
            self.assertEqual(len(result.failures), 1)
            self.assertIn('expected-inner-failure', result.failures[0][1])
            self.assertIn('diagnose_haproxy_test.py', result.failures[0][1])
            opening.assert_called_once_with('fixture-only')


if __name__ == '__main__':
    unittest.main()
