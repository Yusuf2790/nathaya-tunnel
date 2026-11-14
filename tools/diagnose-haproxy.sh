#!/bin/bash
# Operator-only, opt-in diagnostic. Sourcing defines functions and does nothing.
nathaya_diagnose_haproxy_main() {
    case "$#:${1-}" in
        1:--help)
            builtin printf '%s\n' \
                'Usage: bash tools/diagnose-haproxy.sh --help | --run' \
                '--help is read-only. --run requires root Ubuntu 24.04 amd64, systemd PID 1.' \
                'Creates bounded, private transient probes; never changes the production unit.' \
                'Evidence is preserved under /run/nathaya-haproxy-probe.* (root only).' \
                'An unsupported effective profile stops BEFORE HAProxy execution.' \
                'Tracing changes privilege/timing; traced results do not represent an untraced run.'
            return 0
            ;;
        1:--run) ;;
        *) builtin printf '%s\n' 'Usage: bash tools/diagnose-haproxy.sh --help | --run' >&2; return 64 ;;
    esac
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
        /usr/bin/python3 -I -B - --run <<'NATHAYA_HAPROXY_DIAG_PY'
"""Self-contained, fail-closed HAProxy probe. Importing defines APIs only.

Pure public interfaces:
  parse_show(text) -> dict[str, str]
  validate_fragment(text) -> dict[str, str] (audited directives)
  validate_effective(properties, fragment) -> frozenset[str] (source caps)
  restriction_differences(source, probe) -> sorted list[str]
  make_config(port, abstract_name) -> str
  trace_command(haproxy_argv) -> list[str]
  sanitise_trace(text) -> dict (no arguments, IDs or raw log text)
  owned_unit(properties, unit, nonce) -> bool
Controller is the bounded runtime/evidence owner; main(argv=None) is opt-in.
Unknown effective differences are unsupported, never a reason to weaken a probe.
"""
import collections
import errno
import grp
import hashlib
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
import sys
import tempfile
import time

MAIN = 'nathaya-haproxy.service'
FRAGMENT = '/etc/systemd/system/' + MAIN
HAPROXY = '/usr/sbin/haproxy'
LOGS = '/opt/nathaya/logs'
LOCK = '/run/nathaya-tunnel-setup.lock'
CAPS3 = frozenset(('CAP_SETUID', 'CAP_SETGID', 'CAP_NET_BIND_SERVICE'))
CAPS4 = CAPS3 | {'CAP_KILL'}
CAP_BITS = {'CAP_KILL': 5, 'CAP_SETGID': 6, 'CAP_SETUID': 7, 'CAP_NET_BIND_SERVICE': 10}
SHOW_LIMIT = 4 * 1024 * 1024
FIXED_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
SYSCALLS = (
    'getuid', 'geteuid', 'getgid', 'getegid', 'getresuid', 'getresgid',
    'setuid', 'setreuid', 'setresuid', 'setfsuid', 'setgid', 'setregid',
    'setresgid', 'setfsgid', 'getgroups', 'setgroups', 'capget', 'capset',
    'prctl', 'clone', 'clone3', 'fork', 'vfork', 'wait4', 'waitid',
    'exit', 'exit_group', 'kill', 'tgkill', 'tkill',
)
IDENTITY_CALLS = frozenset(('getuid', 'geteuid', 'getresuid', 'setuid',
                            'setreuid', 'setresuid', 'setfsuid'))


class Unsupported(ValueError):
    """Messages are constant labels or validated property NAMES, never values."""


def parse_show(text):
    """Parse a complete systemctl show --all response, without unescaping values."""
    if not isinstance(text, str) or not text or len(text) > SHOW_LIMIT or '\x00' in text:
        raise Unsupported('show-format')
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', key) or key in result:
            raise Unsupported('show-format')
        result[key] = value
    return result


def _capset(text):
    tokens = text.split()
    normal = [token.upper() for token in tokens]
    if len(normal) != len(set(normal)) or any(not re.fullmatch(r'CAP_[A-Z0-9_]+', t) for t in normal):
        raise Unsupported('CapabilityBoundingSet')
    return frozenset(normal)


# These are the actual renderer's directives, not a generic systemd parser.
UNIT_FIELDS = {'Description': 'Nathaya HAProxy', 'After': 'network.target'}
SERVICE_FIELDS = {
    'Type': 'simple', 'User': 'root', 'Group': 'root', 'UMask': '0077',
    'StandardOutput': 'append:/opt/nathaya/logs/%N.log',
    'StandardError': 'append:/opt/nathaya/logs/%N.log',
    'ExecStart': '/usr/sbin/haproxy -W -db -f /etc/nathaya-tunnel/services/haproxy.cfg',
    'ExecReload': '/bin/kill -USR2 $MAINPID',
    'Restart': 'on-failure', 'RestartSec': '3s', 'NoNewPrivileges': 'true',
    'PrivateTmp': 'true', 'ProtectSystem': 'strict', 'ProtectHome': 'true',
    'ProtectKernelTunables': 'true', 'ProtectKernelModules': 'true',
    'ProtectControlGroups': 'true', 'RestrictSUIDSGID': 'true',
    'LockPersonality': 'true',
    'RestrictAddressFamilies': 'AF_INET AF_INET6 AF_UNIX',
    'AmbientCapabilities': '', 'ReadWritePaths': LOGS,
}
INSTALL_FIELDS = {'WantedBy': 'multi-user.target'}


def validate_fragment(text):
    """Reject unknown sections/directives, duplicates, continuations and resets."""
    if not isinstance(text, str) or len(text) > 65536 or '\x00' in text or '\r' in text:
        raise Unsupported('fragment-format')
    expected = {'Unit': UNIT_FIELDS, 'Service': SERVICE_FIELDS, 'Install': INSTALL_FIELDS}
    section, seen_sections, result = None, set(), {}
    for line in text.split('\n'):
        if line.endswith('\\'):
            raise Unsupported('fragment-continuation')
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        if line.startswith('['):
            if line not in ('[Unit]', '[Service]', '[Install]') or line[1:-1] in seen_sections:
                raise Unsupported('fragment-section')
            section = line[1:-1]
            seen_sections.add(section)
            continue
        key, sep, value = line.partition('=')
        if (section is None or not sep or key in result or
                (key not in expected[section] and not (section == 'Service' and key == 'CapabilityBoundingSet'))):
            raise Unsupported('fragment-directive')
        if key == 'CapabilityBoundingSet':
            if _capset(value) not in (CAPS3, CAPS4):
                raise Unsupported('CapabilityBoundingSet')
        elif value != expected[section][key]:
            raise Unsupported('fragment-value')
        result[key] = value
    required = set(UNIT_FIELDS) | set(SERVICE_FIELDS) | set(INSTALL_FIELDS) | {'CapabilityBoundingSet'}
    if set(result) != required or seen_sections != set(expected):
        raise Unsupported('fragment-missing')
    return result


def _require(properties, expected):
    bad = [k for k, v in expected.items() if properties.get(k) != v]
    if bad:
        raise Unsupported('properties:' + ','.join(sorted(bad)))


def _exec_struct(value, argv):
    """Validate one show Exec* structure against our exact command factory.

    Only bookkeeping fields may follow argv[]. No second command is allowed.
    The fields are read only, and no show value ever becomes command syntax.
    """
    if not value.startswith('{ ') or not value.endswith(' }'):
        return False
    fields = value[2:-2].split(' ; ')
    if len(fields) < 3 or fields[:2] != ['path=' + argv[0], 'argv[]=' + ' '.join(argv)]:
        return False
    seen = set()
    for field in fields[2:]:
        key, sep, val = field.partition('=')
        if not sep or key in seen:
            return False
        seen.add(key)
        if key == 'ignore_errors':
            if val != 'no':
                return False
        elif key == 'flags':
            if val not in ('', '0'):
                return False
        elif key in ('start_time', 'stop_time'):
            if not re.fullmatch(r'\[[^\[\]{};\n]*\]', val):
                return False
        elif key == 'pid':
            if not re.fullmatch(r'[0-9]+', val):
                return False
        elif key == 'code':
            if val not in ('(null)', 'exited', 'killed', 'dumped'):
                return False
        elif key == 'status':
            if not re.fullmatch(r'[0-9]+(?:/[A-Za-z0-9]+)?', val):
                return False
        else:
            return False
    return bool(seen & {'flags', 'ignore_errors'})


def validate_effective(properties, fragment):
    """Validate production profile without reading its config, PEM, or logs."""
    _require(properties, {
        'Id': MAIN, 'LoadState': 'loaded', 'FragmentPath': FRAGMENT,
        'DropInPaths': '', 'NeedDaemonReload': 'no', 'User': 'root', 'Group': 'root',
        'Type': 'simple', 'NoNewPrivileges': 'yes', 'SecureBits': '0',
        'AmbientCapabilities': '', 'ProtectSystem': 'strict', 'ProtectHome': 'yes',
        'PrivateTmp': 'yes', 'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes',
        'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
        'ReadWritePaths': LOGS, 'UMask': '0077', 'Slice': 'system.slice',
        'PrivateNetwork': 'no', 'PrivateUsers': 'no', 'JoinsNamespaceOf': '',
        'RootDirectory': '', 'RootImage': '',
        'Restart': 'on-failure', 'RestartUSec': '3s', 'CanReload': 'yes',
        'Description': 'Nathaya HAProxy',
        'StandardOutput': 'append', 'StandardError': 'append',
        'StandardOutputFile': '/opt/nathaya/logs/nathaya-haproxy.log',
        'StandardErrorFile': '/opt/nathaya/logs/nathaya-haproxy.log',
    })
    caps = _capset(properties.get('CapabilityBoundingSet', ''))
    if caps not in (CAPS3, CAPS4) or caps != _capset(fragment['CapabilityBoundingSet']):
        raise Unsupported('CapabilityBoundingSet')
    families = properties.get('RestrictAddressFamilies', '').split()
    if len(families) != 3 or set(families) != {'AF_INET', 'AF_INET6', 'AF_UNIX'}:
        raise Unsupported('RestrictAddressFamilies')
    # Only an empty deny list is supported. Never translate an allow-list to deny.
    if properties.get('SystemCallFilter') != '~':
        raise Unsupported('SystemCallFilter')
    for name, argv in (('ExecStart', SERVICE_FIELDS['ExecStart'].split()),
                       ('ExecReload', ['/bin/kill', '-USR2', '$MAINPID'])):
        if not _exec_struct(properties.get(name, ''), argv):
            raise Unsupported(name)
        if name + 'Ex' in properties and not _exec_struct(properties[name + 'Ex'], argv):
            raise Unsupported(name + 'Ex')
    for name in ('ExecStartPre', 'ExecStartPost', 'ExecCondition', 'ExecStop', 'ExecStopPost'):
        if properties.get(name) != '' or properties.get(name + 'Ex', '') != '':
            raise Unsupported(name)
    return caps


# Explicit property names only. No prefix-based exemptions: a new property blocks
# when it differs, even if a particular systemd version considers it metadata.
# Restrictions (network, filesystem, resource, security) MUST NOT be added here.
RUNTIME_PROPERTIES = frozenset('''
Id Names Following Description LoadState ActiveState FreezerState SubState
FragmentPath SourcePath DropInPaths UnitFileState UnitFilePreset Transient
NeedDaemonReload StateChangeTimestamp StateChangeTimestampMonotonic
InactiveExitTimestamp InactiveExitTimestampMonotonic ActiveEnterTimestamp
ActiveEnterTimestampMonotonic ActiveExitTimestamp ActiveExitTimestampMonotonic
InactiveEnterTimestamp InactiveEnterTimestampMonotonic InvocationID
Job JobType JobTimeoutUSec JobRunningTimeoutUSec ConditionResult AssertResult
ConditionTimestamp ConditionTimestampMonotonic AssertTimestamp AssertTimestampMonotonic
StopWhenUnneeded RefuseManualStart RefuseManualStop
Requires Requisite Wants BindsTo PartOf Upholds RequiredBy RequisiteOf WantedBy
BoundBy ConsistsOf UpheldBy Conflicts ConflictedBy Before After OnFailure OnSuccess
OnFailureJobMode OnSuccessJobMode PropagatesReloadTo ReloadPropagatedFrom
PropagatesStopTo StopPropagatedFrom TriggeredBy Triggers JoinsNamespaceOf
References ReferencedBy Documentation CollectMode
MainPID ControlPID ExecMainPID StatusText StatusErrno Result ReloadResult
WatchdogTimestamp WatchdogTimestampMonotonic WatchdogPID
CleanResult LiveMountResult NRestarts ExecMainStartTimestamp
ExecMainStartTimestampMonotonic ExecMainExitTimestamp ExecMainExitTimestampMonotonic
ExecMainCode ExecMainStatus ControlGroup ControlGroupId UID GID
CPUUsageNSec CPUUsageNSecStart CPUUsageNSecLast CPUUsageNSecPeak
MemoryCurrent MemoryPeak MemorySwapCurrent MemorySwapPeak MemoryZSwapCurrent
MemoryAvailable TasksCurrent IPIngressBytes IPIngressPackets IPEgressBytes
IPEgressPackets IOReadBytes IOReadOperations IOWriteBytes IOWriteOperations
NFileDescriptorStore FileDescriptorStoreState OOMKilled OOMPolicyResult
ExecMemoryPeak ExecMemorySwapPeak ExecMainHandoffTimestamp ExecMainHandoffTimestampMonotonic
'''.split())
# Stop/refuse and namespace-dependency settings are policy rather than mere
# bookkeeping; compare them even though some appear alongside runtime fields.
RUNTIME_PROPERTIES = RUNTIME_PROPERTIES - {
    'StopWhenUnneeded', 'RefuseManualStart', 'RefuseManualStop', 'JoinsNamespaceOf',
    'JobTimeoutUSec', 'JobRunningTimeoutUSec', 'CollectMode',
}
INTENDED_PROPERTIES = frozenset('''
Restart RuntimeMaxUSec TimeoutStartUSec TimeoutStopUSec TimeoutAbortUSec CanReload
StandardOutputFile StandardErrorFile
ExecStart ExecStartEx ExecStartPre ExecStartPreEx ExecReload ExecReloadEx
'''.split())


def _equivalent(key, value):
    if key in ('CapabilityBoundingSet', 'AmbientCapabilities'):
        return _capset(value)
    if key == 'RestrictAddressFamilies':
        return tuple(sorted(value.split()))
    # Empty allow-list output is NOT equivalent to the known empty deny-list '~'.
    return value


def restriction_differences(source, probe):
    """All missing/extra properties block, INCLUDING exempt property names.

    Returned names contain no values. Intended differences are separately
    validated by Controller.gate; this function does not authorise execution.
    """
    missing = set(source) ^ set(probe)
    changed = {k for k in set(source) & set(probe)
               if k not in RUNTIME_PROPERTIES | INTENDED_PROPERTIES
               and _equivalent(k, source[k]) != _equivalent(k, probe[k])}
    return sorted(missing | changed)


def make_config(port, abstract_name):
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('high-port')
    if not isinstance(abstract_name, str) or not re.fullmatch(r'nathaya-probe-[0-9a-f]{32}', abstract_name):
        raise ValueError('abstract-name')
    return f'''global
    master-worker
    user haproxy
    group haproxy
    maxconn 16

defaults
    mode tcp
    timeout connect 1s
    timeout client 2s
    timeout server 2s

frontend probe_loopback
    bind 127.0.0.1:{port}
    default_backend probe_local

backend probe_local
    server local abns@{abstract_name}

frontend probe_abstract
    bind abns@{abstract_name}
    tcp-request content reject
'''


def trace_command(haproxy_argv):
    if (not isinstance(haproxy_argv, (list, tuple)) or len(haproxy_argv) != 5 or
            list(haproxy_argv[:4]) != [HAPROXY, '-W', '-db', '-f'] or
            not isinstance(haproxy_argv[4], str) or not re.fullmatch(r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+/(?:plain|trace)/haproxy.cfg', haproxy_argv[4])):
        raise ValueError('trace-command')
    return ['/usr/bin/strace', '-f', '-e', 'signal=none', '-e',
            'trace=' + ','.join(SYSCALLS), '-e', 'raw=clone,clone3,prctl'] + list(haproxy_argv)


def sanitise_trace(text):
    """Recognise only actual strace records; never return arguments or log text.

    Includes <... syscall resumed> failures. Unknown names/errno are discarded.
    Combined HAProxy/strace output is not an authenticated syscall transcript.
    """
    counts, identity, records = collections.Counter(), 0, 0
    prefix = r'(?:(?:\[pid +[1-9][0-9]*\] +|[1-9][0-9]* +))?'
    call = re.compile('^' + prefix + r'([a-z][a-z0-9_]*)\(.*\)\s+=\s+(.*)$')
    resumed = re.compile('^' + prefix + r'<\.\.\. ([a-z][a-z0-9_]*) resumed>.*\)\s+=\s+(.*)$')
    denied = False
    for line in text.splitlines():
        if (re.search(r'^strace:.*(?:ptrace|PTRACE).*(?:EPERM|EACCES|Operation not permitted|Permission denied)', line)
                or re.search(r'^strace:.*[Yy]ama', line)
                or re.search(r'^strace:.*(?:Operation not permitted|Permission denied)', line)):
            denied = True
        match = call.fullmatch(line) or resumed.fullmatch(line)
        if not match or match[1] not in SYSCALLS:
            continue
        name, result = match.groups()
        failure = re.fullmatch(r'-1 ([A-Z][A-Z0-9]+)(?: \([^\n]*\))?', result)
        success = re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)(?: \([^()\n]*\))?', result)
        # An invented errno or partial/unfinished record is not evidence, even
        # for completeness counters. Never return the error description either.
        if failure:
            if failure[1] not in errno.errorcode.values():
                continue
            counts[(name, failure[1])] += 1
        elif not success:
            continue
        records += 1
        identity += int(name in IDENTITY_CALLS)
    return {'available': bool(identity) and not denied,
            'identity_calls': identity, 'records': records,
            'counts': [{'syscall': name, 'errno': error, 'count': n}
                       for (name, error), n in sorted(counts.items())]}


def owned_unit(properties, unit, nonce):
    """Ownership is a conjunction, never merely a matching unit name or PID."""
    if (not isinstance(properties, dict) or not isinstance(unit, str) or
            not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce)):
        return False
    match = re.fullmatch(r'nathaya-haproxy-probe-' + nonce + r'-(plain|trace)\.service', unit)
    if not match:
        return False
    expected = {
        'Id': unit, 'Transient': 'yes',
        'Description': 'Nathaya HAProxy probe ' + nonce + ' ' + match[1],
        'FragmentPath': '/run/systemd/transient/' + unit,
    }
    return (all(properties.get(k) == v for k, v in expected.items()) and
            properties.get('ControlGroup') in ('', '/system.slice/' + unit))


GATE_PROGRAM = '''import os, stat, sys, time
from pathlib import Path
if len(sys.argv) != 2:
    raise SystemExit(1)
p = Path(sys.argv[1])
deadline = time.monotonic() + 4.0
while time.monotonic() < deadline:
    try:
        s = p.lstat()
        if (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_gid == 0
                and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1):
            raise SystemExit(0)
        raise SystemExit(1)
    except FileNotFoundError:
        time.sleep(0.025)
raise SystemExit(1)
'''


def _secure_path(path, directory=False):
    """Existing trusted root path; reject symlinks and writable ancestors."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise Unsupported('private-path')
    for part in reversed((path,) + tuple(path.parents)):
        info = part.lstat()
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise Unsupported('private-path')
        if part != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise Unsupported('private-path')
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Unsupported('private-path')
    return path.stat()


def _read_private_source(path, limit=SHOW_LIMIT):
    """Open regular root-owned nonsymlink after checking trusted ancestors."""
    _secure_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_gid or
                info.st_mode & 0o022 or info.st_nlink != 1):
            raise Unsupported('source-metadata')
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise Unsupported('source-size')
    return raw, {'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
                 'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
                 'mtime_ns': info.st_mtime_ns, 'sha256': hashlib.sha256(raw).hexdigest()}


def _no_lock():
    # lexists refuses a stale lock or dangling symlink too; never acquire/remove.
    if os.path.lexists(LOCK):
        raise Unsupported('installer-lock-present')


def _status(raw):
    result = {}
    wanted = {'Pid', 'PPid', 'Uid', 'Gid', 'Groups', 'CapEff', 'CapPrm', 'CapBnd', 'CapAmb', 'NoNewPrivs'}
    for line in raw.splitlines():
        key, sep, val = line.partition(':')
        if key not in wanted:
            continue
        if not sep or key in result:
            raise ValueError('proc-status')
        fields = val.split()
        count = len(fields) if key == 'Groups' else 4 if key in ('Uid', 'Gid') else 1
        pattern = r'[0-9a-fA-F]{1,16}' if key.startswith('Cap') else r'[0-9]{1,10}'
        if len(fields) != count or len(fields) > 1024 or any(not re.fullmatch(pattern, v) for v in fields):
            raise ValueError('proc-status')
        values = tuple(int(v, 16 if key.startswith('Cap') else 10) for v in fields)
        result[key] = values if key in ('Uid', 'Gid', 'Groups') else values[0]
    if set(result) != wanted:
        raise ValueError('proc-status')
    return result


def _capture_unit(unit, nonce):
    """Capture accepts only this run's exact, nonce-qualified probe names."""
    return (isinstance(unit, str) and isinstance(nonce, str) and
            re.fullmatch(r'[0-9a-f]{32}', nonce) is not None and
            re.fullmatch(r'nathaya-haproxy-probe-' + nonce +
                         r'-(plain|trace)\.service', unit) is not None)


def _proc_identity(raw):
    """Extract only PID/starttime; comm may contain spaces and closing parens.

    The rest of stat (including address/memory fields) is never evidence.
    """
    head, sep, tail = raw.rpartition(b') ')
    pid, opening, _comm = head.partition(b' (')
    fields = tail.split()
    if (not sep or not opening or not re.fullmatch(rb'[1-9][0-9]{0,9}', pid) or
            len(fields) < 20 or not re.fullmatch(rb'[A-Za-z]', fields[0]) or
            not re.fullmatch(rb'[0-9]{1,20}', fields[19])):
        raise ValueError('proc-identity')
    return int(pid), int(fields[19])


class Controller:
    """Private evidence, intent-before-create, pre-exec comparison, bounded cleanup."""
    def __init__(self):
        self.directory = None
        self.nonce = secrets.token_hex(16)
        self.intents = []
        self.creation_confirmed = set()
        self.reservations = []
        self.serial = 0
        self.source = None
        self.fragment = None
        self.source_bytes = None
        self.caps = None
        self.uid = self.gid = None
        self.cleanup_confirmed = True

    def save(self, name, content):
        if self.directory is None or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name):
            raise Unsupported('evidence-path')
        path = self.directory / name
        _secure_path(path.parent, directory=True)
        if stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
            raise Unsupported('evidence-mode')
        raw = content if isinstance(content, bytes) else content.encode('utf-8')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        info = path.lstat()
        if info.st_uid or info.st_gid or stat.S_IMODE(info.st_mode) != 0o600:
            raise Unsupported('evidence-mode')
        return path

    def record(self, name, value):
        return self.save(name, json.dumps(value, sort_keys=True, indent=2) + '\n')

    def command(self, argv, timeout=3):
        """Never print command output. Persist even failed/timed-out commands."""
        self.serial += 1
        stem = 'command-%05d' % self.serial
        start = time.monotonic()
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=min(timeout, 3), env=FIXED_ENV, check=False)
            out, err, code, state = result.stdout, result.stderr, result.returncode, 'returned'
        except subprocess.TimeoutExpired as exc:
            out, err, code, state = exc.stdout or b'', exc.stderr or b'', None, 'timeout'
        except KeyboardInterrupt:
            self.record(stem + '.json', {'argv': list(argv), 'returncode': None,
                                        'state': 'interrupted', 'output': 'unavailable',
                                        'elapsed': time.monotonic() - start})
            raise
        except OSError as exc:
            out, err, code, state = b'', b'', None, 'os-error'
            self.record(stem + '.error.json', {'errno': exc.errno})
        self.save(stem + '.stdout', out)
        self.save(stem + '.stderr', err)
        self.record(stem + '.json', {'argv': list(argv), 'returncode': code, 'state': state,
                                    'elapsed': time.monotonic() - start})
        return code, out, err

    def show(self, unit, absent=False, timeout=3):
        if unit != MAIN and not re.fullmatch(r'nathaya-haproxy-probe-' + self.nonce + r'-(?:plain|trace)\.service', unit):
            raise Unsupported('unit-name')
        code, out, _ = self.command(['/usr/bin/systemctl', 'show', '--all', '--no-pager', unit], timeout=timeout)
        if len(out) > SHOW_LIMIT:
            raise Unsupported('show-size')
        try:
            properties = parse_show(out.decode('utf-8', 'strict'))
        except (UnicodeError, ValueError):
            raise Unsupported('show-unavailable') from None
        if code != 0 and not (absent and properties.get('LoadState') == 'not-found'):
            raise Unsupported('dbus-or-show-unavailable')
        return properties

    def prepare(self):
        if (os.geteuid() != 0 or os.getuid() != 0 or os.getegid() != 0 or os.getgid() != 0 or
                platform.machine() != 'x86_64'):
            raise Unsupported('root-Ubuntu-24.04-amd64-required')
        if Path('/proc/1/comm').read_text().strip() != 'systemd':
            raise Unsupported('systemd-PID1-required')
        osinfo, _ = _read_private_source('/usr/lib/os-release', 65536)
        osfields = dict(line.split('=', 1) for line in osinfo.decode('utf-8').splitlines()
                        if '=' in line and not line.startswith('#'))
        if osfields.get('ID', '').strip('"') != 'ubuntu' or osfields.get('VERSION_ID', '').strip('"') != '24.04':
            raise Unsupported('Ubuntu-24.04-required')
        _no_lock()
        _secure_path('/run', directory=True)
        os.umask(0o077)
        self.directory = Path(tempfile.mkdtemp(prefix='nathaya-haproxy-probe.', dir='/run'))
        _secure_path(self.directory, directory=True)
        if stat.S_IMODE(self.directory.stat().st_mode) != 0o700:
            raise Unsupported('evidence-mode')
        self.save('gate.py', GATE_PROGRAM)
        self.source = self.show(MAIN)
        self.save('production.show', ''.join(k + '=' + v + '\n' for k, v in self.source.items()))
        raw, metadata = _read_private_source(FRAGMENT, 65536)
        self.source_bytes = raw
        self.save('production.fragment', raw)
        self.record('production.fragment.metadata.json', metadata)
        self.fragment = validate_fragment(raw.decode('utf-8', 'strict'))
        self.caps = validate_effective(self.source, self.fragment)
        binary, metadata = _read_private_source(HAPROXY, 64 * 1024 * 1024)
        if not binary.startswith(b'\x7fELF\x02\x01') or binary[18:20] != b'\x3e\x00':
            raise Unsupported('haproxy-amd64-ELF-required')
        self.record('haproxy.metadata.json', metadata)
        self.command([HAPROXY, '-vv'])
        for candidate in ('/usr/sbin/getcap', '/usr/bin/getcap'):
            if os.path.isfile(candidate):
                _secure_path(candidate)
                self.command([candidate, HAPROXY])
                break
        else:
            self.record('getcap.unavailable.json', {'available': False})
        if os.path.isfile('/usr/bin/strace'):
            _secure_path('/usr/bin/strace')
            self.command(['/usr/bin/strace', '-V'])
        else:
            self.record('strace.unavailable.json', {'available': False})
        account, group = pwd.getpwnam('haproxy'), grp.getgrnam('haproxy')
        if account.pw_uid <= 0 or group.gr_gid <= 0 or account.pw_gid != group.gr_gid:
            raise Unsupported('haproxy-account')
        self.uid, self.gid = account.pw_uid, group.gr_gid
        self.record('account.metadata.json', {'uid': self.uid, 'gid': self.gid})

    def reserve(self):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reservations.append(tcp)
        tcp.bind(('127.0.0.1', 0))
        port = tcp.getsockname()[1]
        if port < 1024:
            raise Unsupported('high-port-reservation')
        abstract = 'nathaya-probe-' + secrets.token_hex(16)
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.reservations.append(unix)
        # HAProxy abns@ uses sizeof(sockaddr_un.sun_path), including zero padding.
        # Passing bytes (not a pathname) reserves that EXACT 108-byte address.
        unix.bind((b'\x00' + abstract.encode('ascii')).ljust(108, b'\x00'))
        return port, abstract

    def release_reservations(self):
        while self.reservations:
            self.reservations.pop().close()

    def factory(self, phase):
        if phase not in ('plain', 'trace'):
            raise ValueError('probe-phase')
        directory = self.directory / phase
        directory.mkdir(mode=0o700)
        port, abstract = self.reserve()
        config = self.save(phase + '/haproxy.cfg', make_config(port, abstract))
        output = self.save(phase + '/combined.log', b'')
        go = directory / 'go'
        unit = 'nathaya-haproxy-probe-' + self.nonce + '-' + phase + '.service'
        argv = [HAPROXY, '-W', '-db', '-f', str(config)]
        if phase == 'trace':
            argv = trace_command(argv)
        pre = ['/usr/bin/python3', '-I', '-B', str(self.directory / 'gate.py'), str(go)]
        # Never interpolate show values. Every CLI property is a constant, a
        # validated capability token set, or a private generated path/nonce.
        properties = {
            'Description': 'Nathaya HAProxy probe ' + self.nonce + ' ' + phase,
            'Type': 'simple', 'User': 'root', 'Group': 'root', 'UMask': '0077',
            'Slice': 'system.slice', 'NoNewPrivileges': 'yes', 'PrivateTmp': 'yes',
            'ProtectSystem': 'strict', 'ProtectHome': 'yes',
            'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes',
            'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
            'RestrictAddressFamilies': 'AF_INET AF_INET6 AF_UNIX',
            'CapabilityBoundingSet': ' '.join(sorted(self.caps)), 'AmbientCapabilities': '',
            'ReadWritePaths': LOGS, 'Restart': 'no', 'RestartSec': '3s',
            'RuntimeMaxSec': '8s', 'TimeoutStartSec': '5s', 'TimeoutStopSec': '2s',
            'TimeoutAbortSec': '2s',
            'KillMode': 'control-group', 'SendSIGKILL': 'yes',
            'ExecStartPre': ' '.join(pre),
            'StandardOutput': 'append:' + str(output), 'StandardError': 'append:' + str(output),
        }
        # SecureBits=0 and an empty SystemCallFilter are defaults. In particular
        # systemd-run's transient API does NOT accept all unit-file zero syntax.
        # Omit them, then require their effective values before releasing gate.
        command = ['/usr/bin/systemd-run', '--no-block', '--unit=' + unit,
                   '--description=' + properties['Description'], '--service-type=simple']
        for key, value in properties.items():
            if key not in ('Description', 'Type'):
                command += ['--property=' + key + '=' + value]
        command += ['--'] + argv
        return {'phase': phase, 'unit': unit, 'command': command, 'argv': argv,
                'pre': pre, 'go': go, 'output': output, 'properties': properties}

    def validate_probe(self, probe, plan):
        unit = plan['unit']
        if not owned_unit(probe, unit, self.nonce):
            raise Unsupported('probe-ownership')
        _require(probe, {
            'Id': unit, 'LoadState': 'loaded', 'DropInPaths': '', 'NeedDaemonReload': 'no',
            'Slice': 'system.slice', 'ControlGroup': '/system.slice/' + unit,
            'Transient': 'yes', 'User': 'root', 'Group': 'root', 'Type': 'simple',
            'Restart': 'no', 'RuntimeMaxUSec': '8s', 'TimeoutStartUSec': '5s',
            'TimeoutStopUSec': '2s', 'TimeoutAbortUSec': '2s', 'CanReload': 'no',
            'KillMode': 'control-group', 'SendSIGKILL': 'yes',
            'StandardOutput': 'append', 'StandardError': 'append',
            'StandardOutputFile': str(plan['output']), 'StandardErrorFile': str(plan['output']),
            'SecureBits': '0', 'NoNewPrivileges': 'yes',
        })
        for key, argv in (('ExecStart', plan['argv']), ('ExecStartPre', plan['pre'])):
            if not _exec_struct(probe.get(key, ''), argv):
                raise Unsupported(key)
            if key + 'Ex' in probe and not _exec_struct(probe[key + 'Ex'], argv):
                raise Unsupported(key + 'Ex')
        if probe.get('ExecReload') != '' or probe.get('ExecReloadEx', '') != '':
            raise Unsupported('ExecReload')

    def gate(self, plan):
        unit = plan['unit']
        # This starts BEFORE systemd-run, hence before the child's four-second
        # timer. Never mistake an expired/missed prestart gate for HAProxy failure.
        deadline = plan['created_at'] + 3.4
        probe = None
        while time.monotonic() < deadline:
            probe = self.show(unit, timeout=max(0.01, deadline - time.monotonic()))
            if not owned_unit(probe, unit, self.nonce):
                raise Unsupported('probe-ownership')
            if (probe.get('ActiveState') == 'activating' and
                    probe.get('SubState') == 'start-pre' and
                    probe.get('ControlPID', '0') != '0'):
                break
            if probe.get('ActiveState') in ('failed', 'inactive'):
                raise Unsupported('prestart-unavailable')
            time.sleep(0.05)
        else:
            raise Unsupported('prestart-unavailable')
        # Re-read the production unit and bytes immediately before comparison.
        _no_lock()
        current = self.show(MAIN, timeout=max(0.01, deadline - time.monotonic()))
        raw, metadata = _read_private_source(FRAGMENT, 65536)
        validate_effective(current, validate_fragment(raw.decode('utf-8', 'strict')))
        if raw != self.source_bytes or restriction_differences(self.source, current):
            raise Unsupported('source-profile-changed')
        self.record(plan['phase'] + '/source-gate.metadata.json', metadata)
        self.record(plan['phase'] + '/probe-gate.show.json', probe)
        self.validate_probe(probe, plan)
        differences = restriction_differences(current, probe)
        ignored = {k: {'source': current.get(k), 'probe': probe.get(k),
                       'category': 'intended' if k in INTENDED_PROPERTIES else 'runtime-metadata'}
                   for k in sorted(set(current) | set(probe))
                   if current.get(k) != probe.get(k) and k in RUNTIME_PROPERTIES | INTENDED_PROPERTIES}
        self.record(plan['phase'] + '/comparison.json', {'ignored': ignored, 'unsupported': differences})
        if differences:
            raise Unsupported('properties:' + ','.join(differences))
        # Both comparison and gate must be live at the instant of release. The
        # write uses O_EXCL: the complete empty, mode-0600 file appears atomically.
        if time.monotonic() >= deadline:
            raise Unsupported('prestart-deadline')
        live = self.show(unit, timeout=max(0.01, deadline - time.monotonic()))
        self.validate_probe(live, plan)
        if (not owned_unit(live, unit, self.nonce) or
                live.get('ActiveState') != 'activating' or live.get('SubState') != 'start-pre' or
                live.get('ControlPID') != probe.get('ControlPID') or
                restriction_differences(probe, live) or time.monotonic() >= deadline):
            raise Unsupported('prestart-unavailable')
        _no_lock()
        self.release_reservations()
        self.save(plan['phase'] + '/go', b'')

    def capture(self, unit, sample):
        """Stage bounded metadata on an anchored task FD, then validate and save.

        Never reopen a PID path after anchoring: a reused PID must not redirect
        any read to a different task. No maps, environment, arguments or memory.
        """
        if not _capture_unit(unit, self.nonce):
            raise Unsupported('probe-ownership')
        cg = '/system.slice/' + unit
        membership = ('0::' + cg + '\n').encode('ascii')
        captures, errors, exe_unavailable = [], [], False

        def bounded(name, limit, directory=None):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
            try:
                data = bytearray()
                while len(data) <= limit:
                    block = os.read(fd, min(4096, limit + 1 - len(data)))
                    if not block:
                        return bytes(data)
                    data.extend(block)
                raise ValueError('proc-size')
            finally:
                os.close(fd)

        def executable(directory):
            try:
                return os.readlink('exe', dir_fd=directory), None
            except OSError as exc:
                return None, exc.errno

        try:
            raw = bounded('/sys/fs/cgroup' + cg + '/cgroup.procs', 4096)
            fields = raw.split()
            if len(fields) > 256 or any(not re.fullmatch(rb'[1-9][0-9]{0,9}', p) for p in fields):
                raise ValueError('cgroup-procs')
            pids = sorted(set(map(int, fields)))
        except (OSError, ValueError) as exc:
            self.record(sample + '.json', {'unavailable': type(exc).__name__})
            return []
        for pid in pids:
            directory = None
            prefix = sample + '-pid-' + str(pid)
            try:
                directory = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC)
                if bounded('cgroup', 4096, directory) != membership:
                    errors.append({'pid': pid, 'error': 'membership-before'})
                    continue
                identity = _proc_identity(bounded('stat', 4096, directory))
                if identity[0] != pid:
                    raise ValueError('pid')
                before_exe = executable(directory)
                exe_unavailable |= before_exe[0] is None
                status = bounded('status', 65536, directory)
                parsed = _status(status.decode('utf-8', 'strict'))
                if parsed['Pid'] != pid:
                    raise ValueError('pid')
                staged = {'status': status, 'cgroup': membership}
                for name in ('uid_map', 'gid_map'):
                    try:
                        staged[name] = bounded(name, 65536, directory)
                    except (OSError, ValueError) as exc:
                        errors.append({'pid': pid, 'file': name, 'error': type(exc).__name__,
                                       'errno': getattr(exc, 'errno', None)})
                after_exe = executable(directory)
                exe_unavailable |= after_exe[0] is None
                if before_exe != after_exe:
                    raise ValueError('exe-changed')
                if _proc_identity(bounded('stat', 4096, directory)) != identity:
                    errors.append({'pid': pid, 'error': 'identity-after'})
                    continue
                # Last read before persistence; all prior bytes remain in memory
                # until BOTH task identity and exact membership are revalidated.
                if bounded('cgroup', 4096, directory) != membership:
                    errors.append({'pid': pid, 'error': 'membership-after'})
                    continue
                link, link_errno = after_exe
                if link is None:
                    exe_unavailable = True
                    errors.append({'pid': pid, 'error': 'exeUnavailable', 'errno': link_errno})
                else:
                    staged['exe'] = (link + '\n').encode('utf-8')
                for name, data in staged.items():
                    self.save(prefix + '.' + name, data)
                if link is not None:
                    captures.append({'exe': link, 'status': parsed})
            except (OSError, ValueError) as exc:
                errors.append({'pid': pid, 'error': type(exc).__name__, 'errno': getattr(exc, 'errno', None)})
            finally:
                if directory is not None:
                    os.close(directory)
        self.record(sample + '.json', {'pids': pids, 'errors': errors})
        # Persist capability evidence even when exe is denied, but do not let an
        # incomplete executable inventory establish an observed startup identity.
        return [] if exe_unavailable else captures

    def identity(self, captures, properties, traced):
        haproxy = [p['status'] for p in captures if p['exe'] == HAPROXY]
        masters = [p for p in haproxy if p['Uid'] == (0,) * 4 and p['Gid'] == (0,) * 4]
        if len(masters) != 1:
            return None
        master = masters[0]
        mask = sum(1 << CAP_BITS[c] for c in self.caps)
        if (any(master[k] != mask for k in ('CapEff', 'CapPrm', 'CapBnd')) or
                master['CapAmb'] != 0 or master['NoNewPrivs'] != 1):
            return None
        workers = [p for p in haproxy if p['Pid'] != master['Pid']]
        if not workers:
            return None
        for worker in workers:
            if (worker['PPid'] != master['Pid'] or worker['Uid'] != (self.uid,) * 4 or
                    worker['Gid'] != (self.gid,) * 4 or any(g != self.gid for g in worker['Groups']) or
                    any(worker[k] != 0 for k in ('CapEff', 'CapPrm', 'CapAmb')) or
                    worker['CapBnd'] != mask or worker['NoNewPrivs'] != 1):
                return None
        if traced:
            tracers = [p['status'] for p in captures if p['exe'] == '/usr/bin/strace']
            if (not any(str(p['Pid']) == properties.get('MainPID') for p in tracers) or
                    master['PPid'] not in [p['Pid'] for p in tracers]):
                return None
        elif str(master['Pid']) != properties.get('MainPID'):
            return None
        return (master['Pid'], tuple(sorted(p['Pid'] for p in workers)))

    def observe(self, plan):
        start, stable_since, previous, count = time.monotonic(), None, None, 0
        before = self.show(plan['unit'])
        self.record(plan['phase'] + '/before.show.json', before)
        last = before
        while time.monotonic() - start < 3.0:
            last = self.show(plan['unit'])
            if not owned_unit(last, plan['unit'], self.nonce):
                raise Unsupported('probe-ownership')
            if last.get('ControlGroup') != '/system.slice/' + plan['unit']:
                stable_since, previous = None, None
                break
            captures = self.capture(plan['unit'], plan['phase'] + '/sample-%03d' % count)
            count += 1
            identity = self.identity(captures, last, plan['phase'] == 'trace')
            if identity and last.get('ActiveState') == 'active' and last.get('SubState') == 'running':
                if identity != previous:
                    stable_since = time.monotonic()
                previous = identity
            else:
                stable_since, previous = None, None
            if last.get('ActiveState') in ('failed', 'inactive'):
                break
            time.sleep(0.1)
        after = self.show(plan['unit'])
        self.record(plan['phase'] + '/after.show.json', after)
        if not owned_unit(after, plan['unit'], self.nonce):
            raise Unsupported('probe-ownership')
        final_identity = None
        if after.get('ControlGroup') == '/system.slice/' + plan['unit']:
            final_captures = self.capture(plan['unit'], plan['phase'] + '/sample-final')
            final_identity = self.identity(final_captures, after, plan['phase'] == 'trace')
        if (stable_since is not None and time.monotonic() - stable_since >= 2.0 and
                final_identity == previous and final_identity is not None and
                after.get('ActiveState') == 'active' and after.get('SubState') == 'running' and
                after.get('MainPID') == last.get('MainPID')):
            result = 'observed-running'
        elif (after.get('ActiveState') == 'failed' or after.get('Result') not in ('success', '') or
                after.get('ExecMainStatus') not in ('0', '')):
            result = 'failed'
        else:
            result = 'unavailable'
        self.record(plan['phase'] + '/observation.json', {
            'startup': result, 'samples': count, 'elapsed': time.monotonic() - start,
            # In particular, a fast exit provides NO invented process identity.
            'identity': 'stable-observed' if result == 'observed-running' else 'unavailable',
        })
        return result

    def cleanup_one(self, unit):
        """Bounded unit-only cleanup. Never signal a PID or a production unit."""
        try:
            info = self.show(unit, absent=True)
            if info.get('LoadState') == 'not-found':
                # After interruption/timeout a create request might still be
                # pending on DBus. Absence is NOT confirmation in that case.
                return unit in self.creation_confirmed
            if not owned_unit(info, unit, self.nonce):
                return False
            self.creation_confirmed.add(unit)
            self.command(['/usr/bin/systemctl', 'stop', '--no-block', unit])
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                info = self.show(unit, absent=True, timeout=max(0.01, deadline - time.monotonic()))
                if info.get('LoadState') == 'not-found':
                    return True
                if not owned_unit(info, unit, self.nonce):
                    return False
                if info.get('ActiveState') in ('inactive', 'failed') and info.get('ControlGroup') == '':
                    return True
                time.sleep(0.1)
            # Revalidate immediately before sending a unit-scoped SIGKILL.
            info = self.show(unit)
            if not owned_unit(info, unit, self.nonce):
                return False
            self.command(['/usr/bin/systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', unit])
            info = self.show(unit, absent=True)
            return (info.get('LoadState') == 'not-found' or
                    (owned_unit(info, unit, self.nonce) and
                     info.get('ActiveState') in ('inactive', 'failed') and info.get('ControlGroup') == ''))
        except (OSError, ValueError, subprocess.SubprocessError):
            return False

    def run_phase(self, phase):
        _no_lock()
        plan = self.factory(phase)
        if self.show(plan['unit'], absent=True).get('LoadState') != 'not-found':
            raise Unsupported('unit-name-conflict')
        # Persist and register intent BEFORE systemd-run; interrupted creation
        # must still undergo ownership checks in finally/cleanup.
        self.intents.append(plan['unit'])
        self.record(phase + '/intent.json', {'unit': plan['unit'], 'nonce': self.nonce,
                                           'command': plan['command']})
        plan['created_at'] = time.monotonic()
        code, _, _ = self.command(plan['command'])
        if code != 0:
            raise Unsupported('transient-create-unavailable')
        self.creation_confirmed.add(plan['unit'])
        self.gate(plan)
        result = self.observe(plan)
        self.record(phase + '/startup.json', {'status': result})
        if not self.cleanup_one(plan['unit']):
            self.cleanup_confirmed = False
            raise Unsupported('cleanup-unconfirmed')
        self.intents.remove(plan['unit'])
        self.release_reservations()
        if phase == 'trace':
            # Read only this run's private combined output. Never return raw log.
            with plan['output'].open('rb') as stream:
                raw = stream.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                trace = {'available': False, 'counts': [], 'identity_calls': 0, 'records': 0}
            else:
                trace = sanitise_trace(raw.decode('utf-8', 'replace'))
            self.record('trace/sanitised.json', trace)
            return result, trace
        return result, None

    def cleanup(self):
        self.release_reservations()
        for unit in tuple(reversed(self.intents)):
            if self.cleanup_one(unit):
                self.intents.remove(unit)
            else:
                self.cleanup_confirmed = False
        return self.cleanup_confirmed and not self.intents


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv) != ['--run']:
        print('Usage: bash tools/diagnose-haproxy.sh --help | --run', file=sys.stderr)
        return 64
    controller, status, exitcode = Controller(), 'unavailable', 2
    interrupted = False
    old_handlers = {}

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, interrupt)
        controller.prepare()
        status, _ = controller.run_phase('plain')
        print('plain startup: ' + status)
        if status == 'observed-running':
            exitcode = 0
        elif status == 'failed':
            if os.path.isfile('/usr/bin/strace'):
                _secure_path('/usr/bin/strace')
                print('NOTICE: traced run does NOT represent the untraced run.')
                traced_status, trace = controller.run_phase('trace')
                print('trace startup: ' + traced_status)
                print('trace evidence: ' + ('available' if trace['available'] else 'unavailable'))
                if trace['counts']:
                    print('Observed trace errors (may be partial; not proof of untraced cause):')
                    for row in trace['counts']:
                        print(row['syscall'] + ' ' + row['errno'] + ' count=' + str(row['count']))
            else:
                print('trace evidence: unavailable (strace not installed)')
    except Unsupported as exc:
        # All Unsupported labels originate in constants or parse_show keys.
        print('unsupported: ' + str(exc))
    except KeyboardInterrupt:
        interrupted = True
        print('interrupted: cleanup requested')
        exitcode = 130
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError):
        print('unavailable: inspection or runtime evidence incomplete')
    finally:
        # Ignore a second INT/TERM while bounded cleanup runs. SIGKILL/power loss
        # cannot be handled; RuntimeMaxSec is the independent service guard.
        for signum in old_handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            clean = controller.cleanup()
        except (OSError, ValueError, subprocess.SubprocessError):
            clean = False
        if not clean:
            print('cleanup: unconfirmed; inspect private evidence (RuntimeMaxSec=8s was requested)')
            if not interrupted:
                exitcode = 2
        if controller.directory is not None:
            print('private evidence: ' + str(controller.directory))
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    return exitcode


if __name__ == '__main__':
    raise SystemExit(main())
NATHAYA_HAPROXY_DIAG_PY
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    nathaya_diagnose_haproxy_main "$@"
fi
