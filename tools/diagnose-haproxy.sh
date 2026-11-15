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
  watchdog_behavior(value) -> 'disabled' (only raw '0' or 'infinity')
  restriction_differences(source, probe) -> sorted list[str]
  Controller.audit_compatibility(...) -> private aggregate dict (pure, no IO)
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
    def __init__(self, message, *, labels=None):
        self.labels = tuple(labels) if labels is not None else (message,)
        super().__init__(';'.join(self.labels))


def collect_unsupported(errors, operation, *args, **kwargs):
    """Collect independent known validation failures; never hide programming errors."""
    try:
        return operation(*args, **kwargs)
    except Unsupported as exc:
        errors.extend(exc.labels)
        return None


def _raise_unsupported(errors):
    if errors:
        raise Unsupported('aggregate', labels=sorted(set(errors)))


def watchdog_behavior(value):
    """Only the two proven v255 disabled representations are equivalent.

    service.c: service_start_watchdog/service_get_watchdog_usec; service.h:
    watchdog_original_usec starts at USEC_INFINITY; time-util.h:
    timestamp_is_set(t) is t > 0 && t != USEC_INFINITY. This normalizes timer
    behavior only, never watchdog timestamps or a failure's root cause.
    https://github.com/systemd/systemd/blob/v255/src/core/service.c
    https://github.com/systemd/systemd/blob/v255/src/core/service.h
    https://github.com/systemd/systemd/blob/v255/src/basic/time-util.h
    """
    if isinstance(value, str) and value in ('0', 'infinity'):
        return 'disabled'
    raise Unsupported('WatchdogUSec')


def _watchdog_kind(properties):
    if 'WatchdogUSec' not in properties:
        return 'missing'
    value = properties['WatchdogUSec']
    if not isinstance(value, str):
        return 'invalid-type'
    if value == '0':
        return 'zero'
    if value == 'infinity':
        return 'infinity'
    if value == '':
        return 'empty'
    if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?(?:us|ms|s|min|h|d|w)?', value):
        return 'finite'
    return 'unknown'


def _property_name(key):
    return key if isinstance(key, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', key) else 'property-name'


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
    if not isinstance(text, str):
        raise Unsupported('CapabilityBoundingSet')
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
        elif section == 'Service' and key in ('StandardOutput', 'StandardError'):
            # Validate the logging mode only. The production pathname is neither
            # needed nor reused for a probe, and is never expanded/evaluated.
            if not value.startswith('append:') or not value[len('append:'):]:
                raise Unsupported('fragment-value')
        elif value != expected[section][key]:
            raise Unsupported('fragment-value')
        result[key] = value
    required = set(UNIT_FIELDS) | set(SERVICE_FIELDS) | set(INSTALL_FIELDS) | {'CapabilityBoundingSet'}
    if set(result) != required or seen_sections != set(expected):
        raise Unsupported('fragment-missing')
    return result


def _require(properties, expected):
    bad = [_property_name(k) for k, v in expected.items() if properties.get(k) != v]
    if bad:
        raise Unsupported('properties:' + ','.join(sorted(bad)))


# These lists describe UNUSED hooks in two different, validated contexts.
# ExecStart and the probe's ExecStartPre gate are NEVER optional empty hooks.
SOURCE_EMPTY_EXEC_HOOKS = ('ExecStartPre', 'ExecStartPost', 'ExecCondition',
                           'ExecStop', 'ExecStopPost')
PROBE_EMPTY_EXEC_HOOKS = ('ExecReload', 'ExecStartPost', 'ExecCondition',
                          'ExecStop', 'ExecStopPost')
EMPTY_EXEC_FIELDS = frozenset(name + suffix
                              for name in SOURCE_EMPTY_EXEC_HOOKS + PROBE_EMPTY_EXEC_HOOKS
                              for suffix in ('', 'Ex'))


def _checked_empty_exec_fields(properties, fields):
    try:
        fields = frozenset(fields)
    except (TypeError, ValueError):
        raise Unsupported('empty-hook-proof-scope') from None
    if not fields <= EMPTY_EXEC_FIELDS:
        raise Unsupported('empty-hook-proof-scope')
    errors = ['active-hook:' + key for key in sorted(fields)
              if key in properties and properties[key] != '']
    _raise_unsupported(errors)
    return fields


def _source_empty_exec_fields(properties, fragment):
    # Proof requires the whole audited fragment AND no drop-ins/reload/active
    # unused hooks. Collect independent errors, but never issue partial proof.
    errors = []
    collect_unsupported(errors, _require, properties,
                        {'Id': MAIN, 'LoadState': 'loaded', 'FragmentPath': FRAGMENT,
                         'DropInPaths': '', 'NeedDaemonReload': 'no'})
    fields = frozenset(name + suffix for name in SOURCE_EMPTY_EXEC_HOOKS
                       for suffix in ('', 'Ex'))
    collect_unsupported(errors, _checked_empty_exec_fields, properties, fields)
    if not isinstance(fragment, dict):
        errors.append('source-hook-fragment-uncertain')
    else:
        for key in sorted(fields & set(fragment)):
            errors.append('source-hook-defined-in-fragment:' + key)
        expected_values = {**UNIT_FIELDS, **SERVICE_FIELDS, **INSTALL_FIELDS}
        if set(fragment) != set(expected_values) | {'CapabilityBoundingSet'}:
            errors.append('source-hook-fragment-uncertain')
        for key, value in fragment.items():
            if not isinstance(value, str):
                errors.append('source-hook-fragment-uncertain')
            elif key == 'CapabilityBoundingSet':
                caps = collect_unsupported(errors, _capset, value)
                if caps not in (CAPS3, CAPS4):
                    errors.append('source-hook-fragment-uncertain')
            elif key in ('StandardOutput', 'StandardError'):
                if not value.startswith('append:') or not value[len('append:'):]:
                    errors.append('source-hook-fragment-uncertain')
            elif key not in expected_values or value != expected_values[key]:
                errors.append('source-hook-fragment-uncertain')
    _raise_unsupported(errors)
    return fields


def _exec_struct(value, argv):
    """Validate one show Exec* structure against our exact command factory.

    Only bookkeeping fields may follow argv[]. No second command is allowed.
    The fields are read only, and no show value ever becomes command syntax.
    """
    if (not isinstance(value, str) or not isinstance(argv, (list, tuple)) or not argv
            or any(not isinstance(arg, str) for arg in argv)
            or not value.startswith('{ ') or not value.endswith(' }')):
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
    """Collect the complete unsupported profile, returning source caps if valid."""
    if not isinstance(properties, dict):
        raise Unsupported('source-snapshot-format')
    errors = []
    collect_unsupported(errors, _require, properties, {
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
        # The production log pathname is not needed and is not always exposed
        # by systemd's D-Bus interface. Never infer an absent property as empty.
    })
    collect_unsupported(errors, _source_empty_exec_fields, properties, fragment)
    collect_unsupported(errors, watchdog_behavior, properties.get('WatchdogUSec'))
    caps = collect_unsupported(errors, _capset, properties.get('CapabilityBoundingSet'))
    fragment_caps = collect_unsupported(errors, _capset,
                                       fragment.get('CapabilityBoundingSet') if isinstance(fragment, dict) else None)
    if caps not in (CAPS3, CAPS4) or caps != fragment_caps:
        errors.append('CapabilityBoundingSet')
    families = properties.get('RestrictAddressFamilies')
    families = families.split() if isinstance(families, str) else []
    if len(families) != 3 or set(families) != {'AF_INET', 'AF_INET6', 'AF_UNIX'}:
        errors.append('RestrictAddressFamilies')
    # Only an empty deny list is supported. Never translate an allow-list to deny.
    if properties.get('SystemCallFilter') != '~':
        errors.append('SystemCallFilter')
    for name, argv in (('ExecStart', SERVICE_FIELDS['ExecStart'].split()),
                       ('ExecReload', ['/bin/kill', '-USR2', '$MAINPID'])):
        if not _exec_struct(properties.get(name), argv):
            errors.append(name)
        if name + 'Ex' in properties and not _exec_struct(properties[name + 'Ex'], argv):
            errors.append(name + 'Ex')
    _raise_unsupported(errors)
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


# Only these two logging metadata fields may be absent. This exception is NOT
# a fallback for output modes, security restrictions, or other unknown fields.
OPTIONAL_LOG_PROPERTIES = frozenset(('StandardOutputFile', 'StandardErrorFile'))


def _equivalent(key, value):
    if key == 'WatchdogUSec':
        return watchdog_behavior(value)
    if key in ('CapabilityBoundingSet', 'AmbientCapabilities'):
        return _capset(value)
    if key == 'RestrictAddressFamilies':
        if not isinstance(value, str):
            raise Unsupported('RestrictAddressFamilies')
        return tuple(sorted(value.split()))
    # Empty allow-list output is NOT equivalent to the known empty deny-list '~'.
    return value


def _comparison_inventory(source, probe, *, empty_source=(), empty_probe=(), pair=True):
    """Private raw inventory; no value from here belongs on the console."""
    rows, differences = [], []
    ignored = {key: {'source': source.get(key), 'probe': probe.get(key),
                     'category': 'intended' if key in INTENDED_PROPERTIES else 'runtime-metadata'}
               for key in sorted(set(source) | set(probe))
               if key in source and key in probe and source[key] != probe[key]
               and key in RUNTIME_PROPERTIES | INTENDED_PROPERTIES}
    keys = set(source) | set(probe)
    for key in sorted(keys):
        sp, pp = key in source, key in probe
        sv, pv = source.get(key), probe.get(key)
        bad, reason = False, 'equal'
        if not sp or not pp:
            classification = 'missing-source' if not sp else 'missing-probe'
            if not pair:
                reason = 'snapshot-not-supplied'
            elif key in OPTIONAL_LOG_PROPERTIES:
                classification, reason = 'intentional-metadata', 'optional-log-metadata'
            elif ((key in INTENDED_PROPERTIES and key in set(empty_source) | set(empty_probe)) or
                  (not sp and key in empty_source and pv == '') or
                  (not pp and key in empty_probe and sv == '') or
                  (not sp and not pp and key in set(empty_source) & set(empty_probe))):
                classification, reason = 'validated-empty-exec', 'scoped-hook-proof'
            else:
                bad, reason = True, 'missing-property-no-validated-equivalence'
        elif sv == '' and pv == '' and key in set(empty_source) & set(empty_probe):
            classification, reason = 'validated-empty-exec', 'scoped-hook-proof'
        elif key in RUNTIME_PROPERTIES | INTENDED_PROPERTIES:
            classification, reason = 'intentional-metadata', (
                'intended' if key in INTENDED_PROPERTIES else 'runtime-metadata')
            if sv != pv:
                ignored[key] = {'source': sv, 'probe': pv, 'category': reason}
        else:
            normalization_errors = []
            a = collect_unsupported(normalization_errors, _equivalent, key, sv)
            b = collect_unsupported(normalization_errors, _equivalent, key, pv)
            if normalization_errors:
                # A policy rejection is not proof that two identical raw values
                # differ. Keep this separate from an observed value mismatch.
                classification = 'unsupported-value' if sv == pv else 'value-different'
                bad, reason = True, 'unsupported-normalization'
            elif a == b:
                classification = 'normalized-equal'
                reason = 'equal' if sv == pv else 'explicit-normalization'
            else:
                classification, bad, reason = 'value-different', True, 'behavior-different'
        row = {'property': key, 'source_present': sp, 'probe_present': pp,
               'source': sv, 'probe': pv, 'raw_equal': sp and pp and sv == pv,
               'classification': classification, 'unsupported': bad, 'reason': reason}
        if key == 'WatchdogUSec':
            row['source_kind'], row['probe_kind'] = _watchdog_kind(source), _watchdog_kind(probe)
            row['source_behavior'] = 'disabled' if isinstance(sv, str) and sv in ('0', 'infinity') else None
            row['probe_behavior'] = 'disabled' if isinstance(pv, str) and pv in ('0', 'infinity') else None
        rows.append(row)
        if bad:
            differences.append(key)
    return {'ignored': ignored, 'unsupported': differences, 'properties': rows,
            'mismatches': [row for row in rows if row['unsupported']],
            'validated_empty_exec': {
                'source': sorted(empty_source), 'probe': sorted(empty_probe),
                'source_absent': sorted(k for k in empty_source if k not in source),
                'probe_absent': sorted(k for k in empty_probe if k not in probe)}}


def restriction_differences(source, probe, *, checked_empty_source=(), checked_empty_probe=()):
    """Strict differences; unused-hook equivalence requires validated scoped proof.

    No prefix exemptions and no security repairs. This is not authorization to
    execute: required-field/command validation must also succeed independently.
    """
    empty_source = _checked_empty_exec_fields(source, checked_empty_source)
    empty_probe = _checked_empty_exec_fields(probe, checked_empty_probe)
    comparison = _comparison_inventory(source, probe, empty_source=empty_source,
                                       empty_probe=empty_probe)
    _raise_unsupported([_property_name(row['property']) for row in comparison['properties']
                        if row['reason'] == 'unsupported-normalization'])
    return comparison['unsupported']


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

    def _audit_show(self, unit, errors, timeout=3):
        try:
            return self.show(unit, timeout=timeout)
        except Unsupported as exc:
            errors.extend(exc.labels)
        except OSError:
            errors.append('source-show-unavailable' if unit == MAIN else 'probe-show-unavailable')
        return None

    def _audit_fragment(self, stem, metadata_name=None):
        """Read/parse failures remain explicit; persistence failures propagate."""
        errors = []
        try:
            raw, metadata = _read_private_source(FRAGMENT, 65536)
        except Unsupported as exc:
            errors.extend(exc.labels)
            errors.append('source-fragment-read-unavailable')
            return None, None, errors
        except OSError:
            return None, None, ['source-fragment-read-unavailable']
        if stem == 'production.fragment':
            self.save(stem, raw)  # Existing production-fragment evidence format.
        else:
            self.record(stem + '.json', {'raw_hex': raw.hex()})
        self.record(metadata_name or stem + '.metadata.json', metadata)
        try:
            text = raw.decode('utf-8', 'strict')
        except UnicodeError:
            return raw, None, ['fragment-format']
        fragment = collect_unsupported(errors, validate_fragment, text)
        return raw, fragment, errors

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
        inspection_errors = []
        self.source = self._audit_show(MAIN, inspection_errors)
        if self.source is not None:
            self.save('production.show', ''.join(k + '=' + v + '\n' for k, v in self.source.items()))
        self.source_bytes, self.fragment, fragment_errors = self._audit_fragment('production.fragment')
        inspection_errors.extend(fragment_errors)
        audit = self.audit_compatibility(self.source, fragment=self.fragment,
                                         inspection_errors=inspection_errors, allow_source_only=True)
        self.record('source-audit.json', audit)
        _raise_unsupported(audit['issues'])
        self.caps = frozenset(audit['source_caps'])
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
            'TimeoutAbortSec': '2s', 'WatchdogSec': '0',
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

    def validate_probe_logging(self, probe, plan):
        # Never borrow the production destination, even if File metadata exists.
        phase = plan.get('phase')
        directory = str(self.directory)
        if (phase not in ('plain', 'trace') or not isinstance(self.directory, Path) or not re.fullmatch(
                r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+', directory)):
            raise Unsupported('probe-output-plan')
        destination = str(self.directory / phase / 'combined.log')
        errors = []
        if str(plan.get('output')) != destination:
            errors.append('probe-output-plan')
        argv, declared = plan.get('command'), plan.get('properties')
        if (not isinstance(argv, list) or any(not isinstance(a, str) for a in argv)
                or not isinstance(declared, dict)):
            raise Unsupported('probe-output-plan')
        assignments = collect_unsupported(errors, self._plan_assignments, plan)
        for key in ('StandardOutput', 'StandardError'):
            value = 'append:' + destination
            prefix = '--property=' + key + '='
            if (declared.get(key) != value or assignments is None or
                    [v for name, v in assignments if name == key] != [value] or
                    [a for a in argv if a.startswith(prefix)] != [prefix + value]):
                errors.append('probe-output-plan:' + key)
        for key in sorted(OPTIONAL_LOG_PROPERTIES):
            if key in probe and probe[key] != destination:
                errors.append(key)
        _raise_unsupported(errors)

    def _plan_assignments(self, plan):
        args = plan.get('command')
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise Unsupported('probe-hook-plan-uncertain')
        assignments, index = [], 0
        while index < len(args):
            arg, assignment = args[index], None
            if arg == '--':
                break
            if arg.startswith('--property='):
                assignment = arg[len('--property='):]
            elif arg in ('--property', '-p'):
                index += 1
                if index >= len(args):
                    raise Unsupported('probe-hook-plan-uncertain')
                assignment = args[index]
            elif arg.startswith('-p') and arg != '-p':
                assignment = arg[2:]
            if assignment is not None:
                name, separator, value = assignment.partition('=')
                if not separator or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', name):
                    raise Unsupported('probe-hook-plan-uncertain')
                assignments.append((name, value))
            index += 1
        return assignments

    def empty_probe_exec_fields(self, probe, plan):
        errors = []
        if not owned_unit(probe, plan.get('unit'), self.nonce):
            errors.append('probe-ownership')
        collect_unsupported(errors, _require, probe,
                            {'LoadState': 'loaded', 'DropInPaths': '', 'NeedDaemonReload': 'no'})
        fields = frozenset(name + suffix for name in PROBE_EMPTY_EXEC_HOOKS
                           for suffix in ('', 'Ex'))
        declared = plan.get('properties')
        assignments = collect_unsupported(errors, self._plan_assignments, plan)
        if not isinstance(declared, dict):
            errors.append('probe-hook-plan-uncertain')
        else:
            declarations = set(declared) | {key for key, _ in assignments or ()}
            errors.extend('probe-hook-declared:' + key for key in sorted(fields & declarations))
        collect_unsupported(errors, _checked_empty_exec_fields, probe, fields)
        _raise_unsupported(errors)
        return fields

    def _validate_probe_watchdog(self, probe, plan):
        errors = []
        collect_unsupported(errors, watchdog_behavior, probe.get('WatchdogUSec'))
        declared = plan.get('properties')
        assignments = collect_unsupported(errors, self._plan_assignments, plan)
        if (not isinstance(declared, dict) or declared.get('WatchdogSec') != '0'
                or assignments is None
                or [value for key, value in assignments if key == 'WatchdogSec'] != ['0']
                or plan.get('command', []).count('--property=WatchdogSec=0') != 1):
            errors.append('probe-watchdog-plan:WatchdogSec')
        # WatchdogUSec is the D-Bus alias; do not let a second spelling shadow
        # the single audited WatchdogSec=0 request before startup updates its getter.
        if ((isinstance(declared, dict) and 'WatchdogUSec' in declared) or
                any(key == 'WatchdogUSec' for key, _value in assignments or ())):
            errors.append('probe-watchdog-plan:WatchdogUSec')
        _raise_unsupported(errors)

    def _validate_probe_command_plan(self, plan):
        phase = plan.get('phase')
        if (phase not in ('plain', 'trace') or not isinstance(self.directory, Path) or not re.fullmatch(
                r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+', str(self.directory))):
            raise Unsupported('probe-command-plan')
        expected = [HAPROXY, '-W', '-db', '-f', str(self.directory / phase / 'haproxy.cfg')]
        if phase == 'trace':
            expected = trace_command(expected)
        pre = ['/usr/bin/python3', '-I', '-B', str(self.directory / 'gate.py'),
               str(self.directory / phase / 'go')]
        errors = []
        args = plan.get('command')
        if (plan.get('argv') != expected or not isinstance(args, list)
                or '--' not in args or args[args.index('--') + 1:] != expected):
            errors.append('probe-command-plan:ExecStart')
        declared = plan.get('properties')
        assignments = collect_unsupported(errors, self._plan_assignments, plan)
        if (plan.get('pre') != pre or str(plan.get('go')) != pre[-1]
                or not isinstance(declared, dict) or declared.get('ExecStartPre') != ' '.join(pre)
                or assignments is None
                or [v for k, v in assignments if k == 'ExecStartPre'] != [' '.join(pre)]):
            errors.append('probe-command-plan:ExecStartPre')
        _raise_unsupported(errors)

    def validate_probe(self, probe, plan):
        """Collect independent effective/plan/log/hook/argv failures; return None."""
        if not isinstance(probe, dict) or not isinstance(plan, dict):
            raise Unsupported('probe-snapshot-or-plan-format')
        errors = []
        unit = plan.get('unit')
        if not owned_unit(probe, unit, self.nonce):
            errors.append('probe-ownership')
        if not isinstance(unit, str):
            errors.append('probe-plan-unit')
            unit = ''
        collect_unsupported(errors, _require, probe, {
            'Id': unit, 'LoadState': 'loaded', 'DropInPaths': '', 'NeedDaemonReload': 'no',
            'Slice': 'system.slice', 'ControlGroup': '/system.slice/' + unit,
            'Transient': 'yes', 'User': 'root', 'Group': 'root', 'Type': 'simple',
            'Restart': 'no', 'RuntimeMaxUSec': '8s', 'TimeoutStartUSec': '5s',
            'TimeoutStopUSec': '2s', 'TimeoutAbortUSec': '2s', 'CanReload': 'no',
            'KillMode': 'control-group', 'SendSIGKILL': 'yes',
            'StandardOutput': 'append', 'StandardError': 'append',
            'SecureBits': '0', 'NoNewPrivileges': 'yes', 'AmbientCapabilities': '',
            'UMask': '0077', 'ProtectSystem': 'strict', 'ProtectHome': 'yes',
            'PrivateTmp': 'yes', 'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes',
            'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
            'ReadWritePaths': LOGS, 'PrivateNetwork': 'no', 'PrivateUsers': 'no',
            'JoinsNamespaceOf': '', 'RootDirectory': '', 'RootImage': '',
        })
        caps = collect_unsupported(errors, _capset, probe.get('CapabilityBoundingSet'))
        if caps not in (CAPS3, CAPS4):
            errors.append('CapabilityBoundingSet')
        families = probe.get('RestrictAddressFamilies')
        families = families.split() if isinstance(families, str) else []
        if len(families) != 3 or set(families) != {'AF_INET', 'AF_INET6', 'AF_UNIX'}:
            errors.append('RestrictAddressFamilies')
        if probe.get('SystemCallFilter') != '~':
            errors.append('SystemCallFilter')
        collect_unsupported(errors, self.validate_probe_logging, probe, plan)
        collect_unsupported(errors, self._validate_probe_watchdog, probe, plan)
        collect_unsupported(errors, self._validate_probe_command_plan, plan)
        for key, argv in (('ExecStart', plan.get('argv')), ('ExecStartPre', plan.get('pre'))):
            if not _exec_struct(probe.get(key), argv):
                errors.append(key)
            if key + 'Ex' in probe and not _exec_struct(probe[key + 'Ex'], argv):
                errors.append(key + 'Ex')
        collect_unsupported(errors, self.empty_probe_exec_fields, probe, plan)
        _raise_unsupported(errors)

    def audit_compatibility(self, source=None, probe=None, *, fragment=None, plan=None,
                            original=None, original_fragment=None,
                            original_bytes=None, current_bytes=None,
                            probe_source=False, inspection_errors=(), allow_source_only=False):
        """PURE aggregate audit of every supplied property (private JSON result).

        source/probe are parse_show dictionaries, not claims of full --all data.
        For probe->live use probe_source=True and the same validated plan.
        Original->current comparison additionally needs original_fragment; raw
        bytes, when both supplied, establish exact fragment-change evidence.
        No IO, execution, repairs, guessed hooks, or exception-based equivalence.
        """
        validation = {'source': [], 'probe': [], 'original': []}
        source_caps = None
        source_empty, probe_empty, original_empty = (), (), ()
        if source is not None:
            if probe_source:
                collect_unsupported(validation['source'], self.validate_probe, source, plan)
            else:
                source_caps = collect_unsupported(validation['source'], validate_effective, source, fragment)
            if not validation['source']:
                source_empty = (self.empty_probe_exec_fields(source, plan) if probe_source else
                                _source_empty_exec_fields(source, fragment))
        if probe is not None:
            collect_unsupported(validation['probe'], self.validate_probe, probe, plan)
            if not validation['probe']:
                probe_empty = self.empty_probe_exec_fields(probe, plan)
        if original is not None:
            collect_unsupported(validation['original'], validate_effective, original, original_fragment)
            if not validation['original']:
                original_empty = _source_empty_exec_fields(original, original_fragment)
        # A failed validation/inspection stage cannot issue any hook proof for
        # this aggregate. Conservative extra missing-hook reports are deliberate.
        if (any(validation.values()) or inspection_errors or
                (original_bytes is not None and current_bytes is not None and original_bytes != current_bytes)):
            source_empty, probe_empty, original_empty = (), (), ()
        # Invalid snapshots are never substituted as valid profiles. Empty maps
        # here are inventory inputs ONLY; validation/availability remain explicit.
        source_map = source if isinstance(source, dict) else {}
        probe_map = probe if isinstance(probe, dict) else {}
        pair = isinstance(source, dict) and isinstance(probe, dict)
        result = _comparison_inventory(source_map, probe_map, empty_source=source_empty,
                                       empty_probe=probe_empty, pair=pair)
        profile = None
        if original is not None and source is not None:
            profile = _comparison_inventory(original if isinstance(original, dict) else {}, source_map,
                                            empty_source=original_empty, empty_probe=source_empty)
            profile['raw_fragment_changed'] = (original_bytes != current_bytes
                                              if original_bytes is not None and current_bytes is not None else None)
            profile['changed'] = bool(profile['unsupported'] or profile['raw_fragment_changed'])
        validation = {key: sorted(set(values)) for key, values in validation.items()}
        issues = list(inspection_errors)
        for values in validation.values():
            issues.extend(values)
        if result['unsupported']:
            issues.append('properties:' + ','.join(_property_name(k) for k in result['unsupported']))
        if profile is not None and profile['changed']:
            issues.append('source-profile-changed')
        if source is None:
            issues.append('source-snapshot-unavailable')
        if probe is None and not allow_source_only:
            issues.append('probe-snapshot-unavailable')
        if source is None and probe is None:
            issues.append('snapshots-unavailable')
        if allow_source_only and probe is not None:
            issues.append('ambiguous-audit-scope')
        result.update({'validation': validation, 'inspection_errors': list(inspection_errors),
                       'issues': sorted(set(issues)), 'ok': not issues,
                       'snapshot_pair_supplied': pair,
                       'scope': 'source-only-preflight' if allow_source_only else 'pair-required',
                       'complete': pair and not issues and not allow_source_only,
                       'coverage': 'supplied-properties-only' if pair else 'partial',
                       'source_profile_change': profile,
                       'original_inventory': (_comparison_inventory(original, {}, pair=False)
                                              if isinstance(original, dict) else None),
                       'source_caps': sorted(source_caps) if source_caps is not None else None,
                       'hook_proof_valid': {'source': bool(source_empty), 'probe': bool(probe_empty)}})
        return result

    def gate(self, plan):
        unit = plan['unit']
        # Starts before systemd-run; do not release a missed/expired prestart.
        deadline = plan['created_at'] + 3.4
        probe, inspection_errors = None, []
        while time.monotonic() < deadline:
            probe = self._audit_show(unit, inspection_errors,
                                     timeout=max(0.01, deadline - time.monotonic()))
            if probe is None:
                break
            if not owned_unit(probe, unit, self.nonce):
                inspection_errors.append('probe-ownership')
                break
            if (probe.get('ActiveState') == 'activating' and
                    probe.get('SubState') == 'start-pre' and
                    probe.get('ControlPID', '0') != '0'):
                break
            if probe.get('ActiveState') in ('failed', 'inactive'):
                inspection_errors.append('prestart-unavailable')
                break
            time.sleep(0.05)
        else:
            inspection_errors.append('prestart-unavailable')
        # Even a lock refusal must not hide already available probe/diff failures.
        collect_unsupported(inspection_errors, _no_lock)
        current = self._audit_show(MAIN, inspection_errors,
                                  timeout=max(0.01, deadline - time.monotonic()))
        raw, current_fragment, fragment_errors = self._audit_fragment(
            plan['phase'] + '/source-gate.fragment', plan['phase'] + '/source-gate.metadata.json')
        inspection_errors.extend(fragment_errors)
        if probe is not None:
            self.record(plan['phase'] + '/probe-gate.show.json', probe)
        if current is not None:
            self.record(plan['phase'] + '/source-gate.show.json', current)
        audit = self.audit_compatibility(current, probe, fragment=current_fragment, plan=plan,
                                         original=self.source, original_fragment=self.fragment,
                                         original_bytes=self.source_bytes, current_bytes=raw,
                                         inspection_errors=inspection_errors)
        self.record(plan['phase'] + '/comparison.json', audit)
        self.record(plan['phase'] + '/logging-metadata.json', {
            'source_file_properties_available': {k: current is not None and k in current
                                                 for k in sorted(OPTIONAL_LOG_PROPERTIES)},
            'probe_file_properties_available': {k: probe is not None and k in probe
                                                for k in sorted(OPTIONAL_LOG_PROPERTIES)},
            'probe_destination': str(plan['output']),
            'destination_basis': 'explicit-private-transient-assignments',
        })
        _raise_unsupported(audit['issues'])
        # Persist a second aggregate, even if its ownership/argv/state is invalid.
        live_errors = []
        if time.monotonic() >= deadline:
            live_errors.append('prestart-deadline')
        live = self._audit_show(unit, live_errors,
                               timeout=max(0.01, deadline - time.monotonic()))
        if live is not None:
            self.record(plan['phase'] + '/probe-live.show.json', live)
        if (live is None or not owned_unit(live, unit, self.nonce) or
                live.get('ActiveState') != 'activating' or live.get('SubState') != 'start-pre' or
                live.get('ControlPID') != probe.get('ControlPID')):
            live_errors.append('prestart-unavailable')
        if time.monotonic() >= deadline:
            live_errors.append('prestart-deadline')
        collect_unsupported(live_errors, _no_lock)
        live_audit = self.audit_compatibility(probe, live, plan=plan, probe_source=True,
                                              inspection_errors=live_errors)
        self.record(plan['phase'] + '/live-comparison.json', live_audit)
        _raise_unsupported(live_audit['issues'])
        release_errors = []
        if time.monotonic() >= deadline:
            release_errors.append('prestart-deadline')
        collect_unsupported(release_errors, _no_lock)
        self.record(plan['phase'] + '/release-audit.json', {
            'issues': sorted(set(release_errors)), 'gate_released': False,
            'purpose': 'last refusal check before atomic go creation',
        })
        _raise_unsupported(release_errors)
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
