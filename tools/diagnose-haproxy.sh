#!/bin/bash
# Operator-only, opt-in diagnostic. Sourcing defines functions and does nothing.
nathaya_diagnose_haproxy_main() {
    case "$#:${1-}:${2-}" in
        1:--help:)
            builtin printf '%s\n' \
                'Usage: bash tools/diagnose-haproxy.sh --help | --run | --cap-boundaries | --cap-matrix | --nnp-ab [--reload-usr2 [--compare-cap-kill]]' \
                '--compare-cap-kill requires --nnp-ab --reload-usr2: NNP=no in both arms,' \
                'A=source CAPS3, B=CAPS3 plus only CAP_KILL; source CAP_KILL refuses.' \
                '--nnp-ab without comparison runs startup arms NNP=yes then no.' \
                '--nnp-ab --reload-usr2 optionally proves USR2 on the existing B arm before cleanup.' \
                'The option adds a fixed private HTTP responder to BOTH arms; no production change.' \
                'Without that option: no handshake/health, tracing or USR2/reload proof.' \
                'NNP=no loses the kernel exec-gain barrier; other hardening is not a replacement.' \
                '--cap-matrix tests a finite requested-restriction matrix using fixed Python only.' \
                '--cap-boundaries runs only fixed Python controls; no HAProxy, strace or listeners.' \
                '--help is read-only. --run requires root Ubuntu 24.04 amd64, systemd PID 1.' \
                'Creates bounded, private transient probes; never changes the production unit.' \
                'Evidence is preserved under /run/nathaya-haproxy-probe.* (root only).' \
                'An unsupported effective profile stops BEFORE HAProxy execution.' \
                'Tracing changes privilege/timing; traced results do not represent an untraced run.'
            return 0
            ;;
        1:--run:|1:--cap-boundaries:|1:--cap-matrix:|1:--nnp-ab:|2:--nnp-ab:--reload-usr2) ;;
        3:--nnp-ab:--reload-usr2) [[ "$3" == --compare-cap-kill ]] || return 64 ;;
        *) builtin printf '%s\n' 'Usage: bash tools/diagnose-haproxy.sh --help | --run | --cap-boundaries | --cap-matrix | --nnp-ab [--reload-usr2 [--compare-cap-kill]]' >&2; return 64 ;;
    esac
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C \
        /usr/bin/python3 -I -B - "$@" <<'NATHAYA_HAPROXY_DIAG_PY'
"""Self-contained, fail-closed HAProxy probe. Importing defines APIs only.

Pure public interfaces:
  parse_show(text) -> dict[str, str]
  validate_fragment(text) -> dict[str, str] (audited directives)
  validate_effective(properties, fragment) -> frozenset[str] (source caps)
  watchdog_behavior(value) -> 'disabled' (only raw '0' or 'infinity')
  restriction_differences(source, probe) -> sorted list[str]
  Controller.audit_compatibility(...) -> private aggregate dict (pure, no IO)
  make_config(port, abstract_name) -> str (legacy NO_TLS)
  make_ab_config(port, abstract_name, private_pem, reload_http=False, marker=None) -> str
  nnp_ab_plan(directory, nonce, caps, phase, reload_usr2=False, compare_cap_kill=False) -> closed A/B plan
  Controller.validate_nnp_ab(probe, plan) -> None (pure exact-plan proof)
  Controller.compare_nnp_ab(a, b, a_plan, b_plan) -> private raw inventory
  Controller.run_nnp_ab(reload_usr2=False) -> diagnostic exit code; nnp-ab.report.json
  Controller.capture(unit, sample, reload_evidence=False, deadline=None) -> anchored records
  Controller.reload_usr2(plan) -> private report; existing B only, clients closed on return
  trace_command(haproxy_argv) -> list[str]
  sanitise_trace(text) -> dict (no arguments, IDs or raw log text)
  owned_unit(properties, unit, nonce) -> bool
  matrix_plan(directory, nonce, caps, index, enabled_knob_names) -> fixed plan
  matrix_entry_state(records, caps, executable, entry_only=False) -> validated observation state
  Controller.matrix_mount_audit(a, b, source_plan=None, probe_plan=None, source=False) -> pure private proof
  Controller.matrix_mount_manager() -> one recorded system-manager Version sample (matrix only)
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
import select
import signal
import socket
import ssl
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
NNP_PHASES = ('nnp-yes', 'nnp-no')
CAP_KILL_PHASES = ('cap-kill-a', 'cap-kill-b')
AB_PHASES = NNP_PHASES + CAP_KILL_PHASES
RELOAD_OVERALL_SECONDS = 24.0
RELOAD_RELEASE_LIMIT_SECONDS = 29.0
RELOAD_STAGES = (('preparation', 5.0), ('new_worker', 5.0), ('continuity', 2.0),
                 ('old_worker_exit', 5.0), ('final_verification', 4.0))


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


def make_ab_config(port, abstract_name, private_pem, reload_http=False, marker=None):
    """Default bytes unchanged; opt-in responder is necessary for local reload proof."""
    if (not isinstance(private_pem, (str, Path)) or not re.fullmatch(
            r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+/nnp-ab/private.pem', str(private_pem))):
        raise Unsupported('ab-pem-path')
    config = make_config(port, abstract_name)  # Validates high port and abstract name.
    if type(reload_http) is not bool or (reload_http and
            (not isinstance(marker, str) or not re.fullmatch(r'[0-9a-f]{32}', marker))):
        raise Unsupported('ab-reload-marker')
    if reload_http:
        # %pid is HAProxy's log-format PID variable (NOT proc.pid):
        # https://docs.haproxy.org/2.8/configuration.html#8.2.6
        config = config.replace('    timeout client 2s\n    timeout server 2s\n',
                                '    timeout client 15s\n    timeout server 15s\n')
        config = config.replace('    tcp-request content reject\n',
            '    mode http\n    option http-keep-alive\n    timeout http-request 15s\n'
            '    http-request return status 200 content-type text/plain lf-string '
            f'"nathaya-reload:{marker} pid=%pid"\n')
    return config.replace(f'bind 127.0.0.1:{port}\n',
                          f'bind 127.0.0.1:{port} ssl crt {private_pem}\n')


def reload_report(requested):
    """Explicitly initialized before any preflight or optional helper."""
    return dict(requested=requested, status='not-run-startup-unverified' if requested else 'not-requested',
        signal_attempted=False, signal_sent=False,
        source_mechanism='ExecReload=/bin/kill -USR2 $MAINPID', delivery='linux-pidfd-SIGUSR2',
        unit_reload_wrapper_tested=False, source_caps=None, startup_caps=None, reload_caps=None,
        source_mask=None, startup_mask=None, reload_mask=None, capability_delta=None, cap_kill_present=None,
        reload_caps_observation='unavailable',
        before_master=None, old_cohort=[], new_cohort=[], effective_NNP=None,
        baseline_request=None, new_request=None, continuity_request=None, final_request=None,
        clients_closed=True, old_workers_exited=False, old_worker_exit_proof=None,
        budget_seconds=RELOAD_OVERALL_SECONDS, overall_budget_seconds=RELOAD_OVERALL_SECONDS,
        entry_at=None, overall_deadline=None, deadline=None, deadline_alias='overall_deadline',
        current_stage=None, expired_stage=None, deadline_scope=None, finished_at=None,
        elapsed=None, elapsed_after_release=None, verification_finished_at=None,
        stages={name: dict(budget_seconds=budget, start_at=None, deadline=None, end_at=None,
                           elapsed=None, status=None) for name, budget in RELOAD_STAGES},
        timeline=[], signal_attempted_at=None, signal_sent_at=None, new_worker_first_seen_at=None,
        new_worker_served_at=None, continuity_complete_at=None, clients_closed_at=None,
        old_workers_exited_at=None, final_request_at=None, old_worker_timeout_observations=None,
        unit_cleanup=dict(requested_at=None, first_stop_at=None, first_kill_at=None, finished_at=None,
                          confirmed=None, outcome=None, old_exit_verified_before_cleanup=None,
                          old_exit_proof_before_cleanup=None, old_exit_proof_status=None,
                          old_exit_verification_status=None),
        release_time=None, deadline_enforcement='not-armed', deadline_signal_unblocked=None,
        cleanup_evidence='nnp-ab.report.json:reload.unit_cleanup (canonical after unit cleanup)',
        coverage=[], pidfd_binding_verified=False, issues=[])


def _reload_response(sock, io, marker):
    """Read one bounded HTTP/1.1 response; never persist payload or headers."""
    data = b''
    while b'\r\n\r\n' not in data:
        block = io(sock, sock.recv, 8193 - len(data))
        if not block:
            raise Unsupported('reload-http-eof')
        data += block
        if len(data) > 8192 and b'\r\n\r\n' not in data:
            raise Unsupported('reload-http-headers-size')
    head, body = data.split(b'\r\n\r\n', 1)
    lines, headers = head.split(b'\r\n'), {}
    if len(head) + 4 > 8192 or not re.fullmatch(rb'HTTP/1\.1 200 [\x20-\x7e]*', lines[0]):
        raise Unsupported('reload-http-status-or-size')
    for line in lines[1:]:
        name, sep, value = line.partition(b':')
        name, value = name.lower(), value.strip()
        if (not sep or not re.fullmatch(rb'[a-z0-9-]+', name) or name in headers
                or any(c < 32 or c > 126 for c in value)):
            raise Unsupported('reload-http-headers')
        headers[name] = value
    length = headers.get(b'content-length', b'')
    if (not re.fullmatch(rb'[0-9]{1,3}', length) or not 1 <= int(length) <= 128
            or b'transfer-encoding' in headers or headers.get(b'content-type') != b'text/plain'
            or b'close' in [t.strip().lower() for t in headers.get(b'connection', b'').split(b',')]):
        raise Unsupported('reload-http-framing-or-close')
    size = int(length)
    while len(body) < size:
        block = io(sock, sock.recv, size - len(body))
        if not block:
            raise Unsupported('reload-http-body-eof')
        body += block
    match = re.fullmatch(b'nathaya-reload:' + marker.encode('ascii') + rb' pid=([1-9][0-9]{0,9})', body)
    if len(body) != size or not match or sock.pending():
        raise Unsupported('reload-http-body-or-extra')
    try:
        sock.recv(1)  # Nonblocking: reject buffered extras/EOF, never pretend an idle hold.
    except (ssl.SSLWantReadError, BlockingIOError):
        pass
    else:
        raise Unsupported('reload-http-extra-or-eof')
    return {'status': 200, 'pid': int(match[1]), 'body_bytes': size, 'marker_verified': True}


def nnp_ab_plan(directory, nonce, caps, phase, reload_usr2=False, compare_cap_kill=False):
    """Closed plans selected by trusted mode, never caller-supplied properties."""
    if (type(compare_cap_kill) is not bool or type(reload_usr2) is not bool
            or (compare_cap_kill and (not reload_usr2 or caps != CAPS3))
            or phase not in (CAP_KILL_PHASES if compare_cap_kill else NNP_PHASES)
            or not isinstance(nonce, str)
            or not re.fullmatch(r'[0-9a-f]{32}', nonce) or not re.fullmatch(
                r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+', str(directory))):
        raise Unsupported('ab-plan')
    directory = Path(directory)
    output, go = directory / phase / 'combined.log', directory / phase / 'go'
    argv = [HAPROXY, '-W', '-db', '-f', str(directory / 'nnp-ab/haproxy.cfg')]
    pre = ['/usr/bin/python3', '-I', '-B', str(directory / 'gate.py'), str(go)]
    unit = 'nathaya-haproxy-probe-' + nonce + '-' + phase + '.service'
    arm_caps = CAPS4 if compare_cap_kill and phase == CAP_KILL_PHASES[1] else caps
    properties = {**restriction_properties(arm_caps),
                  'NoNewPrivileges': 'yes' if phase == 'nnp-yes' else 'no',
                  'Description': 'Nathaya HAProxy probe ' + nonce + ' ' + phase,
                  'ExecStartPre': ' '.join(pre),
                  'StandardOutput': 'append:' + str(output), 'StandardError': 'append:' + str(output)}
    if reload_usr2:
        properties['RuntimeMaxSec'] = '30s'  # Identical opt-in runtime in BOTH arms.
    return dict(phase=phase, unit=unit, argv=argv, pre=pre, go=go, output=output,
                properties=properties, command=transient_command(unit, properties, argv))


def _allow_nnp_ab_delta(inventory):
    # Caller must independently prove both contexts. Never normalize a snapshot.
    for row in inventory['properties']:
        if (row['property'] == 'NoNewPrivileges' and row['source_present'] and row['probe_present']
                and row['source'] == 'yes' and row['probe'] == 'no'):
            row.update(unsupported=False, classification='validated-nnp-ab-delta',
                       reason='closed-startup-AB-only-NNP-yes-to-no')
    inventory['unsupported'] = [r['property'] for r in inventory['properties'] if r['unsupported']]
    inventory['mismatches'] = [r for r in inventory['properties'] if r['unsupported']]


def _allow_cap_kill_delta(inventory):
    # ONLY called after closed, registered source->B or A->B context proofs.
    for row in inventory['properties']:
        if (row['property'] == 'CapabilityBoundingSet' and row['source_present']
                and row['probe_present'] and _capset(row['source']) == CAPS3
                and _capset(row['probe']) == CAPS4):
            row.update(unsupported=False, classification='validated-cap-kill-ab-delta',
                       reason='closed-directed-CAPS3-to-CAPS4-only')
    inventory['unsupported'] = [r['property'] for r in inventory['properties'] if r['unsupported']]
    inventory['mismatches'] = [r for r in inventory['properties'] if r['unsupported']]


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
    counts, calls, identity, records = collections.Counter(), collections.Counter(), 0, 0
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
        calls[name] += 1
        identity += int(name in IDENTITY_CALLS)
    return {'available': bool(identity) and not denied,
            'identity_calls': identity, 'records': records, 'capset_records': calls['capset'],
            'counts': [{'syscall': name, 'errno': error, 'count': n}
                       for (name, error), n in sorted(counts.items())]}


def owned_unit(properties, unit, nonce):
    """Ownership is a conjunction, never merely a matching unit name or PID."""
    if (not isinstance(properties, dict) or not isinstance(unit, str) or
            not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{32}', nonce)):
        return False
    match = re.fullmatch(r'nathaya-haproxy-probe-' + nonce + r'-(plain|trace|cap-gated|cap-direct|nnp-yes|nnp-no|cap-kill-a|cap-kill-b|mx(?:0[0-9]|1[0-9]|2[0-7]))\.service', unit)
    if not match:
        return False
    expected = {
        'Id': unit, 'Transient': 'yes',
        'Description': 'Nathaya HAProxy probe ' + nonce + ' ' + match[1],
        'FragmentPath': '/run/systemd/transient/' + unit,
    }
    return (all(properties.get(k) == v for k, v in expected.items()) and
            properties.get('ControlGroup') in ('', '/system.slice/' + unit))


ENV_NAMES = ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONHOME', 'PYTHONPATH',
             'BASH_ENV', 'ENV', 'GLIBC_TUNABLES')
BOUNDARY_TAG = 'nathaya-cap-boundary-v1'
# First helper observation is AFTER Python initialization, not before Python exec.
# Output uses the inherited append FD, never a reopened path or new writable path.
BOUNDARY_PROGRAM = '''import json, os, stat, sys, time
from pathlib import Path
def emit(stage, token):
    with open('/proc/self/status') as f:
        raw = f.read(65537)
    if len(raw) > 65536:
        raise SystemExit(1)
    names = {'Pid','PPid','Uid','Gid','Groups','CapInh','CapPrm','CapEff',
             'CapBnd','CapAmb','NoNewPrivs','TracerPid','Seccomp'}
    status = '\\n'.join(s for s in raw.splitlines() if s.partition(':')[0] in names)
    env = ('LD_PRELOAD','LD_LIBRARY_PATH','PYTHONHOME','PYTHONPATH',
           'BASH_ENV','ENV','GLIBC_TUNABLES')
    record = dict(tag='nathaya-cap-boundary-v1', stage=stage, token=token,
                  status=status, exe=os.readlink('/proc/self/exe'),
                  env_present={n: n in os.environ for n in env})
    data = (json.dumps(record, sort_keys=True) + '\\n').encode()
    if len(data) > 8192 or os.write(1, data) != len(data):
        raise SystemExit(1)
def wait(p):
    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        try:
            s = p.lstat()
            if (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_gid == 0
                    and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1):
                return
            raise SystemExit(1)
        except FileNotFoundError:
            time.sleep(0.025)
    raise SystemExit(1)
'''
GATE_PROGRAM = BOUNDARY_PROGRAM + '''if len(sys.argv) != 2:
    raise SystemExit(1)
p = Path(sys.argv[1])
emit('gate-entry', str(p.parent))
wait(p)
emit('gate-exit', str(p.parent))
'''
CONTROL_PROGRAM = BOUNDARY_PROGRAM + '''if (len(sys.argv) not in (2, 3) or
        (len(sys.argv) == 3 and sys.argv[2] != 'after-exec')):
    raise SystemExit(1)
p = Path(sys.argv[1])
if len(sys.argv) == 3:
    emit('after-exec', str(p.parent))
else:
    emit('control-entry', str(p.parent))
    wait(p)
    os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', '-B',
             __file__, sys.argv[1], 'after-exec'])
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
    wanted = {'Pid', 'PPid', 'Uid', 'Gid', 'Groups', 'CapInh', 'CapEff', 'CapPrm', 'CapBnd', 'CapAmb', 'NoNewPrivs'}
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
                         r'-(plain|trace|cap-gated|cap-direct|nnp-yes|nnp-no|cap-kill-a|cap-kill-b|mx(?:0[0-9]|1[0-9]|2[0-7]))\.service', unit) is not None)


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


def restriction_properties(caps):
    if frozenset(caps) not in (CAPS3, CAPS4):
        raise ValueError('probe-caps')
    return {
        'Type': 'simple', 'User': 'root', 'Group': 'root', 'UMask': '0077',
        'Slice': 'system.slice', 'NoNewPrivileges': 'yes', 'PrivateTmp': 'yes',
        'ProtectSystem': 'strict', 'ProtectHome': 'yes',
        'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes',
        'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes', 'LockPersonality': 'yes',
        'RestrictAddressFamilies': 'AF_INET AF_INET6 AF_UNIX',
        'CapabilityBoundingSet': ' '.join(sorted(caps)), 'AmbientCapabilities': '',
        'ReadWritePaths': LOGS, 'Restart': 'no', 'RestartSec': '3s',
        'RuntimeMaxSec': '8s', 'TimeoutStartSec': '5s', 'TimeoutStopSec': '2s',
        'TimeoutAbortSec': '2s', 'WatchdogSec': '0',
        'KillMode': 'control-group', 'SendSIGKILL': 'yes',
    }


def transient_command(unit, properties, argv):
    command = ['/usr/bin/systemd-run', '--no-block', '--unit=' + unit,
               '--description=' + properties['Description'], '--service-type=simple']
    for key, value in properties.items():
        if key not in ('Description', 'Type'):
            command += ['--property=' + key + '=' + value]
    command += ['--'] + argv
    return command


def control_plan(directory, nonce, caps, phase):
    if (phase not in ('cap-gated', 'cap-direct') or not re.fullmatch(r'[0-9a-f]{32}', nonce)
            or not re.fullmatch(r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+', str(directory))):
        raise Unsupported('control-plan')
    directory = Path(directory)
    base = directory / phase
    output, control_go = base / 'combined.log', base / 'control-go'
    go = base / 'go' if phase == 'cap-gated' else control_go
    argv = ['/usr/bin/python3', '-I', '-B', str(directory / 'control.py'), str(control_go)]
    pre = ['/usr/bin/python3', '-I', '-B', str(directory / 'gate.py'), str(go)] if phase == 'cap-gated' else []
    unit = 'nathaya-haproxy-probe-' + nonce + '-' + phase + '.service'
    properties = {**restriction_properties(caps),
                  'Description': 'Nathaya HAProxy probe ' + nonce + ' ' + phase,
                  'StandardOutput': 'append:' + str(output), 'StandardError': 'append:' + str(output)}
    if pre:
        properties['ExecStartPre'] = ' '.join(pre)
    return dict(phase=phase, unit=unit, argv=argv, pre=pre, go=go, control_go=control_go,
                output=output, properties=properties, command=transient_command(unit, properties, argv))


# Fixed, directed request space: OFF is explicit, never inferred from absence.
MATRIX_KNOBS = ('NoNewPrivileges', 'PrivateTmp', 'ProtectSystem', 'ProtectHome',
                'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectControlGroups',
                'RestrictSUIDSGID', 'LockPersonality', 'RestrictAddressFamilies', 'ReadWritePaths')


def matrix_plan(directory, nonce, caps, index, enabled_knob_names):
    if (type(index) is not int or not 0 <= index < 28 or not isinstance(nonce, str)
            or not re.fullmatch(r'[0-9a-f]{32}', nonce)
            or not re.fullmatch(r'/run/nathaya-haproxy-probe\.[A-Za-z0-9_-]+', str(directory))
            or not isinstance(enabled_knob_names, (list, tuple, set, frozenset))
            or any(k not in MATRIX_KNOBS for k in enabled_knob_names)
            or len(set(enabled_knob_names)) != len(enabled_knob_names)):
        raise Unsupported('matrix-plan')
    phase = 'mx%02d' % index
    directory, enabled = Path(directory), frozenset(enabled_knob_names)
    output, go = directory / phase / 'combined.log', directory / phase / 'control-go'
    properties = restriction_properties(caps)
    for key in MATRIX_KNOBS:
        if key not in enabled:
            properties[key] = '' if key in ('RestrictAddressFamilies', 'ReadWritePaths') else 'no'
    # As in the existing factory, do not send unsupported transient zero syntax.
    # SecureBits=0 is a required audited default, not an invented request value.
    properties.update(Description='Nathaya HAProxy probe ' + nonce + ' ' + phase,
                      StandardOutput='append:' + str(output), StandardError='append:' + str(output))
    argv = ['/usr/bin/python3', '-I', '-B', str(directory / 'control.py'), str(go)]
    return dict(phase=phase, index=index, enabled=sorted(enabled), unit='nathaya-haproxy-probe-' + nonce + '-' + phase + '.service',
                properties=properties, required_effective_defaults={'SecureBits': '0', 'SystemCallFilter': '~'},
                argv=argv, pre=[], go=go, control_go=go, output=output,
                command=transient_command('nathaya-haproxy-probe-' + nonce + '-' + phase + '.service', properties, argv))


def _matrix_value(key, value):
    # Normalize only known boolean/AF/path spellings; unknown strings stay raw.
    if key in MATRIX_KNOBS and key not in ('RestrictAddressFamilies', 'ReadWritePaths'):
        return {'true': 'yes', 'false': 'no'}.get(value, value)
    if key == 'RestrictAddressFamilies' and isinstance(value, str):
        words = value.split()
        if len(words) == len(set(words)) and set(words) <= {'AF_INET', 'AF_INET6', 'AF_UNIX'}:
            return tuple(sorted(words))
    if key == 'ReadWritePaths' and value in ('', LOGS):
        return tuple(value.split())
    return value


def _matrix_allowed(key, value):
    on = restriction_properties(CAPS3)[key]
    off = '' if key in ('RestrictAddressFamilies', 'ReadWritePaths') else 'no'
    return _matrix_value(key, value) in (_matrix_value(key, off), _matrix_value(key, on))


def matrix_entry_state(records, caps, executable, *, entry_only=False):
    stages = ['control-entry'] if entry_only else ['control-entry', 'after-exec']
    if [r['stage'] for r in records] != stages:
        raise Unsupported('matrix-record-sequence')
    mask = sum(1 << CAP_BITS[c] for c in caps)
    states = []
    for record in records:
        s, optional = record['status'], record['optional_status']
        if not {'TracerPid', 'Seccomp'} <= set(optional):
            raise Unsupported('matrix-status-coverage')
        if (record['exe'] != executable or s['Pid'] <= 0 or s['Uid'] != (0,) * 4 or s['Gid'] != (0,) * 4
                or s['CapBnd'] != mask or s['CapAmb'] or s['CapInh']
                or optional['TracerPid'] != 0 or optional['Seccomp'] not in (0, 1, 2)
                or s['NoNewPrivs'] not in (0, 1) or s['CapEff'] != s['CapPrm']
                or s['CapEff'] not in (mask, mask & ~0x80)):
            raise Unsupported('matrix-anomalous-credentials')
        if any(record['env_present'].values()):
            raise Unsupported('matrix-environment-confounded')
        states.append({k: v for k, v in s.items() if k not in ('Pid', 'PPid')})
    if not entry_only:
        invariant = lambda s: {k: v for k, v in s.items() if k not in ('CapEff', 'CapPrm')}
        if (records[0]['status']['Pid'] != records[1]['status']['Pid']
                or records[0]['status']['PPid'] != records[1]['status']['PPid']
                or invariant(states[0]) != invariant(states[1])
                or records[0]['optional_status'] != records[1]['optional_status']):
            raise Unsupported('matrix-selfexec-unstable')
    return {'entry': states[0], 'after_exec': None if entry_only else states[1],
            'optional': records[0]['optional_status'],
            'selfexec_capability_changed': None if entry_only else states[0] != states[1],
            'missing': not bool(states[0]['CapEff'] & 0x80)}


def fixed_snapshot(pid, environment=False):
    """Only self or fixed PID 1; anchored identity, no global process inventory."""
    if pid not in (1, os.getpid()):
        raise ValueError('fixed-pid')
    fd = None
    try:
        fd = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        def read(name, limit):
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(f, 'rb') as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError('proc-size')
            return raw
        before = _proc_identity(read('stat', 4096))
        def executable():
            try:
                return {'exe': os.readlink('exe', dir_fd=fd)}
            except OSError as exc:
                return {'exe': None, 'exe_unavailable_errno': exc.errno}
        exe = executable()
        raw = read('status', 65536).decode('utf-8', 'strict')
        status = _status(raw)
        if (before[0] != pid or status['Pid'] != pid or
                before != _proc_identity(read('stat', 4096)) or exe != executable()):
            raise ValueError('proc-identity')
        result = {'available': True, 'status': status, 'status_raw': raw, **exe}
    except (OSError, ValueError) as exc:
        result = {'available': False, 'unavailable': type(exc).__name__}
    finally:
        if fd is not None:
            os.close(fd)
    if environment:
        result['env_present'] = {name: name in os.environ for name in ENV_NAMES}
    return result


def executable_metadata(path):
    """Resolve only root-owned symlinks in trusted parents; read filecap, not payload."""
    try:
        pending, resolved, links = list(Path(path).parts[1:]), Path('/'), 0
        if not Path(path).is_absolute():
            raise Unsupported('executable-path')
        while pending:
            part = pending.pop(0)
            if part in ('.', '..'):
                resolved = resolved.parent if part == '..' else resolved
                continue
            _secure_path(resolved, directory=True)
            candidate = resolved / part
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if info.st_uid or info.st_gid or links > 32:
                    raise Unsupported('executable-link')
                target = Path(os.readlink(candidate))
                if target.is_absolute():
                    resolved = Path('/')
                pending = list(target.parts[1:] if target.is_absolute() else target.parts) + pending
            else:
                resolved = candidate
        expected = _secure_path(resolved)
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) != (expected.st_dev, expected.st_ino, expected.st_uid, expected.st_gid, expected.st_mode):
                raise Unsupported('executable-changed')
            try:
                cap = os.getxattr(fd, 'security.capability')
                filecap = {'available': len(cap) <= 64, 'present': True,
                           'hex': cap.hex() if len(cap) <= 64 else None}
            except OSError as exc:
                filecap = {'available': exc.errno == errno.ENODATA,
                           'present': False if exc.errno == errno.ENODATA else None, 'errno': exc.errno}
            return {'available': True, 'resolved': str(resolved), 'uid': info.st_uid,
                    'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
                    'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
                    'mtime_ns': info.st_mtime_ns, 'filecap': filecap}
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        return {'available': False, 'unavailable': type(exc).__name__}


def boundary_records(raw, token, control=False):
    """Fixed schema/tokens only: unrelated combined output is not a snapshot."""
    records = []
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError('duplicate-json-key')
        return result
    stages = ('gate-entry', 'gate-exit', 'control-entry', 'after-exec') if control else ('gate-entry', 'gate-exit')
    for line in raw.splitlines():
        if len(line) > 8192:
            continue
        try:
            r = json.loads(line, object_pairs_hook=unique)
            if (not isinstance(r, dict) or set(r) != {'tag', 'stage', 'token', 'status', 'exe', 'env_present'}
                    or r['tag'] != BOUNDARY_TAG or r['token'] != token or r['stage'] not in stages
                    or not isinstance(r['exe'], str) or not re.fullmatch(r'/usr/bin/python3(?:\.[0-9]+)?', r['exe'])
                    or not isinstance(r['status'], str) or not isinstance(r['env_present'], dict)
                    or set(r['env_present']) != set(ENV_NAMES)
                    or any(type(v) is not bool for v in r['env_present'].values())):
                continue
            optional = {}
            for entry in r['status'].splitlines():
                name, _, value = entry.partition(':')
                if name in ('TracerPid', 'Seccomp') and re.fullmatch(r'[0-9]{1,10}', value.strip()):
                    optional[name] = int(value)
            r['status'] = _status(r['status'])
            r['optional_status'] = optional
            records.append(r)
        except (ValueError, TypeError, KeyError):
            continue
    return records


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
        self.boundaries = []
        self.control_profiles = {}
        self.control_records = {}
        self.boundary_plans = []
        self.process_boundaries = []
        self.matrix_plans = {}
        self.matrix_mount_manager_sample = None
        self.ab_report = {'status': 'NOTSTARTED', 'complete': False, 'production_applied': False,
                          'reload_usr2_tested': False, 'reload_required': True,
                          'proc_identity': 'unavailable', 'arms': {}}
        self.compare_cap_kill = False
        self.reload_report = reload_report(False)
        self.reload_capture_complete = False
        self.ab_assets = None
        self.ab_plans, self.ab_profiles = {}, {}

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
        if unit != MAIN and not re.fullmatch(r'nathaya-haproxy-probe-' + self.nonce + r'-(?:plain|trace|cap-gated|cap-direct|nnp-yes|nnp-no|cap-kill-a|cap-kill-b|mx(?:0[0-9]|1[0-9]|2[0-7]))\.service', unit):
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

    def prepare(self, cap_boundaries=False, ab=False):
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
        # Capture before workdir, source inspection or any transient unit exists.
        initial = {'controller': fixed_snapshot(os.getpid(), True), 'manager': fixed_snapshot(1)}
        _no_lock()
        _secure_path('/run', directory=True)
        os.umask(0o077)
        self.directory = Path(tempfile.mkdtemp(prefix='nathaya-haproxy-probe.', dir='/run'))
        _secure_path(self.directory, directory=True)
        if stat.S_IMODE(self.directory.stat().st_mode) != 0o700:
            raise Unsupported('evidence-mode')
        self.record('boundaries.initial.json', initial)
        for label, snapshot in initial.items():
            self.boundaries.append({'stage': label, **snapshot})
        self.save('gate.py', GATE_PROGRAM)
        if cap_boundaries:
            self.save('control.py', CONTROL_PROGRAM)
        executables = ['/usr/bin/python3', '/usr/bin/env', '/usr/bin/systemd-run',
                       HAPROXY, '/usr/lib/systemd/systemd-executor']
        if not ab:
            executables.append('/usr/bin/strace')
        if initial['manager'].get('exe'):
            executables.append(initial['manager']['exe'])
        self.record('boundaries.executables.json', {p: executable_metadata(p) for p in dict.fromkeys(executables)})
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
        if cap_boundaries:
            return  # No HAProxy/strace inventory execution or account changes.
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
        if not ab:
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

    def ab_private_file(self, name, raw):
        # Register the exclusively created FD BEFORE private bytes are written,
        # including write/flush/close failures. Never authorize cleanup by name.
        if name not in ('nnp-ab/private.key', 'nnp-ab/private.crt', 'nnp-ab/private.pem'):
            raise Unsupported('ab-private-file-name')
        path = self.directory / name
        if stat.S_IMODE(_secure_path(path.parent, directory=True).st_mode) != 0o700:
            raise Unsupported('ab-directory-mode')
        self.ab_assets['owned'][name] = None
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        fd = None
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_gid or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise Unsupported('ab-private-file-mode')
            self.ab_assets['owned'][name] = (info.st_dev, info.st_ino)
            stream = os.fdopen(fd, 'wb')
            fd = None  # The stream owns the descriptor from here.
            with stream:
                if stream.write(raw) != len(raw):
                    raise Unsupported('ab-private-short-write')
        finally:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)

    def prepare_ab_assets(self):
        self.ab_assets = {'owned': {}, 'metadata': {}, 'executables': {}}
        (self.directory / 'nnp-ab').mkdir(mode=0o700)
        for path in (HAPROXY, '/usr/bin/python3', '/usr/bin/openssl'):
            metadata = executable_metadata(path)
            cap = metadata.get('filecap', {})
            if (not metadata.get('available') or not cap.get('available') or
                    cap.get('present') is not False or int(metadata['mode'], 8) & 0o6000):
                raise Unsupported('ab-executable-untrusted-or-filecaps')
            self.ab_assets['executables'][path] = metadata
        _secure_path('/usr/bin/openssl')
        key, cert, pem = ('nnp-ab/' + n for n in ('private.key', 'private.crt', 'private.pem'))
        for name in (key, cert, pem):
            self.ab_private_file(name, b'')
        # OpenSSL 3 req supports -noenc (not a network/trust-store operation):
        # https://docs.openssl.org/3.0/man1/openssl-req/
        argv = ['/usr/bin/openssl', 'req', '-new', '-x509', '-newkey', 'ec',
                '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1',
                '-subj', '/CN=localhost', '-keyout', str(self.directory / key),
                '-out', str(self.directory / cert)]
        self.record('nnp-ab/tls-intent.json', {'argv': argv, 'owned': self.ab_assets['owned']})
        start = time.monotonic()
        generation = dict(argv=argv, returncode=None, errno=None, state='interrupted', exception_class=None)
        try:
            result = subprocess.run(argv, env=FIXED_ENV, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=3, check=False)
            generation.update(returncode=result.returncode, state='returned')
        except (OSError, subprocess.TimeoutExpired) as exc:
            generation.update(state='unavailable', errno=getattr(exc, 'errno', None),
                              exception_class=type(exc).__name__)
        finally:
            generation['elapsed'] = time.monotonic() - start
            self.record('nnp-ab/tls-generation.json', generation)
        if generation['returncode'] != 0:
            raise Unsupported('ab-tls-generation-unavailable')
        private_key, _ = _read_private_source(self.directory / key, 65536)
        certificate, _ = _read_private_source(self.directory / cert, 65536)
        if not private_key or not certificate:
            raise Unsupported('ab-tls-empty')
        # Replace ONLY our still-empty, inode-checked placeholder via secure save.
        self.ab_unlink_secret(pem)
        self.ab_private_file(pem, private_key + b'\n' + certificate)
        del private_key, certificate
        endpoints = self.reserve()
        self.ab_assets['endpoints'] = endpoints
        config = (make_ab_config(*endpoints, self.directory / pem, reload_http=True, marker=self.nonce)
                  if self.reload_report['requested'] else make_ab_config(*endpoints, self.directory / pem))
        self.save('nnp-ab/haproxy.cfg', config)  # Once, before either arm; never rewrite a live config.
        for name in (key, cert, pem, 'nnp-ab/haproxy.cfg', 'gate.py'):
            _, metadata = _read_private_source(self.directory / name, 65536)
            self.ab_assets['metadata'][name] = metadata
        self.verify_ab_assets()
        self.record('nnp-ab/assets.json', self.ab_assets)  # Metadata/hashes, NEVER private bytes.

    def verify_ab_assets(self):
        assets = self.ab_assets
        if assets is None or len(assets['metadata']) != 5:
            raise Unsupported('ab-assets-unavailable')
        for directory in (self.directory, self.directory / 'nnp-ab'):
            if stat.S_IMODE(_secure_path(directory, directory=True).st_mode) != 0o700:
                raise Unsupported('ab-directory-mode')
        for name, expected in assets['metadata'].items():
            _, metadata = _read_private_source(self.directory / name, 65536)
            if metadata != expected or metadata['mode'] != '0o600':
                raise Unsupported('ab-private-asset-changed')
        for name, identity in assets['owned'].items():
            info = _secure_path(self.directory / name)
            if (info.st_dev, info.st_ino) != identity or stat.S_IMODE(info.st_mode) != 0o600:
                raise Unsupported('ab-private-identity-changed')
        for path, expected in assets['executables'].items():
            if executable_metadata(path) != expected:
                raise Unsupported('ab-executable-changed')

    def ab_unlink_secret(self, name):
        if name not in ('nnp-ab/private.key', 'nnp-ab/private.crt', 'nnp-ab/private.pem'):
            raise Unsupported('ab-private-file-name')
        identity = self.ab_assets['owned'][name]
        path = self.directory / name
        if not os.path.lexists(path):
            if identity is None:
                del self.ab_assets['owned'][name]
                return
            raise Unsupported('ab-private-file-missing')
        info = _secure_path(path)
        if (identity is None or (info.st_dev, info.st_ino) != identity or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise Unsupported('ab-private-cleanup-identity')
        path.unlink()  # Exact generated key/cert/PEM only; no logs/evidence deletion.
        del self.ab_assets['owned'][name]

    def cleanup_ab_keys(self, units_clean):
        if not units_clean:
            return False  # Retain keys and all evidence if ANY unit ownership is unresolved.
        if self.ab_assets is None:
            return True
        # Execution-integrity failures (e.g. changed config/executable) must
        # NOT strand still-owned keys. Authorize each unlink independently.
        complete = True
        for name in tuple(self.ab_assets['owned']):
            try:
                self.ab_unlink_secret(name)
            except (OSError, ValueError):
                complete = False
        return complete and not self.ab_assets['owned']

    def reserve(self, endpoints=None):
        if endpoints is not None:
            make_config(*endpoints)  # Exact high port/name; never port zero for B.
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reservations.append(tcp)
        tcp.bind(('127.0.0.1', 0 if endpoints is None else endpoints[0]))
        port = tcp.getsockname()[1]
        if port < 1024:
            raise Unsupported('high-port-reservation')
        if endpoints is not None and port != endpoints[0]:
            raise Unsupported('ab-endpoint-reservation-mismatch')
        abstract = ('nathaya-probe-' + secrets.token_hex(16)) if endpoints is None else endpoints[1]
        unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.reservations.append(unix)
        # HAProxy abns@ uses sizeof(sockaddr_un.sun_path), including zero padding.
        # Passing bytes (not a pathname) reserves that EXACT 108-byte address.
        unix.bind((b'\x00' + abstract.encode('ascii')).ljust(108, b'\x00'))
        return port, abstract

    def release_reservations(self):
        while self.reservations:
            self.reservations.pop().close()

    def ab_phases(self):
        return CAP_KILL_PHASES if self.compare_cap_kill else NNP_PHASES

    def ab_caps(self, phase):
        if phase not in self.ab_phases():
            raise Unsupported('ab-phase')
        if self.compare_cap_kill and self.caps != CAPS3:
            raise Unsupported('cap-kill-already-in-source')
        return CAPS4 if self.compare_cap_kill and phase == CAP_KILL_PHASES[1] else self.caps

    def reload_phase(self, phase):
        return self.reload_report['requested'] and (
            phase in CAP_KILL_PHASES if self.compare_cap_kill else phase == 'nnp-no')

    def factory(self, phase):
        if phase in self.ab_phases():
            self.verify_ab_assets()
            (self.directory / phase).mkdir(mode=0o700)
            self.save(phase + '/combined.log', b'')
            plan = nnp_ab_plan(self.directory, self.nonce, self.caps, phase,
                               reload_usr2=self.reload_report['requested'],
                               compare_cap_kill=self.compare_cap_kill)
            self.ab_plans[phase] = plan
            return plan
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
        properties = {**restriction_properties(self.caps),
                      'Description': 'Nathaya HAProxy probe ' + self.nonce + ' ' + phase,
                      'ExecStartPre': ' '.join(pre),
                      'StandardOutput': 'append:' + str(output), 'StandardError': 'append:' + str(output)}
        # SecureBits=0 and an empty SystemCallFilter are defaults. In particular
        # systemd-run's transient API does NOT accept all unit-file zero syntax.
        # Omit them, then require their effective values before releasing gate.
        command = transient_command(unit, properties, argv)
        return {'phase': phase, 'unit': unit, 'command': command, 'argv': argv,
                'pre': pre, 'go': go, 'output': output, 'properties': properties}

    def validate_probe_logging(self, probe, plan):
        # Never borrow the production destination, even if File metadata exists.
        phase = plan.get('phase')
        directory = str(self.directory)
        if ((phase not in ('plain', 'trace', 'cap-gated', 'cap-direct', 'nnp-yes', 'nnp-no', 'cap-kill-a', 'cap-kill-b') and
             not (isinstance(phase, str) and re.fullmatch(r'mx(?:0[0-9]|1[0-9]|2[0-7])', phase))) or not isinstance(self.directory, Path) or not re.fullmatch(
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
        return self._empty_exec_fields(probe, plan, PROBE_EMPTY_EXEC_HOOKS)

    def control_empty_exec_fields(self, probe, plan):
        if plan.get('phase') not in ('cap-gated', 'cap-direct'):
            raise Unsupported('control-phase')
        hooks = PROBE_EMPTY_EXEC_HOOKS + (('ExecStartPre',) if plan['phase'] == 'cap-direct' else ())
        return self._empty_exec_fields(probe, plan, hooks)

    def _empty_exec_fields(self, probe, plan, hooks):
        errors = []
        if not owned_unit(probe, plan.get('unit'), self.nonce):
            errors.append('probe-ownership')
        collect_unsupported(errors, _require, probe,
                            {'LoadState': 'loaded', 'DropInPaths': '', 'NeedDaemonReload': 'no'})
        fields = frozenset(name + suffix for name in hooks for suffix in ('', 'Ex'))
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

    def _validate_probe_policy(self, probe, plan, expected_nnp='yes', expected_runtime='8s'):
        if expected_runtime not in ('8s', '30s'):
            raise Unsupported('ab-runtime-scope')
        if expected_runtime == '30s':
            expected = self._validated_nnp_ab_plan(plan)
            if (self.reload_report['requested'] is not True
                    or expected['properties']['RuntimeMaxSec'] != '30s'
                    or expected_nnp != expected['properties']['NoNewPrivileges']):
                raise Unsupported('ab-runtime-scope')
        if expected_nnp != 'yes' and not (expected_nnp == 'no' and (
                plan.get('phase') == 'nnp-no' or
                self.compare_cap_kill and plan.get('phase') in CAP_KILL_PHASES)):
            raise Unsupported('ab-policy-scope')
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
            'Restart': 'no', 'RuntimeMaxUSec': expected_runtime, 'TimeoutStartUSec': '5s',
            'TimeoutStopUSec': '2s', 'TimeoutAbortUSec': '2s', 'CanReload': 'no',
            'KillMode': 'control-group', 'SendSIGKILL': 'yes',
            'StandardOutput': 'append', 'StandardError': 'append',
            'SecureBits': '0', 'NoNewPrivileges': expected_nnp, 'AmbientCapabilities': '',
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
        _raise_unsupported(errors)

    def validate_probe(self, probe, plan):
        """Collect independent effective/plan/log/hook/argv failures; return None."""
        if not isinstance(probe, dict) or not isinstance(plan, dict):
            raise Unsupported('probe-snapshot-or-plan-format')
        errors = []
        collect_unsupported(errors, self._validate_probe_policy, probe, plan)
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

    def validate_control(self, probe, plan):
        """Fixed Python-only command proof, independent of the HAProxy validator."""
        if not isinstance(probe, dict) or not isinstance(plan, dict):
            raise Unsupported('control-snapshot-or-plan-format')
        expected = control_plan(self.directory, self.nonce, self.caps, plan.get('phase'))
        errors = ['control-plan:' + key for key, value in expected.items() if plan.get(key) != value]
        caps = collect_unsupported(errors, _capset, probe.get('CapabilityBoundingSet'))
        if caps != self.caps:
            errors.append('CapabilityBoundingSet')
        collect_unsupported(errors, self._validate_probe_policy, probe, plan)
        collect_unsupported(errors, self.validate_probe_logging, probe, plan)
        collect_unsupported(errors, self._validate_probe_watchdog, probe, plan)
        for key, argv in [('ExecStart', expected['argv'])] + ([('ExecStartPre', expected['pre'])] if expected['pre'] else []):
            if not _exec_struct(probe.get(key), argv):
                errors.append(key)
            if key + 'Ex' in probe and not _exec_struct(probe[key + 'Ex'], argv):
                errors.append(key + 'Ex')
        collect_unsupported(errors, self.control_empty_exec_fields, probe, plan)
        _raise_unsupported(errors)

    def _validated_nnp_ab_plan(self, plan):
        # Controller request, never an untrusted plan flag/runtime, selects the plan.
        if not isinstance(plan, dict):
            raise Unsupported('ab-plan')
        expected = nnp_ab_plan(self.directory, self.nonce, self.caps, plan.get('phase'),
                               reload_usr2=self.reload_report['requested'],
                               compare_cap_kill=self.compare_cap_kill)
        if (set(plan) - {'created_at', 'release_time'} != set(expected) or
                any(plan.get(k) != v for k, v in expected.items()) or
                ('created_at' in plan and (type(plan['created_at']) not in (int, float)
                                          or not 0 < plan['created_at'] < float('inf'))) or
                ('release_time' in plan and (type(plan['release_time']) is not float
                    or not 0 < plan['release_time'] < float('inf')
                    or 'created_at' not in plan or plan['release_time'] < plan['created_at']))):
            raise Unsupported('ab-plan')
        return expected

    def validate_nnp_ab(self, probe, plan):
        """Only this exact closed plan may request an effective NNP=no."""
        if not isinstance(probe, dict) or not isinstance(plan, dict):
            raise Unsupported('ab-snapshot-or-plan-format')
        expected = self._validated_nnp_ab_plan(plan)
        errors = []
        collect_unsupported(errors, self._validate_probe_policy, probe, plan,
                            expected_nnp=expected['properties']['NoNewPrivileges'],
                            expected_runtime=expected['properties']['RuntimeMaxSec'])
        if _capset(probe.get('CapabilityBoundingSet')) != self.ab_caps(plan['phase']):
            errors.append('ab-bounding')
        _require(probe, {'RestartUSec': '3s'})
        collect_unsupported(errors, self.validate_probe_logging, probe, plan)
        collect_unsupported(errors, self._validate_probe_watchdog, probe, plan)
        for key in ('ExecStart', 'ExecStartPre'):
            argv = expected['argv' if key == 'ExecStart' else 'pre']
            for field in (key, key + 'Ex'):
                if (field == key or field in probe) and not _exec_struct(probe.get(field), argv):
                    errors.append(field)
        collect_unsupported(errors, self.empty_probe_exec_fields, probe, plan)
        _raise_unsupported(errors)

    def compare_nnp_ab(self, a, b, a_plan, b_plan):
        """Pure independent A/B proofs plus strict raw inventory; no mount waiver."""
        a_phase, b_phase = self.ab_phases()
        if a_plan.get('phase') != a_phase or b_plan.get('phase') != b_phase:
            raise Unsupported('ab-comparison-roles')
        self.validate_nnp_ab(a, a_plan)
        self.validate_nnp_ab(b, b_plan)
        result = _comparison_inventory(a, b,
            empty_source=self.empty_probe_exec_fields(a, a_plan),
            empty_probe=self.empty_probe_exec_fields(b, b_plan))
        if self.compare_cap_kill:
            if any(self.ab_plans.get(p['phase']) != p for p in (a_plan, b_plan)):
                raise Unsupported('ab-plan-not-registered')
            _allow_cap_kill_delta(result)
        else:
            _allow_nnp_ab_delta(result)
        result['issues'] = list(result['unsupported'])
        result['ok'] = not result['issues']
        result['nuisance_differences'] = ['Description', 'ExecStartPre', 'private append log destination']
        return result

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
        control = isinstance(plan, dict) and plan.get('phase') in ('cap-gated', 'cap-direct')
        ab = isinstance(plan, dict) and plan.get('phase') in AB_PHASES
        validator = self.validate_nnp_ab if ab else self.validate_control if control else self.validate_probe
        empty_fields = self.control_empty_exec_fields if control else self.empty_probe_exec_fields
        validation = {'source': [], 'probe': [], 'original': []}
        source_caps = None
        source_empty, probe_empty, original_empty = (), (), ()
        if source is not None:
            if probe_source:
                collect_unsupported(validation['source'], validator, source, plan)
            else:
                source_caps = collect_unsupported(validation['source'], validate_effective, source, fragment)
            if not validation['source']:
                source_empty = (empty_fields(source, plan) if probe_source else
                                _source_empty_exec_fields(source, fragment))
        if probe is not None:
            collect_unsupported(validation['probe'], validator, probe, plan)
            if not validation['probe']:
                probe_empty = empty_fields(probe, plan)
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
        if (ab and plan['phase'] in ('nnp-no', 'cap-kill-a', 'cap-kill-b') and not probe_source and pair
                and not any(validation.values()) and not inspection_errors
                and not (profile is not None and profile['changed'])
                and not (original_bytes is not None and current_bytes is not None
                         and original_bytes != current_bytes)):
            _allow_nnp_ab_delta(result)
            if (self.compare_cap_kill and plan['phase'] == CAP_KILL_PHASES[1]
                    and self.ab_plans.get(plan['phase']) == plan and source_caps == CAPS3):
                _allow_cap_kill_delta(result)
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
        # Only the fixed harmless direct control may start before comparison.
        # ExecStartPre exits: PID 1 starts ExecStart independently, not its child.
        direct = plan['phase'] == 'cap-direct'
        if direct:
            expected = control_plan(self.directory, self.nonce, self.caps, 'cap-direct')
            _raise_unsupported(['control-plan'] if any(plan.get(k) != v for k, v in expected.items()) else [])
        unit = plan['unit']
        state, substate, pidfield = ('active', 'running', 'MainPID') if direct else ('activating', 'start-pre', 'ControlPID')
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
            if (probe.get('ActiveState') == state and probe.get('SubState') == substate
                    and probe.get(pidfield, '0') != '0'):
                if not direct or any(r['stage'] == 'control-entry' for r in self.read_boundaries(plan)):
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
                live.get('ActiveState') != state or live.get('SubState') != substate or
                live.get(pidfield) != probe.get(pidfield)):
            live_errors.append('prestart-unavailable')
        if time.monotonic() >= deadline:
            live_errors.append('prestart-deadline')
        collect_unsupported(live_errors, _no_lock)
        live_audit = self.audit_compatibility(probe, live, plan=plan, probe_source=True,
                                              inspection_errors=live_errors)
        self.record(plan['phase'] + '/live-comparison.json', live_audit)
        _raise_unsupported(live_audit['issues'])
        release_errors = []
        if plan['phase'] in self.ab_phases():
            self.verify_ab_assets()
            if plan['phase'] == self.ab_phases()[1]:
                a_phase = self.ab_phases()[0]
                cross = self.compare_nnp_ab(self.ab_profiles[a_phase], live,
                                           self.ab_plans[a_phase], plan)
                self.record('nnp-ab/comparison.json', cross)
                _raise_unsupported(cross['issues'])
        if time.monotonic() >= deadline:
            release_errors.append('prestart-deadline')
        collect_unsupported(release_errors, _no_lock)
        self.record(plan['phase'] + '/release-audit.json', {
            'issues': sorted(set(release_errors)), 'gate_released': False,
            'purpose': 'last refusal check before atomic go creation',
        })
        _raise_unsupported(release_errors)
        if plan['phase'] in self.ab_phases():
            self.verify_ab_assets()
            if time.monotonic() >= deadline:
                raise Unsupported('prestart-deadline')
        self.release_reservations()
        self.save(plan['phase'] + '/' + plan['go'].name, b'')
        if plan['phase'] in self.ab_phases() and self.reload_report['requested']:
            plan['release_time'] = time.monotonic()
            self.record(plan['phase'] + '/release-time.json', {'release_time': plan['release_time']})
        return live

    def capture(self, unit, sample, reload_evidence=False, deadline=None):
        """Stage bounded metadata on an anchored task FD, then validate and save.

        Never reopen a PID path after anchoring: a reused PID must not redirect
        any read to a different task. No maps, environment, arguments or memory.
        """
        self.reload_capture_complete = False
        if not _capture_unit(unit, self.nonce):
            raise Unsupported('probe-ownership')
        cg = '/system.slice/' + unit
        membership = ('0::' + cg + '\n').encode('ascii')
        captures, errors, exe_unavailable = [], [], False

        def budget():
            if reload_evidence and deadline is not None and time.monotonic() >= deadline:
                raise Unsupported('reload-capture-deadline-inconclusive')

        def bounded(name, limit, directory=None):
            budget()
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                         (os.O_NONBLOCK if reload_evidence else 0), dir_fd=directory)
            try:
                budget()
                data = bytearray()
                while len(data) <= limit:
                    budget()
                    block = os.read(fd, min(4096, limit + 1 - len(data)))
                    budget()
                    if not block:
                        return bytes(data)
                    data.extend(block)
                raise ValueError('proc-size')
            finally:
                os.close(fd)

        def executable(directory):
            budget()
            try:
                result = os.readlink('exe', dir_fd=directory), None
            except OSError as exc:
                result = None, exc.errno
            budget()
            return result

        try:
            raw = bounded('/sys/fs/cgroup' + cg + '/cgroup.procs', 4096)
            fields = raw.split()
            if len(fields) > 256 or any(not re.fullmatch(rb'[1-9][0-9]{0,9}', p) for p in fields):
                raise ValueError('cgroup-procs')
            pids = sorted(set(map(int, fields)))
        except (OSError, ValueError) as exc:
            self.record(sample + '.json', {'unavailable': type(exc).__name__,
                        **({'complete_coverage': False} if reload_evidence else {})})
            return []
        for pid in pids:
            budget()
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
                    budget()
                    self.save(prefix + '.' + name, data)
                    budget()
                if link is not None:
                    captures.append({'exe': link, 'status': parsed,
                                     **({'identity': identity} if reload_evidence else {})})
                role = ('haproxy-root' if parsed['Uid'][1] == 0 else 'haproxy-worker') if link == HAPROXY else 'strace' if link == '/usr/bin/strace' else 'other'
                stage = sample.split('/')[0] + ':' + role
                # Retain the first observation of every credential/capability
                # state, not just the first healthy state for this process role.
                fields = ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff',
                          'CapBnd', 'CapAmb', 'NoNewPrivs')
                if not any(r['stage'] == stage and all(r['status'][k] == parsed[k] for k in fields)
                           for r in self.process_boundaries):
                    self.process_boundaries.append({'stage': stage, 'status': parsed, 'sample': sample})
            except (OSError, ValueError) as exc:
                errors.append({'pid': pid, 'error': type(exc).__name__, 'errno': getattr(exc, 'errno', None)})
            finally:
                if directory is not None:
                    os.close(directory)
        if reload_evidence:
            try:
                if bounded('/sys/fs/cgroup' + cg + '/cgroup.procs', 4096).split() != raw.split():
                    errors.append({'error': 'cgroup-inventory-changed'})
            except (OSError, ValueError):
                errors.append({'error': 'cgroup-inventory-unavailable'})
            self.reload_capture_complete = (bool(pids) and not errors and not exe_unavailable
                                             and len(captures) == len(pids))
        self.record(sample + '.json', {'pids': pids, 'errors': errors,
                    **({'complete_coverage': self.reload_capture_complete,
                        'identities': [r['identity'] for r in captures]} if reload_evidence else {})})
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

    def ab_master_valid(self, master, phase, *, failed_arm=False):
        mask = sum(1 << CAP_BITS[c] for c in self.ab_caps(phase))
        allowed = (mask, mask & ~0x80) if failed_arm and phase == 'nnp-yes' else (mask,)
        return bool(master is not None and master['Uid'] == (0,) * 4 and master['Gid'] == (0,) * 4
                    and master['NoNewPrivs'] == int(phase == 'nnp-yes')
                    and master['CapInh'] == 0 and master['CapAmb'] == 0 and master['CapBnd'] == mask
                    and master['CapEff'] == master['CapPrm'] and master['CapEff'] in allowed)

    def ab_worker_valid(self, worker, nnp, phase=None):
        caps = self.ab_caps(phase) if phase is not None else self.caps
        mask = sum(1 << CAP_BITS[c] for c in caps)
        return (worker['Uid'] == (self.uid,) * 4 and worker['Gid'] == (self.gid,) * 4
                and all(g == self.gid for g in worker['Groups'])
                and not any(worker[k] for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'))
                and worker['CapBnd'] == mask and worker['NoNewPrivs'] in ((1,) if nnp else (0, 1)))

    def reload_cohort(self, captures, properties, phase='nnp-no'):
        """Separate checker: never appends reload transitions to startup proc_samples."""
        masters = [r for r in captures if str(r['status']['Pid']) == properties.get('MainPID')]
        if (not self.reload_capture_complete or len(masters) != 1
                or any(r['exe'] != HAPROXY for r in captures)):
            raise Unsupported('reload-incomplete-cohort')
        master = masters[0]
        workers = [r for r in captures if r is not master]
        if (not self.ab_master_valid(master['status'], phase) or not workers
                or any(r['status']['PPid'] != master['status']['Pid']
                       or not self.ab_worker_valid(r['status'], False, phase) for r in workers)):
            raise Unsupported('reload-cohort-credentials')
        return master, workers

    def ab_identity(self, captures, properties, phase):
        haproxy = [p['status'] for p in captures if p['exe'] == HAPROXY]
        masters = [s for s in haproxy if str(s['Pid']) == properties.get('MainPID')]
        master = masters[0] if len(masters) == 1 else None
        workers = [s for s in haproxy if master and s['Pid'] != master['Pid'] and s['PPid'] == master['Pid']]
        # Keep bad masks/NNP too; never infer proc state from the gate or request.
        self.ab_report['arms'][phase]['proc_samples'].append({
            'MainPID': properties.get('MainPID'), 'master': master, 'workers': workers,
            'availability': 'observed' if master else 'unavailable',
            'other_haproxy': [s for s in haproxy if s is not master and s not in workers]})
        observed = [s['master']['NoNewPrivs'] for s in self.ab_report['arms'][phase]['proc_samples']
                    if s['master'] is not None]
        self.ab_report['actual_master_NNP']['A' if phase == self.ab_phases()[0] else 'B'] = observed or 'unavailable'
        nnp = int(phase == 'nnp-yes')
        if (not self.ab_master_valid(master, phase) or not workers or len(workers) + 1 != len(haproxy)):
            return None
        for worker in workers:
            if not self.ab_worker_valid(worker, nnp, phase):
                return None
        # Credentials as well as PID identity must remain stable for two seconds.
        return tuple(tuple((k, s[k]) for k in sorted(s)) for s in
                     [master] + sorted(workers, key=lambda s: s['Pid']))

    def observe(self, plan):
        ab = plan['phase'] in self.ab_phases()
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
            identity = (self.ab_identity(captures, last, plan['phase']) if ab else
                        self.identity(captures, last, plan['phase'] == 'trace'))
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
            final_identity = (self.ab_identity(final_captures, after, plan['phase']) if ab else
                              self.identity(final_captures, after, plan['phase'] == 'trace'))
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

    def _reload_unit_cleanup(self, unit, kind, info, confirmed=None, interrupted=False):
        """Canonical registered-arm cleanup evidence, NEVER graceful exit proof."""
        phase = next((p for p in self.ab_phases()
                      if self.ab_plans.get(p, {}).get('unit') == unit), None)
        report = (self.ab_report['arms'].get(phase, {}).get('reload')
                  if self.compare_cap_kill else self.reload_report)
        if report is None:
            return
        if not self.compare_cap_kill and phase != 'nnp-no':
            return
        plan = self.ab_plans.get(phase)
        if (report['requested'] is not True or not isinstance(plan, dict)
                or unit not in self.intents or unit != plan.get('unit')):
            return
        try:
            expected = self._validated_nnp_ab_plan(plan)
        except Unsupported:
            return
        if unit != expected['unit']:
            return
        cleanup = report['unit_cleanup']
        owned = owned_unit(info, unit, self.nonce)
        if not owned and not (kind == 'finished' and
                (cleanup['requested_at'] is not None or
                 info.get('LoadState') == 'not-found' and
                 owned_unit(self.ab_profiles.get(phase, {}), unit, self.nonce))):
            return
        now = time.monotonic()
        if cleanup['requested_at'] is None:
            # Snapshot only pre-existing verification; no pidfds survive reload finally.
            close_at, exit_at = report['clients_closed_at'], report['old_workers_exited_at']
            proven = bool(report['old_workers_exited'] and report['old_worker_exit_proof']
                          and close_at is not None and exit_at is not None
                          and close_at < exit_at < now)
            cleanup.update(requested_at=now, old_exit_verified_before_cleanup=proven,
                old_exit_proof_before_cleanup=report['old_worker_exit_proof'],
                old_exit_proof_status='PROVEN-before-cleanup' if proven else 'NOT-PROVEN-before-cleanup',
                old_exit_verification_status=report['stages']['old_worker_exit']['status'])
        if kind in ('stop', 'sigkill'):
            field = 'first_stop_at' if kind == 'stop' else 'first_kill_at'
            if cleanup[field] is None:
                cleanup[field] = now  # Intent immediately BEFORE actual unit command.
                if len(report['timeline']) < 64:
                    report['timeline'].append(dict(label='unit-cleanup-' + kind, at=now,
                        elapsed=now - report['entry_at'] if report['entry_at'] is not None else None,
                        elapsed_after_release=now - report['release_time']
                            if type(report['release_time']) is float else None))
        elif kind == 'finished':
            if self.compare_cap_kill:
                report['snapshot_phase'] = 'post-unit-cleanup'
            cleanup.update(finished_at=now, confirmed=confirmed,
                outcome='interrupted-unconfirmed' if interrupted else
                        'unit-stop-confirmed' if confirmed and cleanup['old_exit_verified_before_cleanup'] else
                        'unit-stop-confirmed-not-graceful-exit-proof' if confirmed else 'unit-stop-unconfirmed')
            if len(report['timeline']) < 64:
                report['timeline'].append(dict(label='unit-cleanup-finished', at=now,
                    elapsed=now - report['entry_at'] if report['entry_at'] is not None else None,
                    elapsed_after_release=now - report['release_time']
                        if type(report['release_time']) is float else None))

    def cleanup_one(self, unit):
        """Bounded unit-only cleanup. Never signal a PID or a production unit."""
        confirmed, interrupted, info = False, False, {}
        try:
            info = self.show(unit, absent=True)
            if info.get('LoadState') == 'not-found':
                # Pending DBus creation is NOT confirmed absence.
                confirmed = unit in self.creation_confirmed
                return confirmed
            if not owned_unit(info, unit, self.nonce):
                return False
            self.creation_confirmed.add(unit)
            self._reload_unit_cleanup(unit, 'stop', info)
            self.command(['/usr/bin/systemctl', 'stop', '--no-block', unit])
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                info = self.show(unit, absent=True, timeout=max(0.01, deadline - time.monotonic()))
                if info.get('LoadState') == 'not-found':
                    confirmed = True
                    return confirmed
                if not owned_unit(info, unit, self.nonce):
                    return False
                if info.get('ActiveState') in ('inactive', 'failed') and info.get('ControlGroup') == '':
                    confirmed = True
                    return confirmed
                time.sleep(0.1)
            # Revalidate immediately before sending a unit-scoped SIGKILL.
            info = self.show(unit)
            if not owned_unit(info, unit, self.nonce):
                return False
            self._reload_unit_cleanup(unit, 'sigkill', info)
            self.command(['/usr/bin/systemctl', 'kill', '--kill-who=all', '--signal=SIGKILL', unit])
            info = self.show(unit, absent=True)
            confirmed = (info.get('LoadState') == 'not-found' or
                         (owned_unit(info, unit, self.nonce) and
                          info.get('ActiveState') in ('inactive', 'failed') and info.get('ControlGroup') == ''))
            return confirmed
        except KeyboardInterrupt:
            interrupted = True
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            return False
        finally:
            self._reload_unit_cleanup(unit, 'finished', info, confirmed, interrupted)

    def run_phase(self, phase):
        _no_lock()
        plan = self.factory(phase)
        self.boundary_plans.append(plan)
        if phase == 'trace':
            self.record('trace/selector.json', {'selector': 'trace=' + ','.join(SYSCALLS),
                        'raw_selector': 'raw=clone,clone3,prctl', 'capset_selector_count': SYSCALLS.count('capset'),
                        'notes': ['prctl 0x17 is PR_CAPBSET_READ (query, not mutation)',
                                  'absence of capset in an excerpt is not proof of absence globally']})
        if self.show(plan['unit'], absent=True).get('LoadState') != 'not-found':
            raise Unsupported('unit-name-conflict')
        # Persist and register intent BEFORE systemd-run; interrupted creation
        # must still undergo ownership checks in finally/cleanup.
        self.intents.append(plan['unit'])
        self.record(phase + '/intent.json', {'unit': plan['unit'], 'nonce': self.nonce,
                                           'command': plan['command']})
        if phase in self.ab_phases():
            self.verify_ab_assets()
        plan['created_at'] = time.monotonic()
        code, _, _ = self.command(plan['command'])
        if code != 0:
            raise Unsupported('transient-create-unavailable')
        self.creation_confirmed.add(plan['unit'])
        profile = self.gate(plan)
        if phase in self.ab_phases():
            self.ab_profiles[phase] = profile
            self.ab_report['arms'][phase]['effective_NNP'] = profile['NoNewPrivileges']
            self.ab_report['arms'][phase]['gate_boundaries'] = self.read_boundaries(plan)
            if self.reload_phase(phase):
                caps = _capset(profile['CapabilityBoundingSet'])
                self.reload_report.update(startup_caps=sorted(caps),
                                          startup_mask=sum(1 << CAP_BITS[c] for c in caps))
        result = self.observe(plan)
        if phase in self.ab_phases():
            self.ab_report['arms'][phase]['startup'] = result
        self.record(phase + '/startup.json', {'status': result})
        if self.reload_phase(phase):
            if result == 'observed-running':
                self.reload_usr2(plan)
            else:
                self.reload_report['status'] = 'not-run-startup-unverified'
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
                trace = {'available': False, 'counts': [], 'identity_calls': 0, 'records': 0, 'capset_records': None}
            else:
                trace = sanitise_trace(raw.decode('utf-8', 'replace'))
            self.record('trace/sanitised.json', trace)
            return result, trace
        return result, None

    def reload_usr2(self, plan):
        """One master USR2 per registered arm; clients/pidfds close before cleanup."""
        report, clients, pidfds = self.reload_report, [], []
        entry = time.monotonic()
        report.update(status='in-progress', release_time=plan.get('release_time'), entry_at=entry)
        overall = entry + RELOAD_OVERALL_SECONDS
        deadline, network_end = overall, float('inf')
        phase = plan['phase']
        base, count = phase + '/reload', 0
        if self.compare_cap_kill:
            report['cleanup_evidence'] = ('nnp-ab.report.json:arms.' + phase +
                '.reload.unit_cleanup (canonical after unit cleanup)')
        master_before, old = None, []
        previous_alarm_handler = None
        alarm_handler_installed, alarm_timer_owned, in_cleanup = False, False, False

        def event(label, at=None):
            at = time.monotonic() if at is None else at
            if len(report['timeline']) < 64:
                release = report['release_time']
                report['timeline'].append(dict(label=label, at=at, elapsed=at - entry,
                    elapsed_after_release=at - release if type(release) is float else None))
            return at

        def mark(field, label):
            if report[field] is None:
                report[field] = event(label)

        def poll_state(fd):
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            events = poller.poll(0)
            flags = 0
            for _, value in events:
                flags |= value
            return dict(poll_flags=flags, exited=bool(flags & select.POLLIN),
                        poll_error=bool(flags & (select.POLLERR | select.POLLNVAL)),
                        unexpected=bool(flags and not flags & select.POLLIN))

        def expire(now=None, alarm=False):
            now = time.monotonic() if now is None else now
            stage = report['current_stage']
            total = now >= overall or alarm and now < deadline
            report['deadline_scope'] = 'overall' if total else 'stage'
            report['expired_stage'] = (stage if stage and now >= deadline
                and report['stages'][stage]['status'] == 'in-progress' else None)
            if (stage == 'old_worker_exit' and report['old_worker_exit_proof'] is None
                    and report['old_worker_timeout_observations'] is None):
                # These are actual timeout-time polls, NOT timely exit proof.
                # Late POLLIN cannot establish whether exit preceded the deadline.
                rows = []
                report['old_worker_timeout_observations'] = rows
                for row, fd in zip(old, pidfds[1:]):
                    poll_started_at = time.monotonic()
                    try:
                        state = poll_state(fd)
                    except OSError:
                        state = dict(poll_flags=None, exited=None, poll_error=True, unexpected=None)
                    sampled_at = time.monotonic()
                    exited = None if state['poll_error'] or state['unexpected'] else state['exited']
                    alive = None if exited is None else not exited
                    closed_at = report['clients_closed_at']
                    rows.append(dict(identity=row['identity'], poll_started_at=poll_started_at,
                        sampled_at=sampled_at, clients_closed_at=closed_at,
                        drain_elapsed_since_clients_closed=sampled_at - closed_at
                            if closed_at is not None else None,
                        stage_deadline=deadline, overall_deadline=overall,
                        poll_flags=state['poll_flags'], poll_error=state['poll_error'],
                        unexpected=state['unexpected'], exited_when_sampled=exited,
                        alive_when_sampled=alive,
                        # A bound pidfd cannot resurrect: late alive proves earlier
                        # alive, but late exit (or any poll error) says nothing.
                        alive_at_deadline=True if alive is True
                            and poll_started_at >= min(overall, deadline) else None))
            label = 'total' if total else (stage or 'preparation').replace('_', '-')
            raise Unsupported('reload-' + label + '-deadline-inconclusive')

        def reload_alarm(_signum, _frame):
            # One overall timer only; queued ALRM must not interrupt teardown.
            if not in_cleanup:
                expire(alarm=True)

        def left():
            now = time.monotonic()
            remaining = min(overall, deadline) - now
            if remaining <= 0:
                expire(now)
            return remaining

        def start_stage(name, start=None):
            nonlocal deadline, network_end
            now = time.monotonic()
            if now >= overall and start is None:
                expire(now)
            # The previous stage already passed its completion check. Do not
            # retroactively turn a timely exit proof into a drain deadline.
            start = now if start is None else start
            stage = report['stages'][name]
            deadline = min(overall, start + stage['budget_seconds'])
            network_end = deadline
            report['current_stage'] = name
            stage.update(start_at=start, deadline=deadline, status='in-progress')
            event(name + '-started', start)
            left()

        def complete_stage(end=None):
            left()
            now = time.monotonic()
            if now >= min(overall, deadline):
                expire(now)
            end = now if end is None else end
            name = report['current_stage']
            stage = report['stages'][name]
            stage.update(end_at=end, elapsed=end - stage['start_at'], status='success')
            event(name + '-success', end)

        def pause():
            time.sleep(min(0.025, left()))
            left()

        def io(sock, operation, *args):
            end = min(deadline, network_end, time.monotonic() + 2.0)  # Never enlarge the 2s network timeout.
            while True:
                left()
                if time.monotonic() >= end:
                    raise Unsupported('reload-network-timeout-inconclusive')
                try:
                    result = operation(*args)
                    left()
                    if time.monotonic() >= end:
                        raise Unsupported('reload-network-timeout-inconclusive')
                    return result
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError) as exc:
                    writing = (isinstance(exc, ssl.SSLWantWriteError) or
                               isinstance(exc, BlockingIOError) and operation.__name__ == 'send')
                    select.select([] if writing else [sock], [sock] if writing else [], [],
                                  min(0.025, left(), max(0, end - time.monotonic())))

        def send(sock, data):
            while data:
                sent = io(sock, sock.send, data)
                if sent <= 0:
                    raise Unsupported('reload-client-send-unavailable')
                data = data[sent:]

        def closed(fd):
            left()
            state = poll_state(fd)
            left()
            if state['poll_error']:
                raise Unsupported('reload-pidfd-poll-unavailable')
            if state['unexpected']:
                raise Unsupported('reload-pidfd-unexpected-event')
            return state['exited']

        def snapshot(label, source=False):
            nonlocal count
            left()
            stem = base + '/%03d-' % count + label
            count += 1
            try:
                live = self.show(plan['unit'], timeout=min(0.25, left()))
            finally:
                left()
            self.validate_nnp_ab(live, plan)
            _require(live, {'ActiveState': 'active', 'SubState': 'running'})
            audit = self.audit_compatibility(self.ab_profiles[phase], live, plan=plan, probe_source=True)
            self.record(stem + '.unit.json', audit)
            _raise_unsupported(audit['issues'])
            self.reload_capture_complete = False
            try:
                captures = self.capture(plan['unit'], stem, reload_evidence=True,
                                        deadline=min(overall, deadline))
            finally:
                left()
            report['coverage'].append({'artifact': stem + '.json', 'complete': self.reload_capture_complete})
            master, workers = self.reload_cohort(captures, live, phase)
            if master_before is not None and (master['identity'] != master_before['identity']
                                              or closed(pidfds[0])):
                raise Unsupported('reload-master-identity-or-liveness')
            if source:
                left()
                raw, metadata = _read_private_source(FRAGMENT, 65536)
                left()
                fragment = validate_fragment(raw.decode('utf-8', 'strict'))
                try:
                    current = self.show(MAIN, timeout=min(0.25, left()))
                finally:
                    left()
                audit = self.audit_compatibility(current, live, fragment=fragment, plan=plan,
                    original=self.source, original_fragment=self.fragment,
                    original_bytes=self.source_bytes, current_bytes=raw)
                self.record(stem + '.source.json', {'audit': audit, 'fragment_metadata': metadata})
                _raise_unsupported(audit['issues'])
                if raw != self.source_bytes or _capset(current['CapabilityBoundingSet']) != self.caps:
                    raise Unsupported('reload-source-changed')
                left()
                self.verify_ab_assets()
                left()
                _no_lock()
            left()
            return master, workers

        def fresh():
            nonlocal network_end
            left()
            network_end = min(deadline, time.monotonic() + 2.0)
            report['clients_closed'] = False
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clients.append(raw)
            raw.setblocking(False)
            left()
            code = raw.connect_ex(('127.0.0.1', self.ab_assets['endpoints'][0]))
            left()
            if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR):
                raise Unsupported('reload-loopback-connect-unavailable')
            end = network_end
            while code:
                left()
                if time.monotonic() >= end:
                    raise Unsupported('reload-connect-timeout-inconclusive')
                _, ready, _ = select.select([], [raw], [], min(0.025, left(), max(0, end - time.monotonic())))
                left()
                if ready:
                    if raw.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                        raise Unsupported('reload-loopback-connect-unavailable')
                    break
            tls = context.wrap_socket(raw, server_hostname='localhost', do_handshake_on_connect=False)
            clients.append(tls)
            tls.setblocking(False)
            io(tls, tls.do_handshake)
            if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() != pin:
                raise Unsupported('reload-leaf-pin')
            send(tls, b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            response = _reload_response(tls, io, self.nonce)
            left()
            network_end = min(overall, deadline)
            return tls, response

        def ids(rows):
            return {r['identity'] for r in rows}

        def serves(response, rows):
            return any(response['pid'] == r['identity'][0] for r in rows)

        try:
            if report['signal_attempted']:
                raise Unsupported('reload-signal-already-attempted')
            if type(plan.get('release_time')) is not float or not 0 < plan['release_time'] < float('inf'):
                raise Unsupported('reload-release-time-unavailable')
            overall = min(entry + RELOAD_OVERALL_SECONDS,
                          plan['release_time'] + RELOAD_RELEASE_LIMIT_SECONDS)
            deadline = overall
            report.update(deadline=overall, overall_deadline=overall)
            start_stage('preparation', entry)
            if (not self.reload_phase(phase) or self.ab_plans.get(phase) is not plan
                    or self.ab_report['arms'][phase]['startup'] != 'observed-running'
                    or not report['requested']):
                raise Unsupported('reload-B-startup-unverified')
            if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
                raise Unsupported('reload-linux-pidfd-unavailable')
            # Fresh Linux/root CLI only (preflight); signal.signal also refuses
            # non-main-thread use. Never borrow or overwrite an existing timer.
            # Opt-in A/B RuntimeMaxSec=30s independently bounds the service.
            # This controller cannot bound kernel D-state or noninterruptible C waits.
            try:
                if sys.platform != 'linux' or not all(hasattr(signal, name) for name in (
                        'SIGALRM', 'ITIMER_REAL', 'getitimer', 'setitimer', 'getsignal', 'signal',
                        'pthread_sigmask')):
                    raise Unsupported('reload-deadline-guard-unavailable')
                # env -i does not reset inherited masks; query without changing one.
                inherited_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                if signal.SIGALRM in inherited_mask:
                    raise Unsupported('reload-deadline-signal-blocked')
                report['deadline_signal_unblocked'] = True
                if any(signal.getitimer(signal.ITIMER_REAL)):
                    raise Unsupported('reload-deadline-timer-active')
                previous_alarm_handler = signal.getsignal(signal.SIGALRM)
                # Register intent before mutation so even partial setup is undone.
                alarm_handler_installed = True
                signal.signal(signal.SIGALRM, reload_alarm)
                alarm_timer_owned = True
                left()
                signal.setitimer(signal.ITIMER_REAL, max(0.000001, overall - time.monotonic()), 0.0)
                # One overall alarm; stage transitions/polls NEVER renew it.
                left()
            except Unsupported:
                raise
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                raise Unsupported('reload-deadline-guard-unavailable') from None
            report['deadline_enforcement'] = ('SIGALRM wall-clock for interruptible controller work; '
                                               'kernel uninterruptible waits not guaranteed')
            (self.directory / base).mkdir(mode=0o700)
            left()
            certificate, _ = _read_private_source(self.directory / 'nnp-ab/private.crt', 65536)
            left()
            pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.decode('ascii'))).hexdigest()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            left()
            context.load_verify_locations(cafile=str(self.directory / 'nnp-ab/private.crt'))
            left()
            report['tls'] = {'own_certificate_trust_only': True, 'leaf_sha256': pin,
                             'hostname_check_required': context.check_hostname}
            master, old = snapshot('before', source=True)
            report.update(before_master=master, old_cohort=old,
                source_caps=sorted(self.caps), startup_caps=sorted(_capset(self.ab_profiles[phase]['CapabilityBoundingSet'])),
                source_mask=sum(1 << CAP_BITS[c] for c in self.caps),
                startup_mask=master['status']['CapBnd'], reload_mask=master['status']['CapBnd'],
                reload_caps_observation='verified-before-signal',
                reload_caps=sorted(c for c, bit in CAP_BITS.items() if master['status']['CapBnd'] & (1 << bit)),
                cap_kill_present=bool(master['status']['CapBnd'] & (1 << CAP_BITS['CAP_KILL'])),
                effective_NNP={'unit': 'no', 'master': master['status']['NoNewPrivs'],
                               'workers': [r['status']['NoNewPrivs'] for r in old]})
            report['cap_kill_note'] = ('probe B only; CAP_KILL effective/permitted verified'
                if self.compare_cap_kill and phase == CAP_KILL_PHASES[1] else
                'already in source/startup profile; no difference' if report['cap_kill_present'] else
                                      'absent in observed profile; failure possible, not an automatic causal diagnosis')
            report['capability_delta'] = sorted(set(report['startup_caps']) ^ set(report['reload_caps']))
            if self.compare_cap_kill:
                report['master_cap_kill_effective'] = bool(master['status']['CapEff'] & (1 << CAP_BITS['CAP_KILL']))
                report['source_to_startup_delta'] = sorted(set(report['startup_caps']) - set(report['source_caps']))
            held, response = fresh()
            report['baseline_request'] = response
            if not serves(response, old):
                raise Unsupported('reload-baseline-not-old-worker')
            for row in [master] + old:
                left()
                fd = os.pidfd_open(row['identity'][0], 0)
                pidfds.append(fd)
                left()
            master_before = master
            again, workers = snapshot('bound', source=True)
            if again != master or workers != old or any(closed(fd) for fd in pidfds):
                raise Unsupported('reload-pidfd-binding-changed')
            report['pidfd_binding_verified'] = True
            # Last complete identity/unit/source/config/TLS/executable/lock checks
            # are above; no numeric-PID signal, arbitrary target or unit hook.
            # Busy across reload, NOT idle keepalive. Delay partial headers until
            # the last complete binding verification to minimize its open window.
            send(held, b'GET / HTTP/1.1\r\nHost: localhost\r\n')
            complete_stage()
            start_stage('new_worker')  # Immediately before the sole USR2 attempt.
            report.update(signal_attempted=True, signal_sent=None)
            mark('signal_attempted_at', 'signal-attempted')
            self.ab_report['reload_usr2_tested'] = True
            left()
            try:
                signal.pidfd_send_signal(pidfds[0], signal.SIGUSR2, None, 0)
            except OSError:
                report['signal_sent'] = False
                raise
            report['signal_sent'] = True
            mark('signal_sent_at', 'signal-sent')
            left()
            while True:
                _, workers = snapshot('generation')
                new = [r for r in workers if r['identity'] not in ids(old)]
                if new:
                    mark('new_worker_first_seen_at', 'new-worker-first-seen')
                    tls, response = fresh()
                    tls.close()
                    if serves(response, new):
                        mark('new_worker_served_at', 'new-worker-served')
                        _, confirmed = snapshot('new-confirmed')
                        if not ids(new) <= ids(confirmed):
                            raise Unsupported('reload-new-cohort-changed')
                        report.update(new_cohort=new, new_request=response)
                        complete_stage()
                        break
                    if not serves(response, old):
                        raise Unsupported('reload-fresh-unanchored-worker')
                pause()  # Only read-only inventory/request retries, NEVER signal retry.
            start_stage('continuity')
            held_index = next(i for i, r in enumerate(old) if r['identity'][0] == report['baseline_request']['pid'])
            if closed(pidfds[held_index + 1]):
                raise Unsupported('reload-held-old-worker-exited-before-continuity')
            send(held, b'\r\n')
            network_end = min(deadline, time.monotonic() + 2.0)
            response = _reload_response(held, io, self.nonce)
            network_end = deadline
            report['continuity_request'] = response
            if not serves(response, old):
                raise Unsupported('reload-continuity-not-old-worker')
            left()
            mark('continuity_complete_at', 'old-connection-continuity-complete')
            for client in clients:
                left()
                client.close()
                left()
            report['clients_closed'] = True
            mark('clients_closed_at', 'all-clients-closed-before-drain')
            complete_stage(end=report['clients_closed_at'])
            # Anchor the drain budget to actual closure, never a later fresh clock.
            start_stage('old_worker_exit', start=report['clients_closed_at'])
            while True:
                exited = [closed(fd) for fd in pidfds[1:]]
                if exited and all(exited):
                    complete_stage()
                    report.update(old_workers_exited=True,
                                  old_worker_exit_proof='pidfd-POLLIN-after-client-close')
                    report['old_workers_exited_at'] = event('old-workers-pidfd-POLLIN',
                        report['stages']['old_worker_exit']['end_at'])
                    break
                pause()  # POLLIN proves exit even for a zombie; absence is not death.
            start_stage('final_verification')
            _, workers = snapshot('drained', source=True)
            if ids(workers) != ids(new) or ids(workers) & ids(old):
                raise Unsupported('reload-post-drain-cohort')
            tls, response = fresh()
            report['clients_closed'] = False
            tls.close()
            left()
            report['final_request'] = response
            mark('final_request_at', 'final-TLS-request')
            if not serves(response, workers):
                raise Unsupported('reload-final-not-new-worker')
            final_master, final_workers = snapshot('final', source=True)
            if ids(final_workers) != ids(new):
                raise Unsupported('reload-final-cohort-changed')
            report.update(after_master=final_master, final_cohort=final_workers,
                reload_mask=final_master['status']['CapBnd'], reload_caps_observation='verified-after-drain',
                reload_caps=sorted(c for c, bit in CAP_BITS.items() if final_master['status']['CapBnd'] & (1 << bit)),
                cap_kill_present=bool(final_master['status']['CapBnd'] & (1 << CAP_BITS['CAP_KILL'])),
                effective_NNP={'unit': 'no', 'master': final_master['status']['NoNewPrivs'],
                               'workers': [r['status']['NoNewPrivs'] for r in final_workers]})
            report['capability_delta'] = sorted(set(report['startup_caps']) ^ set(report['reload_caps']))
            complete_stage()  # Final bookkeeping is also inside the verification bounds.
            report['verification_finished_at'] = event('verification-finished',
                report['stages']['final_verification']['end_at'])
            report['status'] = 'passed'
        except KeyboardInterrupt:
            report['status'] = 'interrupted'
            raise
        except Unsupported as exc:
            # Reclassify a blocking operation's failure if it consumed the stage.
            if report['deadline_scope'] is None:
                try:
                    left()
                except Unsupported as expired:
                    exc = expired
            report.update(status='failed' if report['signal_sent'] else 'unavailable', issues=list(exc.labels))
        except (OSError, ValueError, subprocess.SubprocessError):
            issues = ['reload-inspection-or-io-unavailable']
            try:
                left()
            except Unsupported as expired:
                issues = list(expired.labels)
            report.update(status='unavailable', issues=issues)
        finally:
            in_cleanup = True
            blocked, deferred_interrupt = None, False
            try:
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            except KeyboardInterrupt:
                report['status'] = 'interrupted'
                deferred_interrupt = True
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                report['issues'].append('reload-cleanup-signal-mask-unavailable')
            finished = time.monotonic()
            if report['verification_finished_at'] is None:
                report['verification_finished_at'] = finished
                event('verification-finished-without-pass', finished)
            for name, stage in report['stages'].items():
                if stage['start_at'] is None:
                    stage['status'] = 'missing'  # No fabricated start/end/elapsed.
                elif stage['status'] == 'in-progress':
                    stage.update(end_at=finished, elapsed=finished - stage['start_at'],
                        status='interrupted' if report['status'] == 'interrupted' else
                               'deadline' if report['deadline_scope'] else 'failure')
            # Only a successful disable confirms our timer is disarmed. If it
            # fails, leave reload_alarm installed: in_cleanup ignores late ALRM,
            # whereas restoring a previous SIG_DFL could terminate the controller.
            disarm_confirmed = not alarm_timer_owned
            if alarm_timer_owned:
                try:
                    signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
                    disarm_confirmed = True
                except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                    report['issues'].extend(['reload-deadline-timer-disable-unconfirmed',
                                             'reload-deadline-handler-left-installed'])
                    if report['status'] != 'interrupted':
                        report['status'] = 'unavailable'
            if alarm_handler_installed and disarm_confirmed:
                try:
                    signal.signal(signal.SIGALRM, previous_alarm_handler)
                except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                    report['issues'].append('reload-deadline-handler-restore-unconfirmed')
            report['clients_closed'] = True
            for client in clients:
                try:
                    client.close()
                except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                    report['clients_closed'] = False
                    report['issues'].append('reload-client-close-unconfirmed')
            if clients and report['clients_closed'] and report['clients_closed_at'] is None:
                mark('clients_closed_at', 'all-clients-closed-in-finally')
            for fd in pidfds:
                try:
                    os.close(fd)
                except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                    report['issues'].append('reload-pidfd-close-unconfirmed')
            # Unmask before final evidence so failures/pending INT or TERM are
            # reflected in it, but defer any interrupt until finalization ends.
            if blocked is not None:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                except KeyboardInterrupt:
                    report['status'] = 'interrupted'
                    deferred_interrupt = True
                except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                    report['issues'].append('reload-cleanup-signal-mask-restore-unconfirmed')
            if report['issues'] and report['status'] == 'passed':
                report['status'] = 'unavailable'
            finished = time.monotonic()
            report.update(finished_at=finished, elapsed=finished - entry)
            if type(report['release_time']) is float:
                report['elapsed_after_release'] = finished - report['release_time']
            try:
                snapshot_report = dict(report, snapshot_phase='pre-unit-cleanup') if self.compare_cap_kill else report
                self.record(base + '/report.json', snapshot_report)
            except (OSError, ValueError):
                if report['status'] != 'interrupted':
                    report['status'] = 'unavailable'
                report['issues'].append('reload-evidence-write-unavailable')
            self.ab_report['reload_required'] = report['status'] != 'passed'
            if deferred_interrupt:
                raise KeyboardInterrupt
        return report

    def cap_kill_startup_samples_valid(self, samples, phase):
        complete_cohort_seen = False
        for sample in samples:
            master, workers = sample['master'], sample['workers']
            if sample['other_haproxy'] or (master is not None and not self.ab_master_valid(master, phase)):
                return False
            if not workers:
                # The gate can release before HAProxy execs or forks workers.
                if complete_cohort_seen:
                    return False
                continue
            if master is None or not all(self.ab_worker_valid(worker, False, phase) for worker in workers):
                return False
            complete_cohort_seen = True
        return complete_cohort_seen

    def cap_kill_arm_valid(self, phase):
        """A timeout is a failed reload, not a pass; accept only proved live-old failure."""
        row = self.ab_report['arms'][phase]
        report = row['reload']
        if (row['startup'] != 'observed-running' or row['effective_NNP'] != 'no'
                or not row['cleanup_confirmed']
                or not self.cap_kill_startup_samples_valid(row['proc_samples'], phase)
                or not report['signal_sent'] or not report['pidfd_binding_verified']
                or not report['clients_closed'] or report['unit_cleanup']['confirmed'] is not True
                or not report['coverage'] or not all(c['complete'] for c in report['coverage'])
                or report['before_master'] is None
                or not self.ab_master_valid(report['before_master']['status'], phase)
                or not report['old_cohort']
                or not all(self.ab_worker_valid(r['status'], False, phase)
                           for r in report['old_cohort'] + report['new_cohort'])):
            return False
        if report['status'] == 'passed':
            return (not report['issues']
                    and report['unit_cleanup']['old_exit_verified_before_cleanup'] is True)
        # No inference from late POLLIN, missing evidence, cleanup or TLS errors.
        observations = report['old_worker_timeout_observations']
        return bool(phase == CAP_KILL_PHASES[0] and report['status'] == 'failed'
            and report['issues'] == ['reload-old-worker-exit-deadline-inconclusive']
            and report['new_request'] and report['continuity_request']
            and report['stages']['continuity']['status'] == 'success'
            and observations and len(observations) == len(report['old_cohort'])
            and {tuple(r['identity']) for r in observations} ==
                {tuple(r['identity']) for r in report['old_cohort']}
            and all(r['alive_at_deadline'] is True for r in observations))

    def finish_cap_kill_comparison(self):
        a_phase, b_phase = CAP_KILL_PHASES
        comparison = self.compare_nnp_ab(self.ab_profiles[a_phase], self.ab_profiles[b_phase],
                                         self.ab_plans[a_phase], self.ab_plans[b_phase])
        valid = {p: self.cap_kill_arm_valid(p) for p in CAP_KILL_PHASES}
        passed = self.ab_report['arms'][b_phase]['reload']['status'] == 'passed'
        proven = comparison['ok'] and all(valid.values()) and passed
        a_passed = self.ab_report['arms'][a_phase]['reload']['status'] == 'passed'
        self.ab_report['cap_kill_comparison'].update(
            valid_runs=valid, inventory=comparison, proven=proven,
            finding=('both-reloads-passed' if a_passed else 'A-old-worker-alive-at-deadline-B-passed')
                    if proven else 'inconclusive')
        self.ab_report.update(status='cap-kill-comparison-proven' if proven else 'inconclusive',
            diagnostic_finding_completed=proven,
            reload_usr2_tested=any(self.ab_report['arms'][p]['reload']['signal_attempted']
                                  for p in CAP_KILL_PHASES),
            reload_required=not passed)
        return 0 if proven else 2

    def run_nnp_ab(self, reload_usr2=False, compare_cap_kill=False):
        # Initialize BEFORE preflight/helpers: NOTSTARTED is not invented proc data.
        if (type(reload_usr2) is not bool or type(compare_cap_kill) is not bool
                or compare_cap_kill and not reload_usr2):
            raise Unsupported('ab-reload-option')
        self.compare_cap_kill = compare_cap_kill
        phases = self.ab_phases()
        self.reload_report = reload_report(reload_usr2)
        self.ab_report = {'status': 'NOTSTARTED', 'complete': False, 'production_applied': False,
            'diagnostic_finding_completed': False, 'confirmed_startup_difference': False,
            'actual_master_NNP': {'A': 'unavailable', 'B': 'unavailable'},
            'reload_usr2_tested': False, 'reload_required': True, 'startup_candidate': False,
            'scope': 'environment/control-specific TLS-config startup only; not Linux-universal',
            'prospective_fix': 'ONLY HAProxy NoNewPrivileges=no; NOT applied',
            'risk': 'Loss of kernel NNP exec-gain barrier for setID/file capabilities in master and descendants '
                    'that do not self-set NNP; bounding/other hardening are not a replacement.',
            'limits': ['no connection/TLS health proof or production health claim',
                       'no reload/USR2 proof, no CAP_KILL addition or capability promotion',
                       'legacy make_config probe has no TLS; root master/nonroot workers unchanged'],
            'reload': self.reload_report,
            'arms': {p: {'startup': 'NOTSTARTED', 'proc_samples': [], 'proc_identity': 'unavailable',
                         'effective_NNP': 'unavailable', 'gate_boundaries': 'unavailable',
                         'cleanup_confirmed': False} for p in phases}}
        if compare_cap_kill:
            self.ab_report.update(
                scope='isolated CAP_KILL reload comparison; NNP=no both arms',
                prospective_fix='probe-only CAP_KILL addition; production NOT changed',
                limits=['not causal or production health proof', 'unit reload wrapper untested'],
                cap_kill_comparison={'proven': False, 'valid_runs': {}, 'finding': 'inconclusive'})
            for phase in phases:
                report = reload_report(True)
                report.update(master_cap_kill_effective=None, source_to_startup_delta=None)
                report['cleanup_evidence'] = ('nnp-ab.report.json:arms.' + phase +
                    '.reload.unit_cleanup (canonical after unit cleanup)')
                self.ab_report['arms'][phase]['reload'] = report
        def finding(code):
            self.ab_report['startup_status'] = self.ab_report['status']
            return 2 if reload_usr2 and self.reload_report['status'] != 'passed' else code

        self.prepare(ab=True)
        if compare_cap_kill and self.caps != CAPS3:
            raise Unsupported('cap-kill-already-in-source')
        if reload_usr2 and not compare_cap_kill:
            self.reload_report.update(source_caps=sorted(self.caps),
                                      source_mask=sum(1 << CAP_BITS[c] for c in self.caps))
            self.ab_report['scope'] = 'isolated TLS-config startup A/B plus B pidfd USR2/local-request proof'
            self.ab_report['limits'] = ['probe-only HTTP responder; not production health',
                'unit reload wrapper untested; no production change or complete fix',
                'same source capabilities; no CAP_KILL addition or capability promotion']
        self.prepare_ab_assets()
        self.ab_report['status'] = 'incomplete'
        for phase in phases:
            if phase == phases[1]:
                if compare_cap_kill and not self.cap_kill_arm_valid(phases[0]):
                    raise Unsupported('cap-kill-A-run-invalid')
                if self.intents or not self.cleanup_confirmed:
                    raise Unsupported('ab-A-cleanup-unconfirmed')
                self.reserve(self.ab_assets['endpoints'])  # Conflict refuses; NEVER choose new endpoints.
            if compare_cap_kill:
                self.reload_report = self.ab_report['arms'][phase]['reload']
                self.ab_report['reload'] = self.reload_report  # Last selected arm, NOT canonical cleanup.
                self.ab_report['reload_required'] = True  # This arm has not verified reload yet.
                self.reload_report.update(source_caps=sorted(self.caps),
                    source_mask=sum(1 << CAP_BITS[c] for c in self.caps))
            row = self.ab_report['arms'][phase]
            row['startup'] = 'unavailable'
            startup, _ = self.run_phase(phase)
            row.update(startup=startup, cleanup_confirmed=True,
                       proc_identity='stable-observed' if startup == 'observed-running' else 'unavailable',
                       effective_NNP=self.ab_profiles[phase]['NoNewPrivileges'],
                       gate_boundaries=self.read_boundaries(self.ab_plans[phase]))
        a, b = (self.ab_report['arms'][p] for p in phases)
        a_masters = [s['master'] for s in a['proc_samples'] if s['master'] is not None]
        b_masters = [s['master'] for s in b['proc_samples'] if s['master'] is not None]
        self.ab_report['actual_master_NNP'] = {
            'A': [s['NoNewPrivs'] for s in a_masters] if a_masters else 'unavailable',
            'B': [s['NoNewPrivs'] for s in b_masters] if b_masters else 'unavailable'}
        if compare_cap_kill:
            return self.finish_cap_kill_comparison()
        self.ab_report['comparative_verification'] = 'incomplete'
        if (b['startup'] != 'observed-running' or not b_masters or b['effective_NNP'] != 'no'
                or not all(self.ab_master_valid(s, 'nnp-no') for s in b_masters)):
            self.ab_report['status'] = 'inconclusive'
            return finding(2)
        # Failed A may lack SETUID exactly as observed in the Python control,
        # but unrelated capability anomalies cannot confirm an NNP-only result.
        if a_masters and not all(self.ab_master_valid(s, 'nnp-yes', failed_arm=a['startup'] == 'failed')
                                 for s in a_masters):
            self.ab_report['status'] = 'inconclusive-A-credentials'
            return finding(2)
        if a['startup'] == 'observed-running':
            self.ab_report.update(status='no-NNP-startup-differentiator', diagnostic_finding_completed=True,
                                  comparative_verification='both-started')
            return finding(0)
        self.ab_report.update(status='CANDIDATE-startup-only', startup_candidate=True)
        if (a['startup'] == 'failed' and a_masters
                and all(self.ab_master_valid(s, 'nnp-yes', failed_arm=True) for s in a_masters)
                and all(self.ab_master_valid(s, 'nnp-no') for s in b_masters)):
            self.ab_report.update(confirmed_startup_difference=True, diagnostic_finding_completed=True,
                                  comparative_verification='confirmed-startup-only')
            return finding(0)  # Completed diagnostic finding, NEVER a complete production fix.
        return finding(2)

    def read_boundaries(self, plan):
        _secure_path(plan['output'])
        with plan['output'].open('rb') as stream:
            raw = stream.read(65536)  # Snapshots precede unrelated HAProxy output.
        return boundary_records(raw, str(self.directory / plan['phase']),
                                plan['phase'] in ('cap-gated', 'cap-direct') or
                                re.fullmatch(r'mx(?:0[0-9]|1[0-9]|2[0-7])', plan['phase']) is not None)

    def run_controls(self):
        outcomes = {}
        for phase in ('cap-gated', 'cap-direct'):
            plan = control_plan(self.directory, self.nonce, self.caps, phase)
            (self.directory / phase).mkdir(mode=0o700)
            self.save(phase + '/combined.log', b'')
            self.boundary_plans.append(plan)
            outcomes[phase] = 'unavailable'
            try:
                _no_lock()
                if self.show(plan['unit'], absent=True).get('LoadState') != 'not-found':
                    raise Unsupported('unit-name-conflict')
                self.intents.append(plan['unit'])
                self.record(phase + '/intent.json', {'unit': plan['unit'], 'nonce': self.nonce, 'command': plan['command']})
                plan['created_at'] = time.monotonic()
                code, _, _ = self.command(plan['command'])
                if code != 0:
                    raise Unsupported('transient-create-unavailable')
                self.creation_confirmed.add(plan['unit'])
                profile = self.gate(plan)
                deadline = time.monotonic() + 3.4
                released = phase == 'cap-direct'  # Direct gate released control-go.
                while time.monotonic() < deadline:
                    records = self.read_boundaries(plan)
                    if any(r['stage'] == 'control-entry' for r in records) and not released:
                        live = self.show(plan['unit'], timeout=max(0.01, deadline - time.monotonic()))
                        audit = self.audit_compatibility(profile, live, plan=plan, probe_source=True)
                        self.record(phase + '/helper-comparison.json', audit)
                        _raise_unsupported(audit['issues'])
                        if live.get('ActiveState') != 'active' or live.get('SubState') != 'running':
                            raise Unsupported('control-helper-unavailable')
                        _no_lock()
                        self.save(phase + '/control-go', b'')
                        profile, released = live, True
                    if any(r['stage'] == 'after-exec' for r in records):
                        expected = ['gate-entry', 'gate-exit'] if phase == 'cap-gated' else []
                        if [r['stage'] for r in records] != expected + ['control-entry', 'after-exec']:
                            raise Unsupported('control-record-sequence')
                        self.control_profiles[phase], self.control_records[phase] = profile, records
                        outcomes[phase] = 'recorded'
                        break
                    time.sleep(0.025)
                self.record(phase + '/control-result.json', {'status': outcomes[phase]})
            except Unsupported as exc:
                self.record(phase + '/control-result.json', {'status': 'unavailable', 'issues': list(exc.labels)})
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.record(phase + '/control-result.json', {'status': 'unavailable', 'unavailable': type(exc).__name__})
            finally:
                if plan['unit'] in self.intents:
                    if self.cleanup_one(plan['unit']):
                        self.intents.remove(plan['unit'])
                    else:
                        self.cleanup_confirmed = False
        if len(self.control_profiles) == 2:
            a, b = (self.control_profiles[p] for p in ('cap-gated', 'cap-direct'))
            pa, pb = (control_plan(self.directory, self.nonce, self.caps, p) for p in ('cap-gated', 'cap-direct'))
            ea, eb = self.control_empty_exec_fields(a, pa), self.control_empty_exec_fields(b, pb)
            comparison = _comparison_inventory(a, b, empty_source=ea, empty_probe=eb)
            self.record('boundaries.control-comparison.json', comparison)
            _raise_unsupported(restriction_differences(a, b, checked_empty_source=ea, checked_empty_probe=eb))
        return outcomes

    def validate_matrix(self, probe, plan):
        """Separate fixed Python validator; never weaken the production/control gate."""
        if not isinstance(probe, dict) or not isinstance(plan, dict):
            raise Unsupported('matrix-snapshot-or-plan-format')
        expected = matrix_plan(self.directory, self.nonce, self.caps, plan.get('index'), plan.get('enabled'))
        if any(plan.get(k) != v for k, v in expected.items()):
            raise Unsupported('matrix-plan')
        if not owned_unit(probe, plan['unit'], self.nonce):
            raise Unsupported('matrix-ownership')
        _require(probe, {
            'LoadState': 'loaded', 'DropInPaths': '', 'NeedDaemonReload': 'no',
            'User': 'root', 'Group': 'root', 'Type': 'simple', 'Slice': 'system.slice',
            'SecureBits': '0', 'AmbientCapabilities': '', 'UMask': '0077',
            'RuntimeMaxUSec': '8s', 'TimeoutStartUSec': '5s', 'TimeoutStopUSec': '2s',
            'TimeoutAbortUSec': '2s', 'Restart': 'no', 'RestartUSec': '3s', 'CanReload': 'no',
            'KillMode': 'control-group', 'SendSIGKILL': 'yes', 'StandardOutput': 'append',
            'StandardError': 'append', 'PrivateNetwork': 'no', 'PrivateUsers': 'no',
            'RootDirectory': '', 'RootImage': '', 'JoinsNamespaceOf': '', 'SystemCallFilter': '~',
        })
        if _capset(probe.get('CapabilityBoundingSet')) != self.caps:
            raise Unsupported('matrix-bounding')
        if any(k not in probe for k in MATRIX_KNOBS):
            raise Unsupported('matrix-missing-knob')
        for key in MATRIX_KNOBS:
            requested = _matrix_value(key, expected['properties'][key])
            applied = _matrix_value(key, probe[key])
            implied_nnp = key == 'NoNewPrivileges' and requested == 'no' and applied == 'yes'
            if not _matrix_allowed(key, probe[key]) or (requested != applied and not implied_nnp):
                raise Unsupported('matrix-effective-value:' + key)
        for key in ('ExecStart', 'ExecStartEx'):
            if (key == 'ExecStart' or key in probe) and not _exec_struct(probe.get(key), expected['argv']):
                raise Unsupported('matrix-command')
        self._empty_exec_fields(probe, plan, PROBE_EMPTY_EXEC_HOOKS + ('ExecStartPre',))
        self.validate_probe_logging(probe, plan)
        self._validate_probe_watchdog(probe, plan)

    def matrix_mount_manager(self):
        """One read-only system-manager sample, before any matrix helper exists."""
        if self.matrix_mount_manager_sample is not None:
            return self.matrix_mount_manager_sample
        code, out, _ = self.command(['/usr/bin/systemctl', '--system', 'show', '--property=Version'])
        sample = {'available': False, 'version': None, 'verified_255': False,
                  'scope': 'system-manager sampled once for this matrix run'}
        try:
            props = parse_show(out.decode('utf-8', 'strict')) if len(out) <= 4096 else {}
            if code == 0 and set(props) == {'Version'} and props['Version']:
                sample.update(available=True, version=props['Version'])
                sample['verified_255'] = bool(re.fullmatch(
                    r'255(?:[.\-+~][0-9A-Za-z][0-9A-Za-z.+:~_\-]*)?', props['Version']))
        except (UnicodeError, Unsupported):
            pass
        sample['reason'] = ('verified-system-manager-255' if sample['verified_255'] else
                            'unsupported-manager-version' if sample['available'] else 'manager-version-unavailable')
        self.matrix_mount_manager_sample = sample
        self.record('matrix.mount-manager.json', sample)
        self.matrix_report['mount_manager'] = sample
        return sample

    def matrix_mount_audit(self, a, b, source_plan=None, probe_plan=None, source=False):
        """PURE, opt-in proof for exactly RequiresMountsFor, never a path exemption.

        v255 unit_add_exec_dependencies registers ONLY /var/tmp for PrivateTmp;
        tmp.mount is separately weak Wants/After (allow masked), plus tmpfiles
        ordering. Root/working/image and the five managed directories also add
        mount paths. ReadWritePaths and append log files do NOT do so here.
        https://raw.githubusercontent.com/systemd/systemd/v255/src/core/unit.c
        (unit_add_exec_dependencies, around lines 1177-1252)
        The getter exposes exact registered hashmap path keys, not mount units
        or prefix closure; do not expand /var/tmp into /tmp or ancestor paths.
        https://raw.githubusercontent.com/systemd/systemd/v255/src/core/dbus-unit.c
        (property_get_requires_mounts_for, around lines 169-195)
        https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#
        Version is proof scope, NOT evidence of any VPS/SETUID root cause.
        """
        producers = ('WorkingDirectory', 'RootDirectory', 'RootImage', 'RuntimeDirectory',
                     'StateDirectory', 'CacheDirectory', 'LogsDirectory', 'ConfigurationDirectory')
        logs = ('StandardOutput', 'StandardError', 'StandardOutputFile', 'StandardErrorFile', 'ReadWritePaths')
        manager = self.matrix_mount_manager_sample or {'available': False, 'version': None,
                                                       'verified_255': False, 'reason': 'manager-not-sampled'}
        scoped = bool(source_plan is not None or probe_plan is not None)

        def observed(properties, key):
            return {'present': key in properties, 'raw': properties.get(key)}

        def side(properties, plan, production):
            errors = []
            requested = self.fragment if production else (plan.get('properties') if isinstance(plan, dict) else None)
            requested_available = isinstance(requested, dict)
            requested = requested if requested_available else {}
            result = {'role': 'production-source' if production else 'matrix-probe',
                      'id': properties.get('Id'), 'phase': plan.get('phase') if isinstance(plan, dict) else None,
                      'requested_context_available': requested_available,
                      'provenance_basis': 'audited-full-source-fragment' if production else 'registered-exact-fixed-matrix-plan',
                      'requested_requires': observed(requested, 'RequiresMountsFor'),
                      'requested_cli_requires': {'available': False, 'present': None, 'raw': None},
                      'effective_requires': observed(properties, 'RequiresMountsFor'),
                      'requested_private_tmp': observed(requested, 'PrivateTmp'),
                      'effective_private_tmp': observed(properties, 'PrivateTmp'),
                      'producer_context': {k: observed(properties, k) for k in producers},
                      'requested_producer_context': {k: observed(requested, k) for k in producers},
                      'proof_context': {k: observed(properties, k) for k in
                                        ('Id', 'LoadState', 'Transient', 'Description', 'FragmentPath',
                                         'DropInPaths', 'NeedDaemonReload', 'ControlGroup')},
                      'log_context': {'requested': {k: observed(requested, k) for k in logs},
                                      'effective': {k: observed(properties, k) for k in logs}},
                      'expected_paths': None, 'observed_paths': None,
                      'explicit_request_absence_proved': False, 'provenance_valid': False}
            if not scoped:
                errors.append('strict-comparison-no-proof-scope')
            elif production:
                collect_unsupported(errors, validate_effective, properties, self.fragment)
                # Also verifies the complete fragment key grammar, including
                # forbidding a RequiresMountsFor directive even with empty RHS.
                collect_unsupported(errors, _source_empty_exec_fields, properties, self.fragment)
            elif not isinstance(plan, dict):
                errors.append('matrix-plan-not-supplied')
            else:
                registered = self.matrix_plans.get(plan.get('phase'))
                if registered is None or registered != plan:
                    errors.append('matrix-plan-not-registered')
                collect_unsupported(errors, self.validate_matrix, properties, plan)
                assignments = collect_unsupported(errors, self._plan_assignments, plan)
                if assignments is not None:
                    values = [v for k, v in assignments if k == 'RequiresMountsFor']
                    result['requested_cli_requires'] = {'available': True, 'present': bool(values),
                                                        'raw': values if values else None}
                if ('RequiresMountsFor' in requested or
                        any(k == 'RequiresMountsFor' for k, _ in assignments or ())):
                    errors.append('explicit-mount-request-forbidden')
            result['provenance_valid'] = not errors
            result['explicit_request_absence_proved'] = not errors and 'RequiresMountsFor' not in requested
            if not manager.get('verified_255'):
                errors.append('system-manager-255-unproved')
            for key in producers:
                if key not in properties or properties[key] != '':
                    errors.append('dependency-producer-not-verified-empty:' + key)
            private = properties.get('PrivateTmp')
            if private not in ('yes', 'no'):
                errors.append('private-tmp-not-proved-on-or-off')
            # Only fully proved contexts predict paths. Missing is never empty.
            rule = not errors
            if rule:
                result['expected_paths'] = ['/var/tmp'] if private == 'yes' else []
            value = properties.get('RequiresMountsFor')
            if 'RequiresMountsFor' not in properties:
                errors.append('effective-mount-key-missing')
            elif value == '':
                result['observed_paths'] = []
            elif value == '/var/tmp':
                result['observed_paths'] = ['/var/tmp']
            else:
                # Reject escapes, specifiers, whitespace, duplicates, /tmp,
                # unrelated paths and all noncanonical spellings, even if equal.
                errors.append('mount-paths-outside-exact-model')
            if rule and result['observed_paths'] != result['expected_paths']:
                errors.append('mount-paths-not-exact-private-tmp-derivation')
            outside = scoped and 'RequiresMountsFor' in properties and value not in ('', '/var/tmp')
            result.update(status=('verified-generated-private-tmp' if not errors else
                                  'unsupported' if outside or (rule and 'RequiresMountsFor' in properties) else 'unproved'),
                          reasons=sorted(set(errors)), rule_context_proved=rule)
            return result

        sides = {'source': side(a, source_plan, source), 'probe': side(b, probe_plan, False)}
        verified = all(s['status'] == 'verified-generated-private-tmp' for s in sides.values())
        return {'property': 'RequiresMountsFor', 'scope_requested': scoped, 'manager': manager,
                'coverage': ('unknown-both-effective-keys-absent' if 'RequiresMountsFor' not in a
                             and 'RequiresMountsFor' not in b else 'observed-effective-keys'),
                'sides': sides, 'verified': verified,
                'classification': ('verified-generated-private-tmp' if verified else
                                   'unsupported' if any(s['status'] == 'unsupported' for s in sides.values()) else 'unproved'),
                'scope': 'exact registered roots; logging context is not a dependency producer'}

    def record_matrix_inventory(self, inventory, artifact, phase, stage, roles=None):
        """Private raw mount details in both the comparison and the top report."""
        mount = inventory.get('mount_dependency_audit')
        if roles and mount:
            for key, role in zip(('source', 'probe'), roles):
                mount['sides'][key]['role'] = role
        self.record(artifact, inventory)
        rows = [r for r in inventory.get('properties', []) if r['property'] == 'RequiresMountsFor']
        detail = {'artifact': artifact, 'phase': phase, 'stage': stage,
                  'roles': roles or ['reference', 'observation'], 'rows': rows,
                  'mount_dependency_audit': inventory.get('mount_dependency_audit')}
        self.matrix_report.setdefault('comparisons', []).append(detail)
        if any(not r['raw_equal'] or r['unsupported'] for r in rows):
            self.matrix_report.setdefault('mount_mismatches', []).append(detail)

    def matrix_inventory(self, a, b, variable=False, source=False, *, source_plan=None, probe_plan=None):
        hooks = frozenset(n + suffix for n in PROBE_EMPTY_EXEC_HOOKS + ('ExecStartPre',) for suffix in ('', 'Ex'))
        inventory = _comparison_inventory(a, b, empty_source=(_source_empty_exec_fields(a, self.fragment) if source else hooks),
                                          empty_probe=hooks)
        mount = self.matrix_mount_audit(a, b, source_plan, probe_plan, source)
        inventory['mount_dependency_audit'] = mount
        for row in inventory['properties']:
            key = row['property']
            if key == 'RequiresMountsFor' and mount['scope_requested']:
                if mount['verified'] and row['source_present'] and row['probe_present']:
                    row.update(unsupported=False, classification='verified-generated-private-tmp',
                               reason='known-source-backed-PrivateTmp-distinction')
                elif mount['classification'] == 'unsupported':
                    row.update(unsupported=True, classification='unsupported',
                               reason='mount-paths-outside-proved-PrivateTmp-model')
                row['mount_proof_classification'] = mount['classification']
            if key in MATRIX_KNOBS and row['source_present'] and row['probe_present']:
                known = _matrix_allowed(key, row['source']) and _matrix_allowed(key, row['probe'])
                equal = _matrix_value(key, row['source']) == _matrix_value(key, row['probe'])
                row.update(unsupported=not (equal and known),
                           classification=('matrix-unsupported-value' if not known else
                                           'matrix-equal' if equal else 'matrix-effective-difference'),
                           reason='unsupported-value' if not known else 'known-normalization' if equal else 'effective-value-different')
                row['known_matrix_values'], row['requested_variable'] = known, variable
        inventory['unsupported'] = [r['property'] for r in inventory['properties'] if r['unsupported']]
        inventory['mismatches'] = [r for r in inventory['properties'] if r['unsupported']]
        inventory['matrix_issues'] = [r['property'] for r in inventory['properties'] if r['unsupported']
                                     and not (variable and r['property'] in MATRIX_KNOBS and r.get('known_matrix_values')
                                              and r['source_present'] and r['probe_present'])]
        inventory['effective_differences'] = [r['property'] for r in inventory['properties'] if not r['raw_equal']]
        return inventory

    def matrix_source(self, plan, stem):
        _no_lock()
        raw, fragment, errors = self._audit_fragment(plan['phase'] + '/' + stem + '.fragment')
        current = self._audit_show(MAIN, errors)
        audit = self.audit_compatibility(current, fragment=fragment, original=self.source,
                                        original_fragment=self.fragment, original_bytes=self.source_bytes,
                                        current_bytes=raw, inspection_errors=errors, allow_source_only=True)
        self.record(plan['phase'] + '/' + stem + '.show.json', current)
        profile = audit.get('source_profile_change')
        if profile is not None:
            # Original/current source drift is ALWAYS strict, never derived-path
            # normalization. Attach raw mount evidence before a refusal is raised.
            mount = self.matrix_mount_audit(self.source, current, source=True)
            # Record each observed fragment's context, without authorizing any
            # normalization of production drift (including changed log paths).
            for key, requested in (('source', self.fragment), ('probe', fragment)):
                side = mount['sides'][key]
                side['fragment_context_available'] = isinstance(requested, dict)
                side['requested_context_available'] = isinstance(requested, dict)
                side['provenance_basis'] = 'strict-production-fragment-drift-comparison'
                requested = requested if isinstance(requested, dict) else {}
                for field, prop in (('requested_requires', 'RequiresMountsFor'),
                                    ('requested_private_tmp', 'PrivateTmp')):
                    side[field] = {'present': prop in requested, 'raw': requested.get(prop)}
                for group in (side['requested_producer_context'], side['log_context']['requested']):
                    for prop in group:
                        group[prop] = {'present': prop in requested, 'raw': requested.get(prop)}
            profile['mount_dependency_audit'] = mount
            self.record_matrix_inventory(profile, plan['phase'] + '/' + stem + '.comparison.json',
                                         plan['phase'], stem,
                                         ['production-original', 'production-current'])
        self.record(plan['phase'] + '/' + stem + '.audit.json', audit)
        _raise_unsupported(audit['issues'])
        if raw != self.source_bytes or frozenset(audit['source_caps']) != self.caps:
            raise Unsupported('matrix-source-changed')
        return current

    def matrix_python(self, plan, stem):
        metadata = executable_metadata('/usr/bin/python3')
        self.record(plan['phase'] + '/' + stem + '.python.json', metadata)
        if metadata != self.matrix_python_initial:
            raise Unsupported('matrix-python-changed')
        return metadata

    def matrix_attempt(self, enabled):
        index = len(self.matrix_report['attempts'])
        if index >= 28:
            raise Unsupported('matrix-attempt-limit')
        plan = matrix_plan(self.directory, self.nonce, self.caps, index, enabled)
        self.matrix_plans[plan['phase']] = plan  # Retain the actual plan (including later created_at); max 28.
        row = {'phase': plan['phase'], 'enabled': plan['enabled'], 'status': 'unavailable'}
        self.matrix_report['attempts'].append(row)  # Failed creation consumes an index too.
        base = self.directory / plan['phase']
        base.mkdir(mode=0o700)
        self.save(plan['phase'] + '/combined.log', b'')
        self.record(plan['phase'] + '/request.json', {'properties': plan['properties'], 'required_effective_defaults': plan['required_effective_defaults'],
                                                     'command': plan['command'], 'argv': plan['argv']})
        source = self.matrix_source(plan, 'source-before')
        metadata = self.matrix_python(plan, 'before')
        if self.show(plan['unit'], absent=True).get('LoadState') != 'not-found':
            raise Unsupported('unit-name-conflict')
        _no_lock()
        self.intents.append(plan['unit'])
        self.record(plan['phase'] + '/intent.json', {'unit': plan['unit'], 'nonce': self.nonce, 'command': plan['command']})
        plan['created_at'] = time.monotonic()
        code, _, _ = self.command(plan['command'])
        if code != 0:
            raise Unsupported('transient-create-unavailable')
        self.creation_confirmed.add(plan['unit'])
        deadline = plan['created_at'] + 3.4
        while time.monotonic() < deadline:
            records = self.read_boundaries(plan)
            if records:
                break
            time.sleep(0.025)
        else:
            raise Unsupported('matrix-entry-unavailable')
        self.record(plan['phase'] + '/entry.json', records)
        entry = matrix_entry_state(records, self.caps, metadata['resolved'], entry_only=True)
        profile = self.show(plan['unit'], timeout=max(0.01, deadline - time.monotonic()))
        self.record(plan['phase'] + '/entry.show.json', profile)
        validation_errors = []
        collect_unsupported(validation_errors, self.validate_matrix, profile, plan)
        if _matrix_value('NoNewPrivileges', profile.get('NoNewPrivileges')) == 'yes' and entry['entry']['NoNewPrivs'] != 1:
            validation_errors.append('matrix-NNP-inconsistent')
        comparison = self.matrix_inventory(source, profile, variable=True, source=True, probe_plan=plan)
        comparison['validation_issues'] = validation_errors
        self.record_matrix_inventory(comparison, plan['phase'] + '/source-comparison.json',
                                     plan['phase'], 'source-comparison', ['production-source', 'matrix-probe'])
        _raise_unsupported(validation_errors + comparison['matrix_issues'])
        self.matrix_source(plan, 'source-release')
        self.matrix_python(plan, 'release')
        live = self.show(plan['unit'], timeout=max(0.01, deadline - time.monotonic()))
        self.record(plan['phase'] + '/release.show.json', live)
        validation_errors = []
        collect_unsupported(validation_errors, self.validate_matrix, live, plan)
        comparison = self.matrix_inventory(profile, live, source_plan=plan, probe_plan=plan)
        comparison['validation_issues'] = validation_errors
        self.record_matrix_inventory(comparison, plan['phase'] + '/release-comparison.json',
                                     plan['phase'], 'release')
        _raise_unsupported(validation_errors + comparison['matrix_issues'])
        if (live.get('ActiveState') != 'active' or live.get('SubState') != 'running'
                or live.get('MainPID') != str(records[0]['status']['Pid'])
                or live.get('ControlGroup') != '/system.slice/' + plan['unit']):
            raise Unsupported('matrix-helper-unavailable')
        _no_lock()
        if time.monotonic() >= deadline:
            raise Unsupported('matrix-release-deadline')
        self.save(plan['phase'] + '/control-go', b'')
        deadline = min(plan['created_at'] + 6.8, time.monotonic() + 3.0)
        while time.monotonic() < deadline:
            records = self.read_boundaries(plan)
            if any(r['stage'] == 'after-exec' for r in records):
                break
            time.sleep(0.025)
        self.record(plan['phase'] + '/boundaries.json', records)
        state = matrix_entry_state(records, self.caps, metadata['resolved'])
        self.matrix_python(plan, 'after')
        after = self.show(plan['unit'], absent=True)
        self.record(plan['phase'] + '/after.show.json', after)
        if after.get('LoadState') != 'not-found':
            validation_errors = []
            collect_unsupported(validation_errors, self.validate_matrix, after, plan)
            comparison = self.matrix_inventory(live, after, source_plan=plan, probe_plan=plan)
            comparison['validation_issues'] = validation_errors
            self.record_matrix_inventory(comparison, plan['phase'] + '/after-comparison.json',
                                         plan['phase'], 'after')
            _raise_unsupported(validation_errors + comparison['matrix_issues'])
        layers = {k: {'requested': plan['properties'][k], 'show': live[k],
                       'request_matches_show': _matrix_value(k, plan['properties'][k]) == _matrix_value(k, live[k])}
                  for k in MATRIX_KNOBS}
        layers['NoNewPrivileges'].update(proc_entry=records[0]['status']['NoNewPrivs'], proc_after_exec=records[1]['status']['NoNewPrivs'],
                                         show_matches_proc=_matrix_value('NoNewPrivileges', live['NoNewPrivileges']) == ('yes' if state['entry']['NoNewPrivs'] else 'no'),
                                         forced_or_inherited=plan['properties']['NoNewPrivileges'] == 'no' and
                                         (_matrix_value('NoNewPrivileges', live['NoNewPrivileges']) != 'no' or state['entry']['NoNewPrivs'] != 0))
        result = dict(phase=plan['phase'], enabled=plan['enabled'], profile=live, state=state, layers=layers,
                      requested_properties=plan['properties'], unexpected_requested_values=[k for k in MATRIX_KNOBS if not layers[k]['request_matches_show']],
                      actual_NNP_off=_matrix_value('NoNewPrivileges', live['NoNewPrivileges']) == 'no' and state['entry']['NoNewPrivs'] == 0)
        self.record(plan['phase'] + '/result.json', result)
        if not self.cleanup_one(plan['unit']):
            self.cleanup_confirmed = False
            raise Unsupported('cleanup-unconfirmed')
        self.intents.remove(plan['unit'])
        row.update(status='recorded', missing=state['missing'], layers=layers, actual_NNP_off=result['actual_NNP_off'])
        return result

    def matrix_edge(self, a, b, repeat=False):
        delta = sorted(set(a['enabled']) ^ set(b['enabled']))
        if len(delta) != (0 if repeat else 1):
            raise Unsupported('matrix-request-delta')
        inventory = self.matrix_inventory(a['profile'], b['profile'], variable=not repeat,
                                          source_plan=self.matrix_plans.get(a['phase']),
                                          probe_plan=self.matrix_plans.get(b['phase']))
        inventory.update(request_delta=delta, reference=a['phase'], observation=b['phase'],
                         NNP_layers={'reference': a['layers']['NoNewPrivileges'], 'observation': b['layers']['NoNewPrivileges']},
                         actual_NNP_off={'reference': a['actual_NNP_off'], 'observation': b['actual_NNP_off']})
        self.record_matrix_inventory(inventory, b['phase'] + '/against-' + a['phase'] + '.json',
                                     b['phase'], 'repeat' if repeat else 'edge')
        _raise_unsupported(inventory['matrix_issues'])
        if repeat and a['state'] != b['state']:
            raise Unsupported('matrix-repeat-unstable')

    def run_matrix(self):
        self.matrix_report = {'status': 'unavailable', 'attempt_limit': 28, 'attempts': [],
                              'knobs': list(MATRIX_KNOBS), 'minimum_tested_requested_profile': None,
                              'exploration_limit': 23, 'confirmation_limit': 2, 'supplement_limit': 1,
                              'limits': ['requested-profile comparisons, not a global minimum or root cause',
                                         'only singles and NNP-plus-one pairs; higher orders unresolved',
                                         'entry is after Python initialization; no HAProxy, tracing or listeners',
                                         'requested NNP=no does not establish effective/proc NNP=0',
                                         'no production change or production fix is established']}
        self.matrix_mount_manager()  # No manager query while a helper is held.
        self.matrix_python_initial = executable_metadata('/usr/bin/python3')
        self.record('matrix.python.initial.json', self.matrix_python_initial)
        cap = self.matrix_python_initial.get('filecap', {})
        if (not self.matrix_python_initial.get('available') or not cap.get('available') or cap.get('present') is not False):
            raise Unsupported('matrix-python-filecap-unavailable-or-present')
        minimal, production = self.matrix_attempt(()), self.matrix_attempt(MATRIX_KNOBS)
        if minimal['state']['missing']:
            repeated = self.matrix_attempt(())
            self.matrix_edge(minimal, repeated, repeat=True)
            self.matrix_report.update(status='confirmed-zero-optional-settings', minimum_tested_requested_profile=[])
            return 0
        if not production['state']['missing']:
            self.matrix_report['status'] = 'not-reproduced-inconclusive'
            return 2
        nnp, singles, candidate, reference = MATRIX_KNOBS[0], {}, None, None
        for knob in MATRIX_KNOBS:  # NNP first, then the ten other single requests.
            observed = self.matrix_attempt((knob,))
            self.matrix_edge(minimal, observed)
            singles[knob] = observed
            if observed['state']['missing']:
                reference, candidate = minimal, observed
                break
        if candidate is None:
            for knob in MATRIX_KNOBS[1:]:  # No powerset, recursion, or other pairs.
                observed = self.matrix_attempt((nnp, knob))
                self.matrix_edge(singles[knob], observed)
                self.matrix_edge(singles[nnp], observed)
                if observed['state']['missing']:
                    reference, candidate = singles[knob], observed
                    break
        if candidate is None:
            self.matrix_report['status'] = 'higher-order-unresolved'
            return 2
        for original in (reference, candidate):
            repeated = self.matrix_attempt(original['enabled'])
            self.matrix_edge(original, repeated, repeat=True)
        self.matrix_report.update(minimum_tested_requested_profile=candidate['enabled'],
                                  reference=reference['phase'], candidate=candidate['phase'],
                                  status='interaction-incomplete')
        if len(candidate['enabled']) == 1:
            enabled = (set(MATRIX_KNOBS) - {nnp}) if candidate['enabled'] == [nnp] else set(candidate['enabled']) | {nnp}
            supplement = self.matrix_attempt(enabled)
            self.matrix_edge(production if candidate['enabled'] == [nnp] else candidate, supplement)
            self.matrix_report['interaction'] = {'phase': supplement['phase'], 'missing': supplement['state']['missing'],
                                                'actual_NNP_off': supplement['actual_NNP_off'], 'production_fix_claimed': False}
        else:
            self.matrix_report['interaction'] = {'healthy_components': [singles[k]['phase'] for k in candidate['enabled']]}
        self.matrix_report['status'] = 'confirmed-tested-requested-profile'
        return 0

    def boundary_report(self):
        rows = list(self.boundaries)
        for plan in self.boundary_plans:
            try:
                records = self.read_boundaries(plan)
            except (OSError, ValueError):
                records = []
            self.record(plan['phase'] + '/boundaries.json', records)
            rows.extend({'stage': plan['phase'] + ':' + r['stage'], 'available': True, 'status': r['status']} for r in records)
            rows.extend(r for r in self.process_boundaries if r['stage'].startswith(plan['phase'] + ':'))
        summary = []
        for row in rows:
            status = row.get('status')
            summary.append({'stage': row['stage'], 'available': bool(status),
                            'SETUID': {k: bool(status[k] & 0x80) for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')} if status else None})
        # Controller is a D-Bus client, not the service's credential parent.
        # Non-root workers normally lose these capabilities after their UID drop.
        for observation, row in zip(summary, rows):
            observation['scope'] = ('independent-context' if row['stage'] in ('controller', 'manager') else
                                    'unit-root' if row.get('status', {}).get('Uid', (None, None))[1] == 0 else
                                    'unit-nonroot' if row.get('status') else 'unavailable')
            if 'sample' in row:
                observation['sample'] = row['sample']
        root_units = [r for r in summary if r['scope'] == 'unit-root']
        first = next((r['stage'] for r in root_units if r['SETUID'] and
                      not (r['SETUID']['CapEff'] and r['SETUID']['CapPrm'])),
                     'not-observed' if root_units else 'unavailable')
        views = []
        for phase in ('cap-gated', 'cap-direct'):
            views.append([{k: r['status'][k] for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Uid', 'Gid', 'Groups')}
                          for r in self.control_records.get(phase, []) if r['stage'] in ('control-entry', 'after-exec')])
        different = views[0] != views[1] if all(len(v) == 2 for v in views) else None
        self.record('boundaries.report.json', {'observations': summary, 'first_observed_missing_SETUID_EP': first,
                    'headline_scope': 'root unit tasks only; independent contexts and non-root workers excluded',
                    'gated_direct_differ': different, 'ordering': 'observation stages, not a causal inheritance chain',
                    'limits': ['helper entry is after Python initialization', 'manager and controller are independent contexts',
                               'client env -i/FIXED_ENV is not the unit environment', 'bounding does not imply permitted/effective',
                               'missing masks alone do not establish root cause']})
        return first

    def cleanup(self):
        self.release_reservations()
        for unit in tuple(reversed(self.intents)):
            if self.cleanup_one(unit):
                self.intents.remove(unit)
            else:
                self.cleanup_confirmed = False
        return self.cleanup_confirmed and not self.intents


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in (['--run'], ['--cap-boundaries'], ['--cap-matrix'], ['--nnp-ab'],
                    ['--nnp-ab', '--reload-usr2'],
                    ['--nnp-ab', '--reload-usr2', '--compare-cap-kill']):
        print('Usage: bash tools/diagnose-haproxy.sh --help | --run | --cap-boundaries | --cap-matrix | --nnp-ab [--reload-usr2 [--compare-cap-kill]]', file=sys.stderr)
        return 64
    cap_boundaries, cap_matrix = args == ['--cap-boundaries'], args == ['--cap-matrix']
    compare_cap_kill = args == ['--nnp-ab', '--reload-usr2', '--compare-cap-kill']
    reload_usr2 = args == ['--nnp-ab', '--reload-usr2'] or compare_cap_kill
    nnp_ab = args == ['--nnp-ab'] or reload_usr2
    outcomes = {}
    controller, status, exitcode = Controller(), 'unavailable', 2
    interrupted = False
    old_handlers = {}

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, interrupt)
        if nnp_ab:
            exitcode = (controller.run_nnp_ab(reload_usr2=True, compare_cap_kill=True) if compare_cap_kill else
                        controller.run_nnp_ab(reload_usr2=True) if reload_usr2 else controller.run_nnp_ab())
        elif cap_matrix:
            controller.prepare(cap_boundaries=True)
            exitcode = controller.run_matrix()
        elif cap_boundaries:
            controller.prepare(cap_boundaries=True)
            outcomes = controller.run_controls()
            exitcode = 0 if all(v == 'recorded' for v in outcomes.values()) else 2
        else:
            controller.prepare()
            status, _ = controller.run_phase('plain')
            print('plain startup: ' + status)
        if not nnp_ab and status == 'observed-running':
            exitcode = 0
        elif not nnp_ab and status == 'failed':
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
        print('nnp-ab: refused' if nnp_ab else 'matrix: refused' if cap_matrix else 'unsupported: ' + str(exc))
        if nnp_ab:
            controller.ab_report['issues'] = list(exc.labels)
            if controller.ab_report['status'] != 'NOTSTARTED':
                controller.ab_report['status'] = 'refused'
        if cap_matrix:
            controller.matrix_report = getattr(controller, 'matrix_report', {'status': 'inconclusive', 'attempts': []})
            controller.matrix_report['issues'] = list(exc.labels)
            if controller.matrix_report['status'] == 'unavailable':
                controller.matrix_report['status'] = 'inconclusive'
    except KeyboardInterrupt:
        interrupted = True
        print('interrupted: cleanup requested')
        exitcode = 130
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError):
        if nnp_ab:
            controller.ab_report['issues'] = ['inspection-or-runtime-evidence-unavailable']
        print('nnp-ab: evidence-unavailable' if nnp_ab else 'matrix: evidence-unavailable' if cap_matrix else
              'unavailable: inspection or runtime evidence incomplete')
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
            print('cleanup: unconfirmed; inspect private evidence for requested RuntimeMaxSec')
            if not interrupted:
                exitcode = 2
        if nnp_ab:
            keys_clean = controller.cleanup_ab_keys(clean)
            if not clean or not keys_clean:
                if not interrupted:
                    exitcode = 2
                print('nnp-ab: private key cleanup unconfirmed; keys may remain in private evidence')
            report = controller.ab_report
            report.update(cleanup_confirmed=clean, tls_cleanup_confirmed=keys_clean,
                          interrupted=interrupted, exitcode=exitcode)
            if reload_usr2:
                report['reload'] = controller.reload_report
                report['cleanup'] = {'units_confirmed': clean, 'tls_confirmed': keys_clean,
                                     'status': 'confirmed' if clean and keys_clean else 'unconfirmed'}
                comparison_ok = (not compare_cap_kill or
                    report.get('cap_kill_comparison', {}).get('proven') is True)
                if (controller.reload_report['status'] != 'passed' or not comparison_ok) and not interrupted:
                    exitcode = report['exitcode'] = 2
            if not clean or not keys_clean:
                report.update(status='cleanup-unconfirmed', startup_candidate=False,
                              diagnostic_finding_completed=False, confirmed_startup_difference=False)
                if compare_cap_kill:
                    report['cap_kill_comparison']['proven'] = False
                if reload_usr2:
                    report['cleanup']['status'] = 'unconfirmed'
            elif interrupted and report['status'] != 'NOTSTARTED':
                report['status'] = 'interrupted'
            if compare_cap_kill and interrupted:
                report['cap_kill_comparison']['proven'] = False
                report['diagnostic_finding_completed'] = False
            if controller.directory is not None:
                try:
                    controller.record('nnp-ab.report.json', report)
                except (OSError, ValueError):
                    exitcode = 130 if interrupted else 2
                    print('nnp-ab: evidence-unavailable')
            if reload_usr2:
                print('nnp-ab: ' + report['status'] + '; production NOT changed; pidfd USR2: ' +
                      controller.reload_report['status'] + '; unit wrapper untested')
            else:
                print('nnp-ab: ' + report['status'] + '; startup-only, production NOT changed; reload untested')
        if controller.directory is not None:
            if cap_matrix:
                try:
                    report = getattr(controller, 'matrix_report', {'status': 'unavailable', 'attempts': []})
                    report.update(cleanup_confirmed=clean, interrupted=interrupted, exitcode=exitcode,
                                  attempt_count=len(report['attempts']))
                    if interrupted or not clean:
                        report['status'] = 'interrupted' if interrupted else 'cleanup-unconfirmed'
                    controller.record('matrix.report.json', report)
                    print('matrix: ' + report['status'])
                except (OSError, ValueError):
                    if not interrupted:
                        exitcode = 2
                    print('matrix: evidence-unavailable')
            elif not nnp_ab:
                try:
                    first = controller.boundary_report()
                except (OSError, ValueError):
                    first, exitcode = 'unavailable', 2
                prefix = ('control gated/direct: ' + outcomes.get('cap-gated', 'unavailable') + '/' +
                          outcomes.get('cap-direct', 'unavailable') + '; ') if cap_boundaries else ''
                print(prefix + 'first root-unit observation missing SETUID (E/P): ' + first + ' (not a root cause)')
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
