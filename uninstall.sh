#!/bin/bash
# Conservative Nathaya removal over the native Alrescha backend. Data is kept.
# Ownership ledger: SHA256<TAB>ABSOLUTE_PATH, one regular file per line.
# Never use an upstream uninstaller or infer ownership from a filename alone.
set +x
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 077
[[ $EUID -eq 0 ]] || { echo 'Root privileges required.' >&2; exit 1; }
[[ $# -eq 0 ]] || { echo 'No unattended/force/data-purge options are supported.' >&2; exit 1; }
[[ -t 0 ]] || { echo 'Interactive typed confirmation is required.' >&2; exit 1; }
[[ -r /etc/os-release && -d /run/systemd/system && ! -e /system/build.prop ]] || {
    echo 'Requires a systemd Ubuntu 24.04 host, not Android.' >&2; exit 1;
}
os_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
[[ $os_id == ubuntu && $os_version == 24.04 ]] || { echo 'Only Ubuntu 24.04 is supported.' >&2; exit 1; }
cat <<'NOTICE'
NATHAYA TUNNEL — conservative uninstall (KEEP DATA)
Only closed-list code, custom units, cron files and proxy configs recorded in
/var/lib/nathaya-tunnel/owned-files.tsv with matching SHA256 will be removed.
Any unsafe/missing/changed removal target stops the operation for manual review.
Unrecorded or out-of-policy files are NEVER removed.

Accounts, native databases/limits, OpenVPN/CA, TLS/private keys, backups, logs,
notification credentials and /var/lib/nathaya-tunnel/originals are preserved.
No user/package removal, SSH restart, UFW/Netplan/DNS/IPv6 changes, sysctl reset
or global firewall cleanup. Packages and their services remain installed.
Recorded custom VPN units are stopped/disabled. If recorded proxy configs are
removed, their nginx/HAProxy services are stopped, not restarted or restored.
Only a recorded, hash-matching root-trusted openvpn-forward.sh may run 'down'
to remove the installer's exact nathaya-openvpn rules; other rules are untouched.

Use an exclusive maintenance window: no setup/update/account/firewall writers.
The operation is not transactional; a failure can leave services stopped.
NOTICE
read -r -p 'Type UNINSTALL NATHAYA KEEP DATA to continue: ' confirmation
[[ $confirmation == 'UNINSTALL NATHAYA KEEP DATA' ]] || { echo 'Cancelled; nothing changed.'; exit 0; }
exec /usr/bin/python3 - <<'PY'
import fcntl
import hashlib
import os
import re
import stat
import subprocess
import sys

STATE = '/var/lib/nathaya-tunnel'
LEDGER = STATE + '/owned-files.tsv'
FORWARD = '/usr/local/lib/nathaya/openvpn-forward.sh'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LC_ALL': 'C'}
# Pinned destinations from the closed Nathaya code manifest, NOT an arbitrary
# runtime manifest or a recursive /opt deletion. New destinations need review.
CODE = frozenset((
    "/usr/bin/addshadowsocks",
    "/usr/bin/addssh",
    "/usr/bin/addtrojan",
    "/usr/bin/addvless",
    "/usr/bin/addvmess",
    "/usr/bin/autokill",
    "/usr/bin/backuprestore",
    "/usr/bin/backuprestore.js",
    "/usr/bin/checkshadowsocks",
    "/usr/bin/checkssh",
    "/usr/bin/checktrojan",
    "/usr/bin/checkvless",
    "/usr/bin/checkvmess",
    "/usr/bin/dellshadowsocks",
    "/usr/bin/dellssh",
    "/usr/bin/delltrojan",
    "/usr/bin/dellvless",
    "/usr/bin/dellvmess",
    "/usr/bin/exp",
    "/usr/bin/features",
    "/usr/bin/limitip",
    "/usr/bin/limitipssh",
    "/usr/bin/limitssh",
    "/usr/bin/logclear",
    "/usr/bin/menu",
    "/usr/bin/menushadowsocks",
    "/usr/bin/menussh",
    "/usr/bin/menutrojan",
    "/usr/bin/menuvless",
    "/usr/bin/menuvmess",
    "/usr/bin/quota",
    "/usr/bin/renewssh",
    "/usr/bin/renewtrojan",
    "/usr/bin/renewvmess",
    "/usr/bin/renewvless",
    "/usr/bin/trialtrojan",
    "/usr/bin/trialvmess",
    "/usr/bin/trialvless",
    "/usr/bin/trialssh",
    "/usr/bin/trialshadowsocks",
    "/usr/bin/exp-warning",
    "/usr/bin/trial",
    "/usr/bin/renewshadowsocks",
    "/usr/local/bin/add-vmess",
    "/usr/local/bin/add-vless",
    "/usr/local/bin/add-trojan",
    "/usr/local/bin/add-shadowsocks",
    "/usr/local/bin/add-ssh",
    "/usr/local/bin/del-vmess",
    "/usr/local/bin/del-trojan",
    "/usr/local/bin/del-vless",
    "/usr/local/bin/del-shadowsocks",
    "/usr/local/bin/del-ssh",
    "/usr/local/bin/check-vless",
    "/usr/local/bin/check-trojan",
    "/usr/local/bin/check-shadowsocks",
    "/usr/local/bin/check-ssh",
    "/usr/local/bin/check-vmess",
    "/usr/local/bin/renew-vmess",
    "/usr/local/bin/renew-ssh",
    "/usr/local/bin/renew-vless",
    "/usr/local/bin/renew-trojan",
    "/usr/local/bin/renew-shadowsocks",
    "/opt/nathaya/modules/common/account-presentation.sh",
    "/opt/nathaya/modules/common/functions.sh",
    "/opt/nathaya/modules/common/runtime-ui.sh",
    "/opt/nathaya/modules/common/telegram.sh",
    "/opt/nathaya/modules/common/ui.sh",
    "/opt/nathaya/modules/dashboard/dashboard.sh",
    "/opt/nathaya/modules/menu/domain.sh",
    "/opt/nathaya/modules/menu/main.sh",
    "/opt/nathaya/modules/menu/protocol.sh",
    "/opt/nathaya/modules/menu/set_domain.sh",
    "/opt/nathaya/modules/menu/shadowsocks-operations.sh",
    "/opt/nathaya/modules/menu/ssh-operations.sh",
    "/opt/nathaya/modules/menu/ssh.sh",
    "/opt/nathaya/modules/menu/trojan-operations.sh",
    "/opt/nathaya/modules/menu/vless-operations.sh",
    "/opt/nathaya/modules/menu/vmess-operations.sh",
    "/usr/bin/nathaya-update",
    "/opt/nathaya/lib/install-runtime.sh",
    "/opt/nathaya/install-manifest.tsv",
    "/opt/nathaya/LICENSE",
    '/usr/bin/ws.py', '/usr/bin/udp', '/usr/bin/badvpn', '/usr/bin/gotop',
    '/usr/local/bin/xray', FORWARD, '/usr/bin/nathaya-uninstall',
    '/usr/local/share/xray/geoip.dat', '/usr/local/share/xray/geosite.dat',
    '/usr/local/sbin/nathaya-domain', '/usr/local/sbin/nathaya-acme-pre',
    '/usr/local/sbin/nathaya-acme-post', '/usr/local/sbin/nathaya-acme-deploy',
))
UNIT_NAMES = (
    'vmess@config.service', 'vless@config.service', 'trojan@config.service',
    'shadowsocks@config.service', 'ws.service', 'udp.service',
    'limitip.service', 'limitquota.service', 'badvpn.service',
    'badvpn@.service', 'badvpn@7100.service', 'badvpn@7200.service',
    'badvpn@7300.service', 'nathaya-openvpn-tcp.service',
    'nathaya-openvpn-udp.service', 'nathaya-openvpn-forward.service',
    'nathaya-ssh.service', 'nathaya-dropbear.service',
)
UNITS = frozenset('/etc/systemd/system/' + name for name in UNIT_NAMES)
CRON = frozenset('/etc/cron.d/' + name for name in
                 ('xp_all', 'exp_warning', 'logclear', 'daily_reboot', 'backup', 'autokill'))
PROXIES = {'/etc/haproxy/haproxy.cfg': 'haproxy.service',
           '/etc/nginx/nginx.conf': 'nginx.service',
           '/etc/nginx/conf.d/xray.conf': 'nginx.service'}
OTHER = frozenset((
    '/etc/systemd/system/xray@.service.d/10-donot_touch_single_conf.conf',
    '/etc/ssh/sshd_config.nathaya',
    '/etc/sysctl.d/90-nathaya-openvpn.conf',
))
ALLOWED = CODE | UNITS | CRON | frozenset(PROXIES) | OTHER
NOFOLLOW = os.O_NOFOLLOW
changed = False
locks = []


class Review(Exception):
    pass


def trusted_directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Review('A required directory is not root-owned/trusted.')


def open_parent(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        trusted_directory(os.fstat(fd))
        for part in path.split('/')[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            trusted_directory(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def open_regular(path):
    parent = open_parent(path)
    try:
        fd = os.open(path.rsplit('/', 1)[1], os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or info.st_mode & 0o022):
        os.close(fd)
        raise Review('A recorded file or control file is not a trusted root regular file.')
    return fd


def checked(path, expected=None, private=False):
    fd = open_regular(path)
    try:
        before = os.fstat(fd)
        if private and before.st_mode & 0o077:
            raise Review('Ownership state must be private (root:root, 0600).')
        if before.st_size > 256 * 1024 * 1024:
            raise Review('Recorded file exceeds the review limit.')
        digest = hashlib.sha256()
        with os.fdopen(os.dup(fd), 'rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        if fingerprint(before) != fingerprint(os.fstat(fd)):
            raise Review('A recorded file changed during verification.')
        value = digest.hexdigest()
        if expected is not None and value != expected:
            # Do not print hashes, contents or private values.
            raise Review('Owned file hash mismatch: ' + path)
        return value, fingerprint(before)
    finally:
        os.close(fd)


def acquire_lock(path):
    parent = open_parent(path)
    try:
        fd = os.open(path.rsplit('/', 1)[1], os.O_RDWR | os.O_CREAT | NOFOLLOW,
                     0o600, dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022):
        os.close(fd)
        raise Review('Unsafe maintenance lock.')
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise Review('Another runtime/maintenance operation holds the lock.')
    locks.append(fd)


def command(args):
    try:
        result = subprocess.run(args, env=ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Review('A required service/network operation failed; inspect locally.')
    if result.returncode:
        raise Review('A required service/network operation failed; inspect locally.')
    return result.stdout.decode('utf-8', errors='strict').strip()


def property_of(unit, field):
    return command([SYSTEMCTL, 'show', '--property=' + field, '--value', unit])


def check_unit(unit, path):
    if property_of(unit, 'FragmentPath') != path or property_of(unit, 'DropInPaths'):
        raise Review('Unit has an unrecorded replacement/drop-in: ' + unit)


def main():
    global changed
    # Never create a ledger or guess a legacy install's ownership.
    checked(LEDGER, private=True)
    acquire_lock(STATE + '/uninstall.lock')
    if os.path.lexists('/opt/nathaya'):
        acquire_lock('/opt/nathaya/.runtime.lock')
    # Serialize optional cron edits with the complete removal plan.
    acquire_lock(LEDGER + '.lock')
    ledger_hash, ledger_info = checked(LEDGER, private=True)
    fd = open_regular(LEDGER)
    with os.fdopen(fd, 'rb') as source:
        raw = source.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise Review('Ownership ledger exceeds the review limit.')
    if hashlib.sha256(raw).hexdigest() != ledger_hash:
        raise Review('Ownership ledger changed during inspection.')
    records, skipped = {}, 0
    for line in raw.decode('utf-8', errors='strict').splitlines():
        if not line:
            continue
        fields = line.split('\t')
        if len(fields) != 2 or not re.fullmatch(r'[0-9A-Fa-f]{64}', fields[0]):
            raise Review('Expected ledger format: SHA256<TAB>ABSOLUTE_PATH.')
        digest, path = fields
        if (not path.startswith('/') or len(path) > 512
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
                or '\\' in path or any(p in ('', '.', '..') for p in path.split('/')[1:])
                or path in records):
            raise Review('Unsafe or duplicate ownership ledger path.')
        records[path] = digest.lower()
        if len(records) > 20000:
            raise Review('Too many ownership records.')
    plan, initial = {}, {}
    for path, digest in records.items():
        if path not in ALLOWED:
            # Data, SSH, host networking, package files and unknown targets stay.
            # Their registration does not authorize deleting them.
            skipped += 1
            continue
        _, initial[path] = checked(path, digest)
        plan[path] = digest
    if not plan:
        raise Review('No recorded, permitted removal targets. No legacy-name fallback.')
    checked(SYSTEMCTL)
    services = {}
    for path in sorted(plan.keys() & UNITS):
        name = path.rsplit('/', 1)[1]
        names = ('badvpn@7100.service', 'badvpn@7200.service', 'badvpn@7300.service') if name == 'badvpn@.service' else (name,)
        for unit in names:
            # An explicit recorded instance wins over the recorded template.
            expected = '/etc/systemd/system/' + unit
            if expected not in plan:
                expected = path
            check_unit(unit, expected)
            services[unit] = expected
    proxy_services = set(PROXIES[path] for path in plan if path in PROXIES)
    for unit in sorted(proxy_services):
        fragment = property_of(unit, 'FragmentPath')
        if fragment not in ('/usr/lib/systemd/system/' + unit, '/lib/systemd/system/' + unit):
            raise Review('Shared proxy unit is not the packaged unit: ' + unit)
        checked(os.path.realpath(fragment))
        if property_of(unit, 'DropInPaths'):
            raise Review('Shared proxy has administrator drop-ins: ' + unit)
    print('Verified removal targets:', len(plan), '; out-of-policy records retained:', skipped)
    print('No data purge or automatic restoration of shared proxy originals.')

    def recheck():
        if checked(LEDGER, ledger_hash, private=True)[1] != ledger_info:
            raise Review('Ownership ledger changed; rebuild the removal plan manually.')
        for path, digest in plan.items():
            if checked(path, digest)[1] != initial[path]:
                raise Review('Owned target changed; review and re-record only if appropriate: ' + path)

    # Complete preflight before the first service stop/disable or file removal.
    recheck()
    for unit in sorted(services):
        check_unit(unit, services[unit])
        changed = True
        command([SYSTEMCTL, 'stop', unit])
        command([SYSTEMCTL, 'disable', unit])
        if property_of(unit, 'ActiveState') not in ('inactive', 'failed'):
            raise Review('Owned VPN unit did not stop: ' + unit)
    for unit in sorted(proxy_services):
        changed = True
        command([SYSTEMCTL, 'stop', unit])
        if property_of(unit, 'ActiveState') not in ('inactive', 'failed'):
            raise Review('Shared proxy unit did not stop: ' + unit)
    recheck()
    if FORWARD in plan:
        # Typed confirmation above authorizes only this recorded helper's down
        # operation. No generic firewall command or sysctl restoration here.
        checked('/usr/bin/bash')
        changed = True
        command(['/usr/bin/bash', FORWARD, 'down'])
    else:
        print('No trusted recorded forwarding helper: network rules left for manual review.')
    recheck()
    removed = []
    # Remove scheduled entrypoints first; do not stop the host's cron service.
    for path in sorted(plan, key=lambda p: (p not in CRON, p)):
        if checked(LEDGER, ledger_hash, private=True)[1] != ledger_info:
            raise Review('Ownership ledger changed during removal.')
        if checked(path, plan[path])[1] != initial[path]:
            raise Review('Owned target changed during removal: ' + path)
        parent = open_parent(path)
        try:
            name = path.rsplit('/', 1)[1]
            if fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)) != initial[path]:
                raise Review('Owned target was replaced during removal: ' + path)
            changed = True
            os.unlink(name, dir_fd=parent)
            removed.append(path)
        finally:
            os.close(parent)
    command([SYSTEMCTL, 'daemon-reload'])
    # Only exact runtime-code parents, and only if empty. No recursive removal.
    directories = set()
    for path in removed:
        if path.startswith('/opt/nathaya/modules/') or path.startswith('/opt/nathaya/lib/'):
            parent = os.path.dirname(path)
            while parent != '/opt/nathaya':
                directories.add(parent)
                parent = os.path.dirname(parent)
        elif path.startswith('/usr/local/lib/nathaya/'):
            directories.add('/usr/local/lib/nathaya')
    for path in sorted(directories, key=lambda p: (-p.count('/'), p)):
        parent = open_parent(path)
        try:
            os.rmdir(path.rsplit('/', 1)[1], dir_fd=parent)
        except OSError:
            pass  # Nonempty code directories and all data remain intact.
        finally:
            os.close(parent)
    print('Removed only', len(removed), 'verified owned files; recorded VPN units stopped/disabled.')
    print('KEPT: accounts, DBs/limits, OpenVPN/CA, TLS keys/certificates, credentials, backups and logs.')
    print('KEPT: packages, SSH, host networking, ownership ledger and original-config backups.')
    print('Not all installer effects/data have been removed. No reboot or SSH restart was performed.')
    if proxy_services:
        print('nginx/HAProxy remain stopped where owned proxy configuration was removed.')
        print('MANUAL: inspect /var/lib/nathaya-tunnel/originals and its index; restore the correct')
        print('pre-install shared proxy config if required, validate it, then start only that proxy.')
        print('No originals/index schema was assumed; originals were neither moved nor overwritten.')
    print('The retained ledger is historical after removal; review missing records before any retry.')


try:
    os.umask(0o077)
    main()
except Exception as error:
    print('STOP — manual review required.', file=sys.stderr)
    if isinstance(error, Review):
        print(str(error), file=sys.stderr)
    else:
        print('Missing/unsafe file, permission, encoding or system operation failure; inspect locally.', file=sys.stderr)
    if changed:
        print('Some services/files may already have changed. Do not blindly retry; data/originals remain.', file=sys.stderr)
    else:
        print('No services stopped or owned files removed.', file=sys.stderr)
    sys.exit(1)
PY
