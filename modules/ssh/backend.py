#!/usr/bin/env python3
"""Root-only account store and isolated Dropbear supervisor."""

import argparse
import asyncio
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import sqlite3
import stat
import string
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STATE = Path('/var/lib/nathaya-ssh')
RUNTIME = Path('/run/nathaya-ssh')
PORT_FILE = Path('/etc/nathaya-tunnel/ssh-ports.conf')
DROPBEAR = '/usr/sbin/dropbear'
KEY_TOOL = '/usr/bin/dropbearkey'
BWRAP = '/usr/bin/bwrap'
ALPHABET = string.ascii_lowercase + string.digits
NAME = re.compile(r'(?:[a-z0-9]{4,32}|trial-[a-z0-9]{12})\Z')
AUTH = re.compile(rb"^Password auth succeeded for '([a-z0-9-]{4,32})' from [0-9a-fA-F:.%\[\]-]+(?::[0-9]+)?$")
SCHEMA = '''CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY, kind TEXT NOT NULL, created INTEGER NOT NULL,
    expires INTEGER NOT NULL, ip_limit INTEGER NOT NULL, sessions INTEGER NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0, auto_until INTEGER NOT NULL DEFAULT 0,
    verifier TEXT NOT NULL, sealed BLOB
)'''
PUBLIC = 'username, kind, created, expires, ip_limit, sessions, locked, auto_until'


class AccountError(Exception):
    pass


def secret_path(path, is_dir=False):
    info = path.lstat()
    kind = stat.S_ISDIR if is_dir else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise AccountError('Izin atau kepemilikan data SSH tidak aman.')


@contextmanager
def database(init=False):
    if init:
        STATE.mkdir(mode=0o700, exist_ok=True)
    secret_path(STATE, True)
    path = STATE / 'accounts.sqlite3'
    if path.exists() or path.is_symlink() or not init:
        secret_path(path)
    db = sqlite3.connect(path, timeout=8)
    db.row_factory = sqlite3.Row
    try:
        if init:
            db.execute(SCHEMA)
        with db:
            yield db
    finally:
        db.close()


def cipher():
    path = STATE / 'password.key'
    secret_path(path)
    key = path.read_bytes()
    if len(key) != 32:
        raise AccountError('Kunci password tidak valid; pulihkan dari backup.')
    return AESGCM(key)


def initialize():
    with database(init=True) as db:
        db.execute('BEGIN IMMEDIATE')
        keyfile = STATE / 'password.key'
        if not keyfile.exists() and not keyfile.is_symlink():
            if db.execute('SELECT 1 FROM accounts WHERE sealed IS NOT NULL LIMIT 1').fetchone():
                raise AccountError('Kunci password hilang; pulihkan dari backup.')
            with keyfile.open('xb') as stream:
                stream.write(AESGCM.generate_key(bit_length=256))
                stream.flush()
                os.fsync(stream.fileno())
        cipher()
        host = STATE / 'dropbear_ed25519_host_key'
        if not host.exists() and not host.is_symlink():
            with tempfile.TemporaryDirectory(dir=STATE) as temp:
                candidate = Path(temp) / 'hostkey'
                subprocess.run([KEY_TOOL, '-t', 'ed25519', '-f', str(candidate)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                candidate.chmod(0o600)
                candidate.replace(host)
        secret_path(host)


def system_name_used(username):
    try:
        pwd.getpwnam(username)
    except KeyError:
        return False
    return True


def name_free(db, username):
    return not system_name_used(username) and not db.execute(
        'SELECT 1 FROM accounts WHERE username=?', (username,)).fetchone()


def generated(size):
    return ''.join(secrets.choice(ALPHABET) for _ in range(size))


def create(kind, username, password, ip_limit, duration, *, trial_unit='h'):
    if not 0 <= ip_limit <= 99:
        raise AccountError('Limit IP harus 0–99.')
    units = {'h': (720, 3600), 'm': (43200, 60)}
    if kind == 'member':
        maximum, seconds = 3650, 86400
    elif kind == 'trial' and trial_unit in units:
        maximum, seconds = units[trial_unit]
    else:
        raise AccountError('Jenis akun atau satuan masa aktif tidak valid.')
    if not 1 <= duration <= maximum:
        raise AccountError('Masa aktif di luar rentang.')
    with database() as db:
        db.execute('BEGIN IMMEDIATE')
        if kind == 'trial':
            for _ in range(32):
                username = 'trial-' + generated(12)
                if name_free(db, username):
                    break
            else:
                raise AccountError('Tidak dapat membuat username Trial yang unik.')
            password = generated(16)
        elif not re.fullmatch(r'[a-z0-9]{4,32}', username) or not re.fullmatch(r'[a-z0-9]{1,64}', password):
            raise AccountError('Username atau password tidak valid.')
        elif not name_free(db, username):
            raise AccountError('Username sudah dipakai; pilih nama lain.')

        # Hanya lewat stdin, bukan argv ataupun lingkungan proses.
        verifier = subprocess.run(['/usr/bin/openssl', 'passwd', '-6', '-stdin'],
                                  input=password + '\n', text=True, capture_output=True, check=True).stdout.strip()
        if not re.fullmatch(r'\$6\$[./A-Za-z0-9$]+', verifier):
            raise AccountError('Tidak dapat membuat verifier password.')
        nonce = os.urandom(12)
        sealed = nonce + cipher().encrypt(nonce, password.encode('ascii'), username.encode('ascii'))
        created = int(time.time())
        expires = created + duration * seconds
        db.execute('INSERT INTO accounts VALUES (?, ?, ?, ?, ?, 2, 0, 0, ?, ?)',
                   (username, kind, created, expires, ip_limit, verifier, sealed))
    return username


def account_row(db, username, fields=PUBLIC):
    row = db.execute(f'SELECT {fields} FROM accounts WHERE username=?', (username,)).fetchone()
    if row is None:
        raise AccountError('Akun tidak ditemukan.')
    return row


class StaleAccount(AccountError):
    pass


class ReplacedAccount(AccountError):
    pass


def account_identity(row):
    # The encrypted password contains a random nonce. No schema change is needed.
    # Legacy rows without an envelope fall back to their creation time and salted verifier.
    seed = [row['username'], row['created'], row['verifier']]
    if row['sealed'] is not None:
        seed.append(row['sealed'].hex())
    return hashlib.sha256(json.dumps(['nathaya-identity-v1', *seed]).encode()).hexdigest()


def status_for(expires, locked, auto_until, now):
    if expires <= now:
        return 'Expired'
    return 'Locked' if locked or auto_until > now else 'Aktif'


def action_snapshot(db, username, identity, days=None, *, expired_only=False):
    if days is not None and not 1 <= days <= 3650:
        raise AccountError('Tambahan masa aktif harus 1–3650 hari.')
    row = db.execute('SELECT * FROM accounts WHERE username=?', (username,)).fetchone()
    if row is None or not secrets.compare_digest(account_identity(row), identity):
        raise ReplacedAccount('Akun hilang atau diganti. Pilih ulang dari daftar.')
    now = int(time.time())
    status = status_for(row['expires'], row['locked'], row['auto_until'], now)
    if expired_only and status != 'Expired':
        raise StaleAccount('Akun tidak lagi expired. Tidak ada akun yang dihapus.')
    state = [identity, row['expires'], row['ip_limit'], row['locked'], row['auto_until'], status, days, expired_only]
    token = hashlib.sha256(json.dumps(['nathaya-action-v1', *state]).encode()).hexdigest()
    proposed = max(row['expires'], now) + days * 86400 if days is not None else 0
    return row, status, token, proposed, now


def action_days(value):
    if re.fullmatch(r'[0-9]{1,4}', value) is None or not 1 <= int(value) <= 3650:
        raise AccountError('Tambahan masa aktif harus 1–3650 hari.')
    return int(value)


def change_account(username, identity, expected_token, days=None, *, expired_only=False):
    with database() as db:
        db.execute('BEGIN IMMEDIATE')
        row, _, token, proposed, now = action_snapshot(db, username, identity, days, expired_only=expired_only)
        if not secrets.compare_digest(token, expected_token):
            raise StaleAccount('Data akun berubah. Tinjau konfirmasi terbaru.')
        if days is None:
            db.execute('DELETE FROM accounts WHERE username=?', (username,))
            return None
        db.execute('UPDATE accounts SET expires=? WHERE username=?', (proposed, username))
        return proposed, status_for(proposed, row['locked'], row['auto_until'], now)


def expired_snapshot(db, now):
    rows = db.execute(f'SELECT {PUBLIC}, verifier, sealed FROM accounts WHERE expires <= ? ORDER BY username',
                      (now,)).fetchall()
    # Include immutable identity and public state, not secrets or the wall clock.
    entries = [(*tuple(row)[:-2], account_identity(row)) for row in rows]
    fingerprint = hashlib.sha256(json.dumps(['nathaya-expired-v1', entries]).encode()).hexdigest()
    return entries, fingerprint


def delete_all_expired(expected_fingerprint):
    with database() as db:
        db.execute('BEGIN IMMEDIATE')
        now = int(time.time())
        entries, fingerprint = expired_snapshot(db, now)
        if not secrets.compare_digest(fingerprint, expected_fingerprint):
            raise StaleAccount('Daftar expired berubah. Tidak ada akun yang dihapus; tinjau daftar terbaru.')
        deleted = db.execute('DELETE FROM accounts WHERE expires <= ?', (now,)).rowcount
        if deleted != len(entries):
            raise AccountError('Jumlah akun berubah saat penghapusan. Seluruh operasi dibatalkan.')
    return deleted


def change_lock(username, lock):
    with database() as db:
        db.execute('BEGIN IMMEDIATE')
        row = account_row(db, username)
        now = int(time.time())
        if not lock and (row['expires'] <= now or row['auto_until'] > now):
            raise AccountError('Unlock ditolak: akun expired atau masih terkunci otomatis.')
        db.execute('UPDATE accounts SET locked=? WHERE username=?', (int(lock), username))


def read_ports():
    try:
        ports = PORT_FILE.read_text(encoding='ascii').split()
    except FileNotFoundError:
        ports = ['109']
    if sorted(ports) not in (['109'], ['109', '143']):
        raise AccountError('ssh-ports.conf harus berisi 109 atau 109 143.')
    return [int(port) for port in ports]


def active_accounts():
    with database() as db:
        now = int(time.time())
        rows = db.execute('SELECT username, created, verifier, sealed FROM accounts '
                          'WHERE locked=0 AND expires>? AND auto_until<=?', (now, now)).fetchall()
    return {r['username']: (r['verifier'], account_identity(r)) for r in rows if NAME.fullmatch(r['username'])
            and re.fullmatch(r'\$6\$[./A-Za-z0-9$]+', r['verifier']) and not system_name_used(r['username'])}


def same_access(original, eligible, name):
    return name in original and original[name] == eligible.get(name)


def jailed_command(snapshot, probe=False):
    cmd = [BWRAP, '--die-with-parent', '--unshare-pid', '--unshare-ipc', '--unshare-uts',
           '--clearenv', '--setenv', 'PATH', '/nonexistent', '--cap-drop', 'ALL',
           '--cap-add', 'CAP_SETUID', '--cap-add', 'CAP_SETGID']
    # Dynamic loader and distro libraries only. No /bin, host /etc, host homes, or devpts.
    for pathname in ('/lib', '/lib64', '/usr/lib', '/usr/lib64', '/dev/null', '/dev/urandom'):
        if os.path.exists(pathname):
            cmd.extend(('--ro-bind', pathname, pathname))
    cmd.extend(('--ro-bind', DROPBEAR, DROPBEAR, '--ro-bind', str(snapshot), '/etc',
                '--ro-bind', str(STATE / 'dropbear_ed25519_host_key'), '/hostkey'))
    if Path('/etc/resolv.conf').is_file():
        cmd.extend(('--ro-bind', '/etc/resolv.conf', '/resolv.conf'))
    if not probe:
        cmd.extend(('--ro-bind', str(snapshot / 'log.sock'), '/dev/log'))
    cmd.extend(('--remount-ro', '/', '--', DROPBEAR))
    if probe:
        return cmd + ['-V']
    # Packaged Dropbear rejects -E in inetd mode; use a dedicated syslog socket.
    return cmd + ['-i', '-w', '-k', '-T', '4', '-r', '/hostkey', '-c', '/nonexistent']


def write_snapshot(snapshot, users):
    passwd = ['root:x:0:0::/empty:/nonexistent\n']
    shadow = ['root:!:0:0:99999:7:::\n']
    for uid, (name, verifier) in enumerate(users.items(), 200000):
        passwd.append(f'{name}:x:{uid}:65534::/empty:/nonexistent\n')
        shadow.append(f'{name}:{verifier}:0:0:99999:7:::\n')
    lines = {'passwd': ''.join(passwd), 'shadow': ''.join(shadow),
             'group': 'root:x:0:\nnogroup:x:65534:\n', 'shells': '/nonexistent\n',
             'nsswitch.conf': 'passwd: files\nshadow: files\ngroup: files\nhosts: files dns\n',
             'hosts': '127.0.0.1 localhost\n::1 localhost\n'}
    for name, data in lines.items():
        (snapshot / name).write_text(data, encoding='ascii')
    (snapshot / 'resolv.conf').symlink_to('/resolv.conf')


def auth_username(line):
    line = line.rstrip(b'\0\r\n')
    payload = re.fullmatch(rb'<\d{1,3}>(?:[A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d )?dropbear\[\d+\]: (.*)', line)
    match = AUTH.fullmatch(payload[1]) if payload else None
    return match[1].decode('ascii') if match else None


async def handle_client(client, sessions):
    process = None
    poll = None
    line = None
    log_socket = None
    try:
        users = active_accounts()
        if not users:
            return
        with tempfile.TemporaryDirectory(dir=RUNTIME) as directory:
            snapshot = Path(directory)
            write_snapshot(snapshot, {name: credentials[0] for name, credentials in users.items()})
            log_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            log_socket.bind(str(snapshot / 'log.sock'))
            log_socket.setblocking(False)
            loop = asyncio.get_running_loop()
            client.setblocking(True)
            process = await asyncio.create_subprocess_exec(*jailed_command(snapshot), stdin=client, stdout=client,
                                                            stderr=subprocess.DEVNULL)
            client.close()
            owner = None
            start = time.monotonic()
            poll = asyncio.create_task(process.wait())
            line = asyncio.create_task(loop.sock_recv(log_socket, 8192))
            while not poll.done():
                await asyncio.wait((poll, line), timeout=0.5, return_when=asyncio.FIRST_COMPLETED)
                eligible = active_accounts()
                if line.done():
                    entry = line.result()
                    if not entry:
                        break
                    observed = auth_username(entry)
                    if observed is not None:
                        if not same_access(users, eligible, observed) or (owner is not None and owner != observed):
                            break
                        owner = observed
                    line = asyncio.create_task(loop.sock_recv(log_socket, 8192))
                if owner is None:
                    if time.monotonic() - start > 20 or any(not same_access(users, eligible, name) for name in users):
                        break
                elif not same_access(users, eligible, owner):
                    break
    except (OSError, ValueError, sqlite3.Error, AccountError):
        # Do not forward the daemon's stderr, account information, or socket data to logs.
        pass
    finally:
        client.close()
        if line is not None:
            line.cancel()
        if log_socket is not None:
            log_socket.close()
        if process is not None and process.returncode is None:
            try:
                process.kill()  # bubblewrap's PID namespace ties the Dropbear worker to its lifetime.
            except ProcessLookupError:
                pass
            await process.wait()
        sessions.discard(asyncio.current_task())


async def serve():
    initialize()
    secret_path(RUNTIME, True)
    with tempfile.TemporaryDirectory(dir=RUNTIME) as directory:
        snapshot = Path(directory)
        write_snapshot(snapshot, {})
        result = subprocess.run(jailed_command(snapshot, probe=True), capture_output=True, timeout=8)
        if result.returncode != 0 or b'Dropbear' not in result.stdout + result.stderr:
            raise AccountError('Dropbear tidak dapat dijalankan di namespace terisolasi; listener tidak dibuka.')
    sockets = []
    sessions = set()
    loop = asyncio.get_running_loop()

    async def accept(listener):
        while True:
            client, _ = await loop.sock_accept(listener)
            if len(sessions) >= 128:
                client.close()
            else:
                sessions.add(asyncio.create_task(handle_client(client, sessions)))

    try:
        for port in read_ports():
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sockets.append(listener)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            listener.bind(('::', port))
            listener.listen(128)
            listener.setblocking(False)
        if addr := os.environ.get('NOTIFY_SOCKET'):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                notifier.connect('\0' + addr[1:] if addr.startswith('@') else addr)
                notifier.sendall(b'READY=1')
        await asyncio.gather(*(accept(s) for s in sockets))
    finally:
        for listener in sockets:
            listener.close()


def trial_duration_args(ip_limit, duration):
    match = re.fullmatch(r'([0-9]{1,5})([mh]?)', duration)
    if not match:
        raise AccountError('Gunakan menit (m) atau jam (h) untuk Trial.')
    # The original CLI accepted bare integers as hours; keep those callers working.
    return int(ip_limit), int(match[1]), match[2] or 'h'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('serve', 'available', 'create', 'trial', 'list', 'table',
                                             'action-table', 'action-view', 'delete', 'renew', 'detail',
                                             'expired-table', 'expired-view', 'delete-expired', 'delete-all-expired',
                                             'password', 'lock', 'unlock', 'ports'))
    parser.add_argument('values', nargs='*')
    args = parser.parse_args()
    operation, values = args.operation, args.values
    os.umask(0o077)
    if os.geteuid() != 0:
        raise AccountError('Modul SSH hanya boleh dijalankan root.')
    if operation == 'serve':
        asyncio.run(serve())
    elif operation == 'ports':
        print(' '.join(map(str, read_ports())))
    elif operation == 'create' and len(values) == 3:
        username, ip_limit, duration = values
        print(create('member', username, sys.stdin.readline(66).rstrip('\n'), int(ip_limit), int(duration)))
    elif operation == 'trial' and len(values) == 2:
        ip_limit, quantity, unit = trial_duration_args(*values)
        print(create('trial', '', '', ip_limit, quantity, trial_unit=unit))
    elif operation in ('lock', 'unlock') and len(values) == 1:
        change_lock(values[0], operation == 'lock')
    elif operation == 'delete' and len(values) == 3:
        change_account(*values)
    elif operation == 'delete-expired' and len(values) == 3:
        change_account(*values, expired_only=True)
    elif operation == 'delete-all-expired' and len(values) == 1:
        print(delete_all_expired(values[0]))
    elif operation == 'renew' and len(values) == 4:
        expires, status = change_account(*values[:3], days=action_days(values[3]))
        print(expires, status, sep='\t')
    else:
        with database() as db:
            if (operation == 'action-view' and len(values) in (2, 3)) or (operation == 'expired-view' and len(values) == 2):
                days = action_days(values[2]) if len(values) == 3 else None
                row, status, token, proposed, _ = action_snapshot(
                    db, values[0], values[1], days, expired_only=(operation == 'expired-view'))
                print(row['expires'], row['ip_limit'], status, token, proposed, sep='\t')
            elif operation == 'list' and not values:
                for row in db.execute(f'SELECT {PUBLIC} FROM accounts ORDER BY username'):
                    print(row['username'])
            elif operation == 'table' and not values:
                # Public data only; no verifier, password, or per-account subprocess.
                for row in db.execute(f'SELECT {PUBLIC} FROM accounts ORDER BY username'):
                    print('\t'.join(str(value) for value in row))
            elif operation == 'expired-table' and not values:
                entries, fingerprint = expired_snapshot(db, int(time.time()))
                print(len(entries), fingerprint, sep='\t')
                for entry in entries:
                    print(*entry, sep='\t')
            elif operation == 'action-table' and not values:
                for row in db.execute(f'SELECT {PUBLIC}, verifier, sealed FROM accounts ORDER BY username'):
                    print(*tuple(row)[:-2], account_identity(row), sep='\t')
            elif operation == 'available' and len(values) == 1:
                if not name_free(db, values[0]):
                    raise AccountError('Username sudah dipakai; pilih nama lain.')
            elif operation == 'detail' and len(values) == 1:
                print('\n'.join(str(v) for v in account_row(db, values[0])))
            elif operation == 'password' and len(values) == 1:
                row = account_row(db, values[0], 'sealed')
                sealed = row['sealed']
                if sealed is not None:
                    print(cipher().decrypt(sealed[:12], sealed[12:], values[0].encode('ascii')).decode('ascii'))
                else:
                    raise AccountError('Password tidak tersedia.')
            else:
                raise AccountError('Argumen modul SSH tidak valid.')


if __name__ == '__main__':
    try:
        main()
    except StaleAccount as error:
        print(str(error), file=sys.stderr)
        sys.exit(3)
    except ReplacedAccount as error:
        print(str(error), file=sys.stderr)
        sys.exit(4)
    except AccountError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        print('Operasi modul SSH gagal; periksa layanan, port, dependensi, dan izin data.', file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Modul SSH gagal atau data kunci tidak cocok.', file=sys.stderr)
        sys.exit(1)
