#!/usr/bin/env python3
"""Real terminal Ctrl+C on mocked SSH UI; no backend, service or account writes."""

import errno
import os
from pathlib import Path
import pty
import select
import signal
import time

REPO = Path(__file__).resolve().parents[2]
FIXTURE = r'''
NATHAYA_BASE=$1
DASHBOARD_EXIT=10
source "$NATHAYA_BASE/modules/common/ui.sh"
source "$NATHAYA_BASE/modules/menu/ssh.sh"
clear_screen() { :; }
get_width() { printf '32\n'; }
ssh_ready() { return 0; }
ssh_backend() {
    case "$1" in
        table) printf 'member01\tmember\t1\t4102444800\t0\t2\t0\t0\n' ;;
        detail) printf '%s\n' member01 member 1 4102444800 0 2 0 0 ;;
        create|trial|lock|unlock) printf 'UNEXPECTED MUTATION\n' >&2; exit 2 ;;
    esac
}
trap 'printf "\nOUTER INT RESTORED\n"; exit 0' INT
show_ssh_menu
'''


def main():
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp('bash', ['bash', '-c', FIXTURE, 'bash', str(REPO)])

    buffer = b''
    all_output = b''

    def expect(text):
        nonlocal buffer, all_output
        needle = text.encode()
        deadline = time.monotonic() + 8
        while needle not in buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise AssertionError(f'timed out waiting for {text!r}')
            try:
                chunk = os.read(fd, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b''
            if not chunk:
                raise AssertionError(f'PTY closed waiting for {text!r}')
            buffer += chunk
            all_output += chunk
        buffer = buffer.split(needle, 1)[1]

    reaped = False
    try:
        expect('Pilih menu SSH:')
        os.write(fd, b'1\n')
        expect('Username          : ')
        os.write(fd, b'\x03')
        expect('Pilih menu SSH:')
        os.write(fd, b'4\n')
        expect('Limit IP          : ')
        os.write(fd, b'0\n30m\n')
        expect('Buat akun trial ini? [y/n]')
        os.write(fd, b'\x03')
        expect('Pilih menu SSH:')
        os.write(fd, b'8\n')
        expect('Pilihan: ')
        os.write(fd, b'1\n')
        expect('Lanjutkan aksi ini? [y/n]')
        os.write(fd, b'\x03')
        expect('Pilih menu SSH:')
        os.write(fd, b'\x03')
        expect('OUTER INT RESTORED')
        _, status = os.waitpid(pid, 0)
        reaped = True
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
        assert b'UNEXPECTED MUTATION' not in all_output
    finally:
        os.close(fd)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
    print('OK: Ctrl+C membatalkan formulir/konfirmasi tanpa aksi dan memulihkan trap sebelumnya.')


if __name__ == '__main__':
    main()
