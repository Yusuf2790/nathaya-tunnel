#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'modules/ssh/backend.py'
SPEC = importlib.util.spec_from_file_location('ssh_backend', SOURCE)
backend = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backend)


class BackendTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        os.umask(0o077)
        backend.STATE = Path(self.temp.name) / 'state'
        backend.PORT_FILE = Path(self.temp.name) / 'ports'
        self.run = patch.object(backend.subprocess, 'run', side_effect=self.tool).start()
        self.addCleanup(patch.stopall)
        backend.initialize()

    def tool(self, args, **kwargs):
        if args[0] == backend.KEY_TOOL:
            Path(args[-1]).write_bytes(b'host key fixture')
        else:
            self.assertEqual(args, ['/usr/bin/openssl', 'passwd', '-6', '-stdin'])
            self.assertRegex(kwargs['input'], r'^[a-z0-9]+\n$')
        return backend.subprocess.CompletedProcess(args, 0, stdout='$6$fixture$verifier\n')

    def test_trial_lock_and_reinitialize(self):
        a = backend.create('trial', '', '', 0, 2)
        b = backend.create('trial', '', '', 3, 1)
        self.assertNotEqual(a, b)
        self.assertRegex(a, r'^trial-[a-z0-9]{12}$')
        key = (backend.STATE / 'password.key').read_bytes()
        backend.initialize()
        self.assertEqual((backend.STATE / 'password.key').read_bytes(), key)
        with backend.database() as db:
            old = backend.account_row(db, a, fields='sealed')['sealed']
            password = backend.cipher().decrypt(old[:12], old[12:], a.encode())
            self.assertRegex(password, rb'^[a-z0-9]{16}$')
            self.assertNotIn(password, old)
        backend.change_lock(a, True)
        self.assertNotIn(a, backend.active_accounts())
        self.assertIn(b, backend.active_accounts())
        backend.change_lock(a, False)
        self.assertIn(a, backend.active_accounts())
        with backend.database() as db:
            db.execute('UPDATE accounts SET auto_until=? WHERE username=?', (2**50, a))
        with self.assertRaises(backend.AccountError):
            backend.change_lock(a, False)

    def test_trial_duration_units_and_legacy_hours(self):
        with patch.object(backend.time, 'time', return_value=1800000000):
            for value, seconds in (('30m', 1800), ('1h', 3600), ('2', 7200)):
                ip_limit, duration, unit = backend.trial_duration_args('0', value)
                name = backend.create('trial', '', '', ip_limit, duration, trial_unit=unit)
                with backend.database() as db:
                    row = backend.account_row(db, name)
                    self.assertEqual(row['created'], 1800000000)
                    self.assertEqual(row['expires'], row['created'] + seconds)
            for value in ('0m', '0h', '-1m', '43201m', '721h'):
                with self.assertRaises(backend.AccountError):
                    ip_limit, duration, unit = backend.trial_duration_args('0', value)
                    backend.create('trial', '', '', ip_limit, duration, trial_unit=unit)

    def test_collision_and_failure(self):
        backend.create('member', 'fixture1', 'x', 1, 7)
        with self.assertRaises(backend.AccountError):
            backend.create('member', 'fixture1', 'z', 0, 7)
        with patch.object(backend.subprocess, 'run', side_effect=OSError):
            with self.assertRaises(OSError):
                backend.create('member', 'fixture2', 'z', 0, 7)
        with backend.database() as db:
            self.assertTrue(backend.name_free(db, 'fixture2'))

    def test_auth_log_and_ports(self):
        message = b"<85>Nov 21 00:10:11 dropbear[2]: Password auth succeeded for 'fixture1' from 127.0.0.1:1234"
        self.assertEqual(backend.auth_username(message), 'fixture1')
        self.assertIsNone(backend.auth_username(message + b', extra auth required'))
        self.assertEqual(backend.read_ports(), [109])
        backend.PORT_FILE.write_text('109\n143\n')
        self.assertEqual(backend.read_ports(), [109, 143])


if __name__ == '__main__':
    unittest.main()
