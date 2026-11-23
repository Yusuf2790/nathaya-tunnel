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

    def action(self, name, days=None):
        with backend.database() as db:
            row = backend.account_row(db, name, '*')
            identity = backend.account_identity(row)
            _, status, token, proposed, _ = backend.action_snapshot(db, name, identity, days)
            return identity, token, status, proposed

    def test_renew_member_and_trial_in_all_states(self):
        now = 1800000000
        with patch.object(backend.time, 'time', return_value=now):
            for kind in ('member', 'trial'):
                for state, expires, manual, auto in (
                    ('Aktif', now + 120, 0, 0), ('Expired', now - 120, 0, 0),
                    ('Locked', now + 120, 1, now + 300),
                ):
                    with self.subTest(kind=kind, state=state):
                        name = backend.create(kind, 'test' + state.lower(), 'x', 9, 1)
                        with backend.database() as db:
                            db.execute('UPDATE accounts SET expires=?, locked=?, auto_until=? WHERE username=?',
                                       (expires, manual, auto, name))
                            before = dict(backend.account_row(db, name, '*'))
                        identity, token, old_status, preview = self.action(name, 30)
                        expected = max(now, expires) + 30 * 86400
                        self.assertEqual((old_status, preview), (state, expected))
                        saved, status = backend.change_account(name, identity, token, days=30)
                        self.assertEqual((saved, status), (expected, 'Locked' if manual else 'Aktif'))
                        with backend.database() as db:
                            after = dict(backend.account_row(db, name, '*'))
                            self.assertEqual(backend.account_identity(after), identity)
                        self.assertEqual(after, {**before, 'expires': expected})
                        with self.assertRaises(backend.StaleAccount):
                            backend.change_account(name, identity, token, days=30)

    def test_delete_revokes_access_and_rejects_recreated_account(self):
        with patch.object(backend.time, 'time', return_value=1800000000):
            member = backend.create('member', 'memberdel', 'x', 0, 7)
            trial = backend.create('trial', '', '', 0, 1)
            other = backend.create('member', 'otherssh', 'z', 0, 7)
            access = backend.active_accounts()
            for name in (member, trial):
                identity, token, _, _ = self.action(name)
                self.assertIsNone(backend.change_account(name, identity, token))
                with backend.database() as db:
                    with self.assertRaises(backend.AccountError):
                        backend.account_row(db, name)
                self.assertNotIn(name, backend.active_accounts())
                with self.assertRaises(backend.ReplacedAccount):
                    backend.change_account(name, identity, token)
            backend.create('member', member, 'x', 0, 7)
            after = backend.active_accounts()
            self.assertTrue(backend.same_access(access, after, other))
            self.assertFalse(backend.same_access(access, after, member))

    def test_renew_crossing_expiry_requires_fresh_confirmation(self):
        now = 1800000000
        with patch.object(backend.time, 'time', return_value=now):
            name = backend.create('trial', '', '', 0, 1, trial_unit='m')
            identity, token, _, _ = self.action(name, 1)
        with patch.object(backend.time, 'time', return_value=now + 61):
            with self.assertRaises(backend.StaleAccount):
                backend.change_account(name, identity, token, days=1)
            _, token, status, preview = self.action(name, 1)
            self.assertEqual(status, 'Expired')
        with patch.object(backend.time, 'time', return_value=now + 66):
            actual, status = backend.change_account(name, identity, token, days=1)
            self.assertEqual((actual, status), (preview + 5, 'Aktif'))

    def test_auth_log_and_ports(self):
        message = b"<85>Nov 21 00:10:11 dropbear[2]: Password auth succeeded for 'fixture1' from 127.0.0.1:1234"
        self.assertEqual(backend.auth_username(message), 'fixture1')
        self.assertIsNone(backend.auth_username(message + b', extra auth required'))
        self.assertEqual(backend.read_ports(), [109])
        backend.PORT_FILE.write_text('109\n143\n')
        self.assertEqual(backend.read_ports(), [109, 143])


if __name__ == '__main__':
    unittest.main()
