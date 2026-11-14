"""Offline fixture-only tests. No network, extraction, commands or live PKI.

Run manually when execution is available: python3 -I -B tests/openvpn_test.py
Not executed by the coding agent. These are NOT OpenVPN/VPS integration tests.
The synthetic ASN.1 CA below is structurally valid, NOT cryptographically signed,
NOT a trust anchor and NOT usable server PKI. It contains no private material.
"""
import ast
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


A = module("fixture_openvpn_audit", "tools/audit-openvpn.py")
C = module("fixture_openvpn_clients", "tools/openvpn-clients.py")

# Independent verbatim directive fixture from Alrescha79 setup.sh:835-909.
# @PROTO@/@PORT@ differ only between the three original heredocs; $ip -> @HOST@.
REFERENCE = """auth-user-pass
client
dev tun
proto @PROTO@
remote @HOST@ @PORT@
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher none
auth none
"""
EXPECTED = (("tcp", "tcp", 1194), ("udp", "udp", 2200), ("ssl", "tcp", 443))


def tlv(tag, value):
    length = len(value)
    if length < 128:
        size = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        size = bytes([128 | len(encoded)]) + encoded
    return bytes([tag]) + size + value


def seq(*values):
    return tlv(0x30, b"".join(values))


def fixture_ca(ca=True):
    # SHA256-with-RSA AlgorithmIdentifier and public RSA bit string, dummy signature.
    alg = seq(tlv(6, bytes.fromhex("2a864886f70d01010b")), tlv(5, b""))
    key_alg = seq(tlv(6, bytes.fromhex("2a864886f70d010101")), tlv(5, b""))
    public_rsa = seq(tlv(2, b"\x00\x81\x01"), tlv(2, b"\x01\x00\x01"))
    identity = seq(tlv(0x31, seq(tlv(6, b"\x55\x04\x03"), tlv(12, b"OFFLINE_FIXTURE_IDENTITY"))))
    constraints = seq(tlv(1, b"\xff")) if ca else seq()
    extension = seq(tlv(6, b"\x55\x1d\x13"), tlv(1, b"\xff"), tlv(4, constraints))
    tbs = seq(tlv(0xa0, tlv(2, b"\x02")), tlv(2, b"\x01"), alg, identity,
              seq(tlv(23, b"240101000000Z"), tlv(23, b"490101000000Z")), identity,
              seq(key_alg, tlv(3, b"\x00" + public_rsa)), tlv(0xa3, seq(extension)))
    der = seq(tbs, alg, tlv(3, b"\x00" + b"FIXTURE_SIGNATURE" * 8))
    encoded = base64.b64encode(der)
    return b"-----BEGIN CERTIFICATE-----\n" + encoded + b"\n-----END CERTIFICATE-----\n"


def make_zip(entries, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # deliberate duplicate fixture
            for name, data in entries:
                archive.writestr(name, data)
    stream.seek(0)
    return stream


def directives(text):
    return [line for line in text.splitlines() if line and not line.startswith("#")]


class ClientTests(unittest.TestCase):
    def test_exact_reference_directives_order_and_ports(self):
        for name, proto, port in EXPECTED:
            template = (ROOT / "templates/openvpn" / ("client-" + name + ".ovpn.in")).read_text()
            expected = REFERENCE.replace("@PROTO@", proto).replace("@PORT@", str(port))
            self.assertEqual(directives(template), expected.splitlines())
            self.assertEqual(template.count("@HOST@"), 1)
            self.assertNotIn("data-ciphers", template)
            self.assertNotIn("AES", template)

    def test_public_ca_only_generated_outputs_and_no_replacement_directives(self):
        profiles = C.render_clients("VPN.Example.org", fixture_ca())
        self.assertEqual(set(profiles), {"client-" + name + ".ovpn" for name, _, _ in EXPECTED})
        for name, proto, port in EXPECTED:
            data = profiles["client-" + name + ".ovpn"]
            text = data.decode("ascii")
            config, ca = text.split("<ca>\n")
            expected = REFERENCE.replace("@PROTO@", proto).replace("@PORT@", str(port)).replace("@HOST@", "vpn.example.org")
            self.assertEqual(directives(config), expected.splitlines())
            self.assertTrue(ca.encode("ascii") == C.public_ca(fixture_ca()) + b"</ca>\n")
            self.assertNotIn(b"PRIVATE KEY", data)
            self.assertNotIn(b"<key>", data)
            self.assertNotIn(b"<cert>", data)
            self.assertNotIn(b"data-ciphers", data)

    def test_malformed_and_private_ca_rejected(self):
        cert = fixture_ca()
        bad_der = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"not a certificate") + b"\n-----END CERTIFICATE-----\n"
        malformed = [b"", b"not PEM", cert + cert, cert + b"extra", bad_der,
                     cert.replace(b"CERTIFICATE", b"PRIVATE KEY"),
                     b"-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n" + cert,
                     b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
                     fixture_ca(ca=False), cert.replace(b"END CERTIFICATE", b"END X509 CERTIFICATE"),
                     b"x" * (C.MAX_CA + 1)]
        for value in malformed:
            with self.assertRaises(ValueError):
                C.public_ca(value)
        self.assertTrue(C.public_ca(cert.replace(b"\n", b"\r\n")) == C.public_ca(cert))
        self.assertTrue(C.public_ca(C.public_ca(cert)) == C.public_ca(cert))

    def test_host_injection_rejected(self):
        for bad in ("", " host", "example.org\nkey secret", "x;plugin", "x/path", "x\\path",
                    "x:443", "x..org", "@HOST@", "-x.org", "x_.org", "é.org", "fe80::1%secret"):
            with self.assertRaises(ValueError):
                C.validate_host(bad)
        self.assertEqual(C.validate_host("192.0.2.1"), "192.0.2.1")
        self.assertEqual(C.validate_host("2001:db8::1"), "2001:db8::1")

    def test_new_temp_only_and_zip_exact_whitelist(self):
        profiles = C.render_clients("vpn.example.org", fixture_ca())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            C.write_clients(output, profiles, with_zip=True)
            self.assertEqual({p.name for p in output.iterdir()}, set(profiles) | {"allovpn.zip"})
            for filename in profiles:
                self.assertTrue((output / filename).read_bytes() == profiles[filename])
                self.assertEqual(stat.S_IMODE((output / filename).stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            with zipfile.ZipFile(output / "allovpn.zip") as archive:
                self.assertEqual(archive.namelist(), [item[0] for item in C.PROFILES])
                for filename in archive.namelist():
                    self.assertTrue(archive.read(filename) == profiles[filename])
            plain = Path(directory) / "plain"
            C.write_clients(plain, profiles)
            self.assertEqual({p.name for p in plain.iterdir()}, set(profiles))
            report = A.audit_stream(io.BytesIO((output / "allovpn.zip").read_bytes()))
            self.assertEqual(report["counts"]["config"], 3)
            self.assertEqual(report["counts"]["private_key"], 0)
            self.assertEqual(report["installation_status"], "BLOCKED")
            with self.assertRaises(FileExistsError):
                C.write_clients(output, profiles)
            (Path(directory) / "link").symlink_to(output, target_is_directory=True)
            with self.assertRaises(OSError):
                C.write_clients(Path(directory) / "link" / "new", profiles)
            with self.assertRaises(ValueError):
                C.write_clients(Path(directory) / ".." / "escape", profiles)
        with self.assertRaises(ValueError):
            C.write_clients(Path("/etc/openvpn/fixture-not-created"), profiles)
        with self.assertRaises(ValueError):
            C.zip_clients(dict(profiles, **{"unexpected.key": b"FORBIDDEN"}))

    def test_ca_symlink_and_special_file_read_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory) / "ca.pem"
            ca.write_bytes(fixture_ca())
            link = Path(directory) / "link.pem"
            link.symlink_to(ca)
            with self.assertRaises(ValueError):
                C.read_regular(link, C.MAX_CA)
            with self.assertRaises(ValueError):
                C.read_regular(Path(directory), C.MAX_CA)

    def test_cli_ack_required_before_read_and_no_sensitive_failure_output(self):
        out, err = io.StringIO(), io.StringIO()
        args = ["--host", "SECRET_HOST", "--ca-file", "SECRET_PATH", "--output-directory", "SECRET_OUTPUT"]
        with patch.object(C, "read_regular", side_effect=AssertionError("must not read")):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(C.main(args), 1)
        with patch.object(C, "read_regular", return_value=b"SECRET_PRIVATE_CONTENT"):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(C.main(args + ["--acknowledge-legacy-insecure"]), 1)
        self.assertNotIn("SECRET", out.getvalue() + err.getvalue())


class AuditTests(unittest.TestCase):
    def test_private_material_and_identities_never_reported(self):
        config = (b"port 1194\nproto tcp\ndev tun\nlocal 127.0.0.1\nserver 10.8.0.0 255.255.255.0\n"
                  b"plugin /SECRET_PLUGIN SECRET_ARGUMENT\nkey SECRET_PATH\nsetenv TOKEN SECRET_TOKEN\n"
                  b"port SECRET_NOT_A_PORT\nlocal SECRET_NOT_AN_IP\n"
                  b"<key>\n-----BEGIN PRIVATE KEY-----\nSECRET_PRIVATE_CONTENT\n-----END PRIVATE KEY-----\n</key>\n")
        entries = [("SECRET_NAME/SECRET_PROFILE.ovpn", config), ("SECRET_CERT.pem", fixture_ca()),
                   ("SECRET_SCRIPT.sh", b"#!/bin/sh\necho SECRET_COMMAND\n"), ("data", b"unclassified")]
        for sanitize in (False, True):
            report = A.audit_stream(make_zip(entries), sanitize)
            text = json.dumps(report)
            self.assertNotIn("SECRET", text)
            self.assertNotIn("OFFLINE_FIXTURE_IDENTITY", text)
            self.assertNotIn("BEGIN CERTIFICATE", text)
            self.assertNotIn("FIXTURE_SIGNATURE", text)
            self.assertNotIn("sha256", text)
            self.assertNotIn("audit_completed", report)
            self.assertEqual(report["status"], "structural_report_only")
            self.assertTrue(report["manual_review_required"])
            self.assertEqual(report["installation_status"], "BLOCKED")
            self.assertEqual(report["counts"], {"members": 4, "directories": 0, "private_key": 1,
                             "public_certificate": 1, "config": 1, "executable": 1, "other": 1})
            if sanitize:
                values = report["sanitized_configs"][0]["directives"]
                self.assertEqual(values, [{"directive": "port", "value": "1194"},
                    {"directive": "proto", "value": "tcp"}, {"directive": "dev", "value": "tun"},
                    {"directive": "local", "value": "127.0.0.1"},
                    {"directive": "server", "value": "10.8.0.0 255.255.255.0"}])
            else:
                self.assertNotIn("sanitized_configs", report)

    def test_private_key_variants_classified_without_names(self):
        entries = [("SECRET_" + str(i), b"-----BEGIN " + kind + b"-----\nPRIVATE_FIXTURE\n")
                   for i, kind in enumerate((b"RSA PRIVATE KEY", b"EC PRIVATE KEY", b"PRIVATE KEY",
                                             b"ENCRYPTED PRIVATE KEY", b"OPENSSH PRIVATE KEY",
                                             b"PGP PRIVATE KEY BLOCK"))]
        report = A.audit_stream(make_zip(entries))
        self.assertEqual(report["counts"]["private_key"], len(entries))
        self.assertNotIn("SECRET", json.dumps(report))

    def test_opaque_material_is_conservatively_classified(self):
        entries = [("SECRET.key", b"opaque fixture"), ("SECRET.p12", b"opaque fixture"),
                   ("SECRET.crt", b"opaque fixture")]
        report = A.audit_stream(make_zip(entries))
        self.assertEqual(report["counts"]["private_key"], 2)
        self.assertEqual(report["counts"]["public_certificate"], 1)
        self.assertNotIn("SECRET", json.dumps(report))

    def test_unsafe_names_and_duplicates(self):
        for name in ("../x", "a/../../x", "/x", "C:/x", "a\\x", "a//x", "a/./x", "./x", "a//"):
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip([(name, b"fixture")]))
        info = zipfile.ZipInfo("safe\x00SECRET")
        with self.assertRaises(ValueError):
            A.safe_name(info)
        for entries in ([('x', b'1'), ('x', b'2')], [('X', b'1'), ('x', b'2')],
                        [('x', b'1'), ('x/child', b'2')], [('x/', b''), ('x', b'1')]):
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip(entries))

    def test_unix_symlinks_special_types_and_linklike_metadata(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFCHR | 0o600,
                     stat.S_IFSOCK | 0o600):
            info = zipfile.ZipInfo("fixture")
            info.create_system = 3
            info.external_attr = mode << 16
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip([(info, b"SECRET_TARGET")]))
        # PKWARE Unix, ASi Unix, Info-ZIP Unix: reject all unknown metadata,
        # even if a particular reader might interpret it as a regular file.
        for tag in (0x000d, 0x756e, 0x5855, 0x7855, 0x7875):
            info = zipfile.ZipInfo("fixture")
            info.extra = struct.pack("<HH", tag, 13) + b"SECRET_TARGET"
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip([(info, b"fixture")]))
        # Hide a Unix field in the LOCAL header only (central field is innocuous).
        info = zipfile.ZipInfo("fixture")
        info.extra = struct.pack("<HH", 0x5455, 1) + b"\x00"
        data = bytearray(make_zip([(info, b"fixture")]).getvalue())
        data[30 + len("fixture"):32 + len("fixture")] = struct.pack("<H", 0x756e)
        with self.assertRaises(ValueError):
            A.audit_stream(io.BytesIO(data))

    def test_bounds_ratio_and_corruption(self):
        with self.assertRaises(ValueError):
            A.audit_stream(make_zip([(str(i), b"") for i in range(A.MAX_MEMBERS + 1)]))
        with self.assertRaises(ValueError):
            A.audit_stream(make_zip([("large", b"x" * (A.MAX_MEMBER + 1))]))
        with self.assertRaises(ValueError):
            A.audit_stream(make_zip([("bomb", b"x" * A.MAX_MEMBER)], zipfile.ZIP_DEFLATED))
        with patch.object(A, "MAX_TOTAL", 3):
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip([("a", b"12"), ("b", b"34")]))
        with patch.object(A, "MAX_ARCHIVE", 4):
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip([("a", b"fixture")]))
        with patch.object(A, "MAX_CENTRAL", 4):
            with self.assertRaises(ValueError):
                A.audit_stream(make_zip([("a", b"fixture")]))
        data = bytearray(make_zip([("a", b"fixture")]).getvalue())
        # Inconsistent end-record count must be rejected before ZipFile parses it.
        data[-12:-10] = struct.pack("<H", 0)
        with self.assertRaises(ValueError):
            A.audit_stream(io.BytesIO(data))
        with self.assertRaises(ValueError):
            A.audit_stream(io.BytesIO(b"not a ZIP SECRET"))
        data = bytearray(make_zip([("a", b"fixture")]).getvalue())
        data[31] ^= 1  # corrupt stored payload: CRC must fail, not report success
        with self.assertRaises(zipfile.BadZipFile):
            A.audit_stream(io.BytesIO(data))

    def test_read_only_no_extraction_and_cli_failure_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "SECRET_ARCHIVE.zip"
            archive.write_bytes(make_zip([("SECRET_CONFIG.ovpn", b"plugin /SECRET_PLUGIN\nport 1194\n")]).getvalue())
            before = archive.read_bytes()
            entries = {p.name for p in Path(directory).iterdir()}
            out = io.StringIO()
            with patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("forbidden")), \
                 patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("forbidden")), \
                 contextlib.redirect_stdout(out):
                self.assertEqual(A.main([str(archive), "--sanitized-report"]), 0)
            self.assertTrue(archive.read_bytes() == before)
            self.assertEqual({p.name for p in Path(directory).iterdir()}, entries)
            self.assertNotIn("SECRET", out.getvalue())
            archive.write_bytes(make_zip([("../SECRET_ESCAPE", b"SECRET_PRIVATE")]).getvalue())
            with contextlib.redirect_stdout(out):
                self.assertEqual(A.main([str(archive)]), 1)
            self.assertNotIn("SECRET", out.getvalue())
            self.assertEqual(json.loads(out.getvalue().splitlines()[-1])["status"], "rejected")

    def test_sanitizer_never_passes_arbitrary_values(self):
        data = (b"proto SECRET\ndev SECRET\nlocal fe80::1%SECRET\nserver SECRET 255.255.0.0\n"
                b"port 1194 SECRET\nplugin /SECRET\n<ca>\nport 9999\nSECRET\n</ca>\n")
        report = A.sanitized_config(data)
        self.assertEqual(report["directives"], [])
        self.assertNotIn("SECRET", json.dumps(report))
        pem = b"-----BEGIN PRIVATE KEY-----\nport 1194\n-----END PRIVATE KEY-----\n"
        self.assertEqual(A.sanitized_config(pem)["directives"], [])
        repeated = A.sanitized_config(b"port 1194\n" * (A.MAX_REPORTED_DIRECTIVES + 10))
        self.assertEqual(len(repeated["directives"]), A.MAX_REPORTED_DIRECTIVES)
        self.assertEqual(repeated["redacted_lines"], 10)

    def test_tools_have_no_process_network_or_extraction_calls(self):
        for path in ("tools/audit-openvpn.py", "tools/openvpn-clients.py"):
            source = (ROOT / path).read_text()
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    modules = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module]
                    self.assertFalse(any(name.split(".")[0] in ("subprocess", "socket", "urllib", "requests", "tarfile")
                                         for name in modules if name))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, ("extract", "extractall", "system", "popen", "spawn", "execv"))


if __name__ == "__main__":
    unittest.main()
