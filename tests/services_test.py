"""Offline fixture tests only; NEVER bind/connect sockets or execute service binaries.

Callable CLI from checkout: python3 -I -B tests/services_test.py
These assertions do not substitute for nginx -t, haproxy -c, locked Xray binary
config tests, systemd validation or VPS SSH/WS/gRPC/TLS integration tests.
"""
import ast
import base64
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


R = module("fixture_service_renderer", "installer/render.py")
W = module("fixture_ws_relay", "services/ws_proxy.py")
# Explicit non-live key for deterministic fixtures ONLY; never a renderer default.
FIXTURE_KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def client_frame(payload=b"", opcode=2, fin=True, mask=b"abcd"):
    length = len(payload)
    if length < 126:
        size = bytes([128 | length])
    elif length < 65536:
        size = b"\xfe" + struct.pack("!H", length)
    else:
        size = b"\xff" + struct.pack("!Q", length)
    return bytes([(128 if fin else 0) | opcode]) + size + mask + bytes(
        value ^ mask[index % 4] for index, value in enumerate(payload))


def request(extra=b"", path=b"/ssh"):
    return b"GET " + path + b" HTTP/1.1\r\nHost: vpn.example.org\r\n" + extra + b"\r\n"


def websocket_request(key=b"dGhlIHNhbXBsZSBub25jZQ=="):
    return request(b"Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
                   b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + b"\r\n")


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.ports = R.load_ports()
        self.outputs = R.render_core("VPN.Example.org", self.ports, ss_server_key=FIXTURE_KEY)

    def test_exact_outputs_and_determinism(self):
        expected = {"nginx.conf", "haproxy.cfg"}
        expected.update(proto + ".json" for proto in R.PROTOCOLS)
        expected.update(proto + "@config.service" for proto in R.PROTOCOLS)
        expected.update(name + ".service" for name in (
            "nathaya-nginx", "nathaya-haproxy", "nathaya-ws", "nathaya-dropbear", "nathaya-sshd"))
        self.assertEqual(len(expected), 15)
        self.assertEqual(set(self.outputs), expected)
        again = R.render_core("vpn.example.org", copy.deepcopy(self.ports), ss_server_key=FIXTURE_KEY)
        # Do not dump configuration contents/key on failure.
        self.assertTrue(self.outputs == again)
        self.assertEqual(set(R.deployment_destinations()), expected)
        self.assertEqual(R.deployment_destinations()["nginx.conf"], "/etc/nathaya-tunnel/services/nginx.conf")
        for proto in R.PROTOCOLS:
            self.assertEqual(R.deployment_destinations()[proto + ".json"],
                             f"/etc/nathaya-tunnel/xray/{proto}/config.json")

    def test_strict_domain(self):
        self.assertEqual(R.validate_domain("Sub-1.example.org"), "sub-1.example.org")
        for bad in ("", "localhost", "127.0.0.1", "::1", "a.123", "*.example.org", "example.org.",
                    "example.org:443", "a_b.org", "-a.org", "a-.org", "a..org", "éxample.org",
                    " a.org", "a.org\n", "a.org;root /", "a.org/ssh", "$(id).org", "a" * 64 + ".org"):
            with self.subTest(domain=repr(bad)), self.assertRaises(ValueError):
                R.validate_domain(bad)

    def test_manifest_ports_paths_and_no_collisions(self):
        self.assertEqual(self.ports["public"], {"haproxy": [80, 443, 8080], "tls_download": 81, "dropbear": 143})
        self.assertEqual(self.ports["internal"], {"nginx_ws": 1010, "nginx_grpc": 1013,
                         "ssh_relay": 10015, "dropbear": 109, "sshd_tls": 2222, "sshd_plain": 2223})
        expected = {"vmess": ("/vmess", 10002, "vmess-grpc", 10006, 20001),
                    "vless": ("/vless", 10001, "vless-grpc", 10005, 20002),
                    "trojan": ("/trojan-ws", 10003, "trojan-grpc", 10007, 20003),
                    "shadowsocks": ("/ss-ws", 10004, "ss-grpc", 10008, 20004)}
        for proto, values in expected.items():
            r = self.ports["routes"][proto]
            self.assertEqual(tuple(r[k] for k in ("ws_path", "ws_port", "grpc_service", "grpc_port", "stats_port")), values)
        mutations = [lambda p: p.update(loopback="example.org"),
                     lambda p: p["routes"]["vless"].update(ws_port=10002),
                     lambda p: p["routes"]["vless"].update(ws_path="/x;root /etc"),
                     lambda p: p["routes"]["vless"].update(grpc_service="bad/name"),
                     lambda p: p["public"].update(tls_download=True),
                     lambda p: p["internal"].update(dropbear=110),
                     lambda p: p["openvpn"].update(status="installed"),
                     lambda p: p["xray"].update(version="latest")]
        for mutate in mutations:
            p = copy.deepcopy(self.ports)
            mutate(p)
            with self.assertRaises(ValueError):
                R.validate_ports(p)
        # The renderer consumes the trusted map rather than hardcoded route ports.
        p = copy.deepcopy(self.ports)
        p["routes"]["vmess"]["ws_port"] = 31002
        changed = R.render_core("vpn.example.org", p, ss_server_key=FIXTURE_KEY)
        self.assertIn("127.0.0.1:31002", changed["nginx.conf"])
        self.assertEqual(json.loads(changed["vmess.json"])["inbounds"][0]["port"], 31002)

    def test_nginx_routes_and_download_allowlist(self):
        text = self.outputs["nginx.conf"]
        self.assertIn("listen 127.0.0.1:1010 proxy_protocol;", text)
        self.assertIn("listen 127.0.0.1:1013 http2 proxy_protocol;", text)
        self.assertNotIn("http2 on;", text)  # Noble's nginx 1.24 does not have this directive.
        self.assertIn("location = /ssh { proxy_pass http://127.0.0.1:10015; }", text)
        self.assertIn("location / { proxy_pass http://127.0.0.1:10015; }", text)
        for proto, route in self.ports["routes"].items():
            self.assertIn(f"location = {route['ws_path']} {{ proxy_pass http://127.0.0.1:{route['ws_port']}; }}", text)
            self.assertIn(f"location ^~ /{route['grpc_service']}/ {{ grpc_pass grpc://127.0.0.1:{route['grpc_port']}; }}", text)
        download = text.split("listen 0.0.0.0:81 ssl;", 1)[1]
        aliases = re.findall(r"alias ([^;]+);", download)
        self.assertEqual(aliases, ["/opt/nathaya/public/openvpn/" + n for n in R.DOWNLOAD_FILES])
        self.assertEqual(re.findall(r"location = /([^ ]+)", download), list(R.DOWNLOAD_FILES))
        self.assertIn("location / { return 404; }", download)
        self.assertIn("disable_symlinks on;", download)
        self.assertIn("limit_except GET { deny all; }", download)
        self.assertNotIn("autoindex on", text)
        self.assertNotIn("root ", download)
        for name in ("fullchain.pem", "privkey.pem"):
            self.assertIn("/etc/nathaya-tunnel/tls/" + name, download)
        for backend in re.findall(r"(?:proxy_pass http|grpc_pass grpc)://([^;]+);", text):
            self.assertRegex(backend, r"^127\.0\.0\.1:[0-9]+$")

    def test_mux_deterministic_and_proxy_pairing(self):
        text = self.outputs["haproxy.cfg"]
        for port in (80, 443, 8080):
            self.assertIn(f"bind 0.0.0.0:{port}\n", text)
        self.assertIn("server tls abns@nathaya-tls send-proxy-v2", text)
        self.assertIn("bind abns@nathaya-tls accept-proxy ssl crt /etc/nathaya-tunnel/tls/haproxy.pem alpn h2,http/1.1", text)
        self.assertIn("5353482d322e30", text)  # SSH-2.0 prefix, not an HTTP header.
        for section in re.split(r"\nbackend ", text)[1:]:
            self.assertEqual(len(re.findall(r"^    server ", section, re.M)), 1)
            if section.startswith(("ssh_plain\n", "ssh_tls\n")):
                self.assertNotIn("send-proxy", section)
        self.assertIn("server ssh 127.0.0.1:2223\n", text)
        self.assertIn("server ssh 127.0.0.1:2222\n", text)
        self.assertIn("server nginx 127.0.0.1:1010 send-proxy-v2", text)
        self.assertIn("server nginx 127.0.0.1:1013 send-proxy-v2", text)
        for backend in re.findall(r"^    server \S+ (\S+)", text, re.M):
            self.assertTrue(backend.startswith(("127.0.0.1:", "abns@nathaya-tls")))
        for prohibited in ("balance ", "1194", "openvpn", "0.0.0.0:2222"):
            self.assertNotIn(prohibited, text.lower())
        decrypted = text.split("frontend decrypted_tls", 1)[1]
        self.assertLess(decrypted.index("use_backend grpc_h2"), decrypted.index("use_backend ssh_tls"))

    def test_xray_empty_clients_and_pinned_engine(self):
        self.assertEqual(self.ports["xray"]["version"], "v26.11.9")
        lock = json.loads((ROOT / "installer/external-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["xray"]["version"], self.ports["xray"]["version"])
        for proto in R.PROTOCOLS:
            config = json.loads(self.outputs[proto + ".json"])
            route = self.ports["routes"][proto]
            self.assertEqual(config["api"]["services"], ["StatsService"])
            self.assertEqual(config["inbounds"][-1]["port"], route["stats_port"])
            self.assertEqual(config["inbounds"][-1]["tag"], "api-in")
            for inbound in config["inbounds"]:
                self.assertEqual(inbound["listen"], "127.0.0.1")
                if inbound["tag"] == "api-in":
                    continue
                self.assertEqual(inbound["settings"]["clients"], [])
                self.assertEqual(inbound["streamSettings"]["security"], "none")
                self.assertNotIn("fallbacks", inbound["settings"])
                self.assertNotIn("id", inbound["settings"])
            self.assertTrue(config["log"]["error"].startswith("/opt/nathaya/logs/"))
        ss = json.loads(self.outputs["shadowsocks.json"])
        self.assertTrue(all(i["settings"]["password"] == FIXTURE_KEY for i in ss["inbounds"][:2]))
        for name, content in self.outputs.items():
            if name != "shadowsocks.json":
                self.assertTrue(FIXTURE_KEY not in content)
        with patch.object(R.secrets, "token_bytes", side_effect=[bytes(range(32)), bytes(reversed(range(32)))]) as entropy:
            first, second = R.new_server_key(), R.new_server_key()
            self.assertTrue(first != second)
            self.assertEqual(entropy.call_args_list[0].args, (32,))
        with self.assertRaises(ValueError):
            R.validate_server_key("not-a-key")

    def test_units_privileges_and_exact_commands(self):
        for proto in R.PROTOCOLS:
            unit = self.outputs[proto + "@config.service"]
            self.assertIn("User=root\n", unit)
            self.assertNotIn("DynamicUser=true", unit)
            self.assertIn("CapabilityBoundingSet=\n", unit)
            self.assertIn("NoNewPrivileges=true", unit)
            self.assertIn("StandardError=append:/opt/nathaya/logs/%N.log", unit)
            self.assertIn(f"ExecStart=/opt/nathaya/bin/xray run -config /etc/nathaya-tunnel/xray/{proto}/config.json", unit)
        nginx = self.outputs["nathaya-nginx.service"]
        self.assertIn("Group=www-data", nginx)
        self.assertIn("RuntimeDirectoryMode=0750", nginx)
        self.assertIn("-o www-data -g www-data -m 0700 /run/nathaya-nginx/body", nginx)
        self.assertIn("CAP_CHOWN", nginx)
        self.assertIn("ExecStart=/usr/sbin/haproxy -W -db -f /etc/nathaya-tunnel/services/haproxy.cfg", self.outputs["nathaya-haproxy.service"])
        self.assertIn("/usr/bin/python3 -I -B /opt/nathaya/services/ws_proxy.py", self.outputs["nathaya-ws.service"])
        drop = self.outputs["nathaya-dropbear.service"]
        self.assertIn("/usr/sbin/dropbear -F -E -w -p 0.0.0.0:143 -p 127.0.0.1:109 -r /etc/dropbear/dropbear_ed25519_host_key", drop)
        self.assertNotIn(" -R", drop)
        self.assertIn("/usr/sbin/sshd -D -f /etc/ssh/sshd_config -p 2222 -p 2223 -oListenAddress=127.0.0.1 -oPidFile=/run/nathaya-sshd.pid", self.outputs["nathaya-sshd.service"])
        for unit in (drop, self.outputs["nathaya-sshd.service"]):
            self.assertNotIn("DynamicUser=true", unit)
        self.assertFalse(any("openvpn" in name or "firewall" in name for name in self.outputs))

    def test_cli_private_exclusive_staging_and_no_secret_stdout(self):
        with tempfile.TemporaryDirectory(prefix="nathaya-services-fixture-") as temp:
            output = Path(temp) / "new"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                self.assertEqual(R.main(["--domain", "vpn.example.org", "--output-directory", str(output)]), 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for file in output.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            before = (output / "shadowsocks.json").read_bytes()
            with self.assertRaises(FileExistsError):
                R.write_outputs(self.outputs, output)
            self.assertTrue((output / "shadowsocks.json").read_bytes() == before)
            for forbidden in (ROOT / "must-not-be-created", Path("/etc/nathaya-tunnel/services"),
                              Path("/etc/systemd/system"), Path("/opt/nathaya/stage")):
                with self.assertRaises(ValueError):
                    R.write_outputs(self.outputs, forbidden)
            for args in (["--domain", "vpn.example.org"],
                         ["--domain", "bad;domain", "--output-directory", str(Path(temp) / "bad")]):
                with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                    R.main(args)
            self.assertFalse((Path(temp) / "bad").exists())


class RelayTests(unittest.TestCase):
    def test_fixed_target_and_no_import_effects(self):
        ports = R.load_ports()
        self.assertEqual(W.LISTEN, (ports["loopback"], ports["internal"]["ssh_relay"]))
        self.assertEqual(W.TARGET, (ports["loopback"], ports["internal"]["dropbear"]))
        # AST checks only: never execute a listener or server in this suite.
        for path in ("installer/render.py", "services/ws_proxy.py"):
            tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
            self.assertFalse(any(isinstance(n, (ast.Import, ast.ImportFrom)) and
                                 any(a.name in {"subprocess", "socket"} for a in n.names) for n in ast.walk(tree)))
        with patch.object(W.asyncio, "start_server", side_effect=AssertionError("listener called")), \
             patch.object(W.asyncio, "open_connection", side_effect=AssertionError("connection called")):
            module("inert_ws_fixture", "services/ws_proxy.py")

    def test_real_accept_and_legacy_raw(self):
        mode, response = W.handshake(websocket_request())
        self.assertEqual(mode, "websocket")
        self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n", response)
        key = base64.b64encode(bytes(range(16)))
        _, changed = W.handshake(websocket_request(key))
        self.assertNotEqual(response, changed)
        for header in (request(), request(b"Upgrade: websocket\r\nConnection: Upgrade\r\n"),
                       request(b"X-Real-Host: 127.0.0.1:109\r\n")):
            mode, response = W.handshake(header)
            self.assertEqual(mode, "raw")
            self.assertNotIn(b"Sec-WebSocket-Accept", response)

    def test_bad_or_target_selecting_headers_rejected(self):
        bad = [request(b"X-Real-Host: 8.8.8.8:443\r\n"), request(b"X-Real-Host: 127.0.0.1:22\r\n"),
               request(b"Content-Length: 1\r\n"), request(b"Transfer-Encoding: chunked\r\n"),
               request(b"Host: duplicate\r\n"), request(b" Folded: value\r\n"),
               request(b"Upgrade: other\r\n"), request(path=b"http://evil.invalid/"),
               websocket_request(b"bad-key"), websocket_request().replace(b"13\r\n", b"12\r\n"),
               websocket_request().replace(b"Connection: keep-alive, Upgrade", b"Connection: close"),
               request(b"Sec-WebSocket-Version: 13\r\n"), b"A" * (W.HEADER_LIMIT + 1),
               request().replace(b"\r\n", b"\n"), request(b"X-Test: value\x00\r\n")]
        for header in bad:
            with self.subTest(length=len(header)), self.assertRaises(W.ProtocolError):
                W.handshake(header)

    def test_masked_frame_lengths_incremental_and_coalesced(self):
        for size in (0, 1, 125, 126, 255, 65535, 65536):
            payload = bytes(n % 256 for n in range(size))
            wire = client_frame(payload)
            parsed = W.decode_frame(wire + b"leftover")
            self.assertEqual(parsed, (True, 2, payload, len(wire)))
            for partial in (b"", wire[:1], wire[:-1]):
                self.assertIsNone(W.decode_frame(partial))
            server = W.encode_frame(payload)
            self.assertEqual(server[0], 0x82)
            self.assertFalse(server[1] & 128)
            self.assertTrue(server.endswith(payload))
        self.assertEqual(W.encode_frame(b"pong", 10), b"\x8a\x04pong")

    def test_invalid_frames(self):
        bad = [b"\x82\x01x", b"\xc2\x80abcd", b"\x83\x80abcd", b"\x09\x80abcd",
               b"\x89\xfe\x00\x7e", b"\x82\xfe\x00\x01", b"\x82\xff" + struct.pack("!Q", 65535),
               b"\x82\xff" + struct.pack("!Q", 2 ** 63),
               b"\x82\xff" + struct.pack("!Q", W.FRAME_LIMIT + 1),
               client_frame(b"x", 8), client_frame(struct.pack("!H", 1005), 8),
               client_frame(struct.pack("!H", 1000) + b"\xff", 8)]
        for wire in bad:
            with self.subTest(prefix=wire[:2]), self.assertRaises(W.ProtocolError):
                W.decode_frame(wire)
        with self.assertRaises(W.ProtocolError):
            W.encode_frame(b"x" * 126, 9)

    def test_fragmentation_binary_ping_close_and_message_limit(self):
        messages = W.BinaryMessages()
        self.assertEqual(messages.receive(False, 2, b"SSH-"), ("data", b"SSH-"))
        self.assertEqual(messages.receive(True, 9, b"ping"), ("ping", b"ping"))
        self.assertEqual(messages.receive(True, 0, b"2.0\r\n"), ("data", b"2.0\r\n"))
        self.assertFalse(messages.fragmented)
        self.assertEqual(messages.receive(True, 8, b""), ("close", b""))
        for fin, opcode in ((True, 0), (True, 1)):
            with self.assertRaises(W.ProtocolError):
                W.BinaryMessages().receive(fin, opcode, b"x")
        messages.receive(False, 2, b"a")
        with self.assertRaises(W.ProtocolError):
            messages.receive(True, 2, b"b")
        huge = W.BinaryMessages()
        for _ in range(W.MESSAGE_LIMIT // W.FRAME_LIMIT):
            huge.receive(False, 2 if not huge.fragmented else 0, b"x" * W.FRAME_LIMIT)
        with self.assertRaises(W.ProtocolError):
            huge.receive(True, 0, b"x")
        close = struct.pack("!H", 1000) + b"bye"
        self.assertEqual(W.decode_frame(client_frame(close, 8))[2], close)


if __name__ == "__main__":
    unittest.main()
