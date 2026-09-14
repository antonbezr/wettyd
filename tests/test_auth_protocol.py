#!/usr/bin/env python3
"""
Protocol-level tests for wettyd's --credential auth handling, exercised
against a real wettyd process over the wire, complementing the pure-C unit
tests in test_auth.c which check the underlying decision logic in isolation.

wettyd's WebSocket upgrade is allowed to complete without an HTTP Basic Auth
header, since not every WebSocket client implementation can attach one to
the upgrade request. Enforcement is instead deferred to the AuthToken the
client sends as its first WS message. These tests pin down that the
handshake relaxation stays exactly that, and never becomes a real auth
bypass: unauthenticated or wrongly-authenticated connections must get
nothing back, not shell access, not input echo, not even the window
title or preferences that are normally sent right after connecting.

Usage: test_auth_protocol.py <path-to-wettyd-binary>
Exit code 0 if every test passes, 1 otherwise.
"""
import base64
import json
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.error

HOST = "127.0.0.1"
CREDENTIAL = "testuser:testpassword123"
CREDENTIAL_B64 = base64.b64encode(CREDENTIAL.encode()).decode()
WRONG_TOKEN = "not-the-right-token"

CLOSE_POLICY_VIOLATION = 1008


class Failure(Exception):
    pass


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, binary: str, port: int):
        self.port = port
        self.proc = subprocess.Popen(
            [
                binary,
                "--writable",
                "--port", str(port),
                "--interface", HOST,
                "--credential", CREDENTIAL,
                "cat",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._wait_until_listening()

    def _wait_until_listening(self, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection((HOST, self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise Failure(f"server never started listening on port {self.port}")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


class WsConn:
    """Minimal hand-rolled WebSocket client, just enough RFC 6455 to drive
    ttyd's protocol without pulling in an external dependency."""

    def __init__(self, port: int, path: str = "/ws"):
        self.sock = socket.create_connection((HOST, port), timeout=3)
        key = base64.b64encode(b"0123456789012345").decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {HOST}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: tty\r\n"
            f"\r\n"
        )
        self.sock.sendall(req.encode())
        resp = self.sock.recv(4096)
        status_line = resp.split(b"\r\n", 1)[0]
        if b"101" not in status_line:
            raise Failure(f"WS handshake failed: {status_line!r}")

    def send(self, payload: bytes):
        mask = b"\x01\x02\x03\x04"
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        fin_op = 0x80 | 0x2  # FIN + binary
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", fin_op, 0x80 | length)
        else:
            header = struct.pack("!BBH", fin_op, 0x80 | 126, length)
        self.sock.sendall(header + mask + masked)

    def recv_raw(self, timeout=1.0) -> bytes:
        """Best-effort single read of whatever's arrived. Good enough here
        since we only ever assert on presence/absence/close-code, not exact
        frame boundaries."""
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(4096)
        except socket.timeout:
            return b""

    @staticmethod
    def close_code(frame: bytes):
        """Returns the close code if frame is, or starts with, a close
        frame, else None."""
        if len(frame) < 4 or (frame[0] & 0x0F) != 0x8:
            return None
        return struct.unpack("!H", frame[2:4])[0]

    def close(self):
        self.sock.close()


def http_status(port: int, path: str, auth: str = None) -> int:
    req = urllib.request.Request(f"http://{HOST}:{port}{path}")
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def fetch_token(port: int) -> str:
    req = urllib.request.Request(f"http://{HOST}:{port}/token")
    req.add_header("Authorization", "Basic " + base64.b64encode(CREDENTIAL.encode()).decode())
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read())["token"]


# ---- tests -----------------------------------------------------------------

def test_http_index_requires_basic_auth(port):
    assert http_status(port, "/") == 401, "GET / without credentials should be 401"
    assert http_status(port, "/", auth=CREDENTIAL) == 200, "GET / with correct credentials should be 200"


def test_token_endpoint_requires_basic_auth(port):
    assert http_status(port, "/token") == 401, "GET /token without credentials should be 401"
    assert http_status(port, "/token", auth=CREDENTIAL) == 200


def test_token_endpoint_returns_expected_value(port):
    token = fetch_token(port)
    assert token == CREDENTIAL_B64, f"expected token {CREDENTIAL_B64!r}, got {token!r}"


def test_ws_handshake_succeeds_without_basic_auth(port):
    """The whole point of the fix: Safari can't attach a Basic Auth header
    to a WebSocket handshake, so the handshake itself must not require one."""
    conn = WsConn(port)
    conn.close()


def test_unauthenticated_input_is_rejected(port):
    conn = WsConn(port)
    conn.send(b"0" + b"id\n")  # INPUT command, skipping the JSON_DATA auth step entirely
    frame = conn.recv_raw()
    assert frame == b"" or conn.close_code(frame) is not None, (
        f"server should close an unauthenticated connection that sends INPUT, got {frame!r}"
    )
    conn.close()


def test_wrong_token_is_rejected_with_no_data_leaked(port):
    conn = WsConn(port)
    msg = json.dumps({"AuthToken": WRONG_TOKEN, "columns": 80, "rows": 24}).encode()
    conn.send(msg)
    frame = conn.recv_raw()
    code = conn.close_code(frame)
    assert code == CLOSE_POLICY_VIOLATION, (
        f"expected a clean close({CLOSE_POLICY_VIOLATION}) for a wrong token, got {frame!r}"
    )
    # Regression check: the server must not have sent the window-title and
    # preferences messages, or anything else, before rejecting the token.
    # frame must be only the close frame, nothing concatenated before it.
    assert frame[0] & 0x0F == 0x8 and len(frame) == 4, (
        f"leaked data to an unauthenticated client before closing: {frame!r}"
    )
    conn.close()


def test_correct_token_succeeds_and_spawns_process(port):
    conn = WsConn(port)
    token = fetch_token(port)
    msg = json.dumps({"AuthToken": token, "columns": 80, "rows": 24}).encode()
    conn.send(msg)
    frame = conn.recv_raw(timeout=2.0)
    assert conn.close_code(frame) is None, f"correct token should not be rejected, got {frame!r}"
    assert len(frame) > 0, "expected the initial title/preferences messages after a correct token"
    conn.close()


TESTS = [
    test_http_index_requires_basic_auth,
    test_token_endpoint_requires_basic_auth,
    test_token_endpoint_returns_expected_value,
    test_ws_handshake_succeeds_without_basic_auth,
    test_unauthenticated_input_is_rejected,
    test_wrong_token_is_rejected_with_no_data_leaked,
    test_correct_token_succeeds_and_spawns_process,
]


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-wettyd-binary>", file=sys.stderr)
        return 2

    binary = sys.argv[1]
    port = free_port()
    server = Server(binary, port)
    failures = []
    try:
        for test in TESTS:
            name = test.__name__
            try:
                test(port)
                print(f"PASS {name}")
            except (Failure, AssertionError) as e:
                print(f"FAIL {name}: {e}")
                failures.append(name)
            except Exception as e:  # noqa: BLE001 - report, don't hide, unexpected errors too
                print(f"ERROR {name}: {e!r}")
                failures.append(name)
    finally:
        out, err = b"", b""
        try:
            out, err = server.proc.communicate(timeout=0)
        except Exception:
            pass
        server.stop()

    if failures:
        print(f"\n{len(failures)}/{len(TESTS)} tests failed: {', '.join(failures)}")
        return 1
    print(f"\nall {len(TESTS)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
