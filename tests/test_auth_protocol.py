#!/usr/bin/env python3
"""
Protocol-level tests for wettyd's password auth, exercised against a real
wettyd process over the wire, complementing the pure-C unit tests in
test_auth.c and test_config.c which check the underlying logic in isolation.

The password lives in a config file, the browser logs in through a form on
wettyd's own login page, and the server hands back a session cookie. These
tests pin down that flow end to end: that an unauthenticated browser only
ever gets the login page, that the password itself is never echoed back to
the client, and that the WebSocket stays shut until the session is proven.

wettyd's WebSocket upgrade is allowed to complete unauthenticated, since not
every WebSocket client implementation can attach headers to the upgrade
request. Enforcement is deferred to the session cookie the browser sends
with the upgrade, or to the AuthToken the client sends as its first WS
message. These tests pin down that the handshake relaxation stays exactly
that, and never becomes a real auth bypass: unauthenticated or
wrongly-authenticated connections must get nothing back, not shell access,
not input echo, not even the window title or preferences that are normally
sent right after connecting.

Usage: test_auth_protocol.py <path-to-wettyd-binary>
Exit code 0 if every test passes, 1 otherwise.
"""
import http.client
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

HOST = "127.0.0.1"
PASSWORD = "testpassword123"
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
    """A wettyd process with its own config file, torn down on exit."""

    def __init__(self, binary: str, config: str = None):
        self.dir = tempfile.mkdtemp(prefix="wettyd-test-")
        self.config_path = os.path.join(self.dir, "config", "config.yaml")
        if config is not None:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                f.write(config)
        self.port = free_port()
        self.proc = subprocess.Popen(
            [
                binary,
                "--writable",
                "--port", str(self.port),
                "--interface", HOST,
                "--config", self.config_path,
                "cat",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._wait_until_listening()

    def _wait_until_listening(self, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise Failure(f"server exited early with code {self.proc.returncode}")
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
        shutil.rmtree(self.dir, ignore_errors=True)


class Response:
    def __init__(self, resp):
        self.status = resp.status
        self.headers = resp.headers
        self.body = resp.read().decode("utf-8", "replace")

    @property
    def location(self):
        return self.headers.get("Location")

    @property
    def set_cookie(self):
        return self.headers.get("Set-Cookie")

    def session_cookie(self):
        header = self.set_cookie
        if not header:
            return None
        match = re.match(r"wettyd-session=([^;]*)", header)
        return match.group(1) if match else None


def request(port, method, path, cookie=None, body=None) -> Response:
    """A single HTTP request that never follows redirects, so the redirect
    itself can be asserted on."""
    conn = http.client.HTTPConnection(HOST, port, timeout=3)
    headers = {}
    if cookie:
        headers["Cookie"] = f"wettyd-session={cookie}"
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, path, body=body, headers=headers)
        return Response(conn.getresponse())
    finally:
        conn.close()


def login(port, password) -> Response:
    return request(port, "POST", "/login", body=urllib.parse.urlencode({"password": password}))


def session_for(port, password=PASSWORD) -> str:
    resp = login(port, password)
    cookie = resp.session_cookie()
    if not cookie:
        raise Failure(f"login did not set a session cookie: {resp.status} {resp.set_cookie!r}")
    return cookie


class WsConn:
    """Minimal hand-rolled WebSocket client, just enough RFC 6455 to drive
    ttyd's protocol without pulling in an external dependency."""

    def __init__(self, port: int, path: str = "/ws", cookie: str = None):
        self.sock = socket.create_connection((HOST, port), timeout=3)
        key = "MDEyMzQ1Njc4OTAxMjM0NQ=="
        cookie_header = f"Cookie: wettyd-session={cookie}\r\n" if cookie else ""
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {HOST}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"{cookie_header}"
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


# ---- tests -----------------------------------------------------------------

def test_index_redirects_to_login(server):
    resp = request(server.port, "GET", "/")
    assert resp.status == 302, f"GET / without a session should redirect, got {resp.status}"
    assert resp.location == "/login", f"expected a redirect to /login, got {resp.location!r}"


def test_login_page_is_served(server):
    resp = request(server.port, "GET", "/login")
    assert resp.status == 200, f"GET /login should serve the login page, got {resp.status}"
    assert 'name="password"' in resp.body, "the login page should carry a password field"
    assert PASSWORD not in resp.body, "the login page must not leak the password"


def test_wrong_password_is_rejected(server):
    resp = login(server.port, "wrong-password")
    assert resp.status == 303, f"a failed login should redirect back to the login page, got {resp.status}"
    assert resp.location == "/login?error=1", f"expected a redirect to /login?error=1, got {resp.location!r}"
    assert resp.session_cookie() is None, "a failed login must not set a session cookie"


def test_correct_password_sets_session_cookie(server):
    resp = login(server.port, PASSWORD)
    assert resp.status == 303, f"a successful login should redirect to the terminal, got {resp.status}"
    assert resp.location == "/", f"expected a redirect to /, got {resp.location!r}"
    cookie = resp.session_cookie()
    assert cookie, "a successful login must set a session cookie"
    assert cookie != PASSWORD, "the session cookie must not be the password itself"
    assert re.fullmatch(r"[0-9a-f]{64}", cookie), f"expected a hex session token, got {cookie!r}"
    assert "HttpOnly" in resp.set_cookie, "the session cookie should be HttpOnly"


def test_session_cookie_opens_the_terminal(server):
    cookie = session_for(server.port)
    resp = request(server.port, "GET", "/", cookie=cookie)
    assert resp.status == 200, f"GET / with a session cookie should serve the terminal, got {resp.status}"


def test_stale_session_cookie_is_rejected(server):
    resp = request(server.port, "GET", "/", cookie="0" * 64)
    assert resp.status == 302, f"a bogus session cookie should be treated as no session, got {resp.status}"


def test_login_page_redirects_when_already_logged_in(server):
    cookie = session_for(server.port)
    resp = request(server.port, "GET", "/login", cookie=cookie)
    assert resp.status == 302, f"GET /login with a session should redirect, got {resp.status}"
    assert resp.location == "/", f"expected a redirect to /, got {resp.location!r}"


def test_logout_clears_the_session_cookie(server):
    cookie = session_for(server.port)
    resp = request(server.port, "GET", "/logout", cookie=cookie)
    assert resp.status == 303, f"GET /logout should redirect, got {resp.status}"
    assert resp.location == "/login", f"expected a redirect to /login, got {resp.location!r}"
    assert "Max-Age=0" in (resp.set_cookie or ""), f"logout should expire the cookie, got {resp.set_cookie!r}"


def test_token_endpoint_requires_a_session(server):
    assert request(server.port, "GET", "/token").status == 401, "GET /token without a session should be 401"
    cookie = session_for(server.port)
    assert request(server.port, "GET", "/token", cookie=cookie).status == 200


def test_token_endpoint_returns_the_session_token(server):
    cookie = session_for(server.port)
    token = json.loads(request(server.port, "GET", "/token", cookie=cookie).body)["token"]
    assert token == cookie, f"expected the session token {cookie!r}, got {token!r}"
    assert PASSWORD not in token, "the token endpoint must not hand out the password"


def test_ws_handshake_succeeds_without_a_session(server):
    """The whole point of the deferral: Safari can't attach credentials to a
    WebSocket handshake, so the handshake itself must not require one."""
    conn = WsConn(server.port)
    conn.close()


def test_unauthenticated_input_is_rejected(server):
    conn = WsConn(server.port)
    conn.send(b"0" + b"id\n")  # INPUT command, skipping the JSON_DATA auth step entirely
    frame = conn.recv_raw()
    assert frame == b"" or conn.close_code(frame) is not None, (
        f"server should close an unauthenticated connection that sends INPUT, got {frame!r}"
    )
    conn.close()


def test_wrong_token_is_rejected_with_no_data_leaked(server):
    conn = WsConn(server.port)
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


def test_password_is_not_accepted_as_a_ws_token(server):
    conn = WsConn(server.port)
    msg = json.dumps({"AuthToken": PASSWORD, "columns": 80, "rows": 24}).encode()
    conn.send(msg)
    frame = conn.recv_raw()
    assert conn.close_code(frame) == CLOSE_POLICY_VIOLATION, (
        f"the raw password must not authenticate a WS client, got {frame!r}"
    )
    conn.close()


def test_correct_token_succeeds_and_spawns_process(server):
    cookie = session_for(server.port)
    conn = WsConn(server.port)
    msg = json.dumps({"AuthToken": cookie, "columns": 80, "rows": 24}).encode()
    conn.send(msg)
    frame = conn.recv_raw(timeout=2.0)
    assert conn.close_code(frame) is None, f"correct token should not be rejected, got {frame!r}"
    assert len(frame) > 0, "expected the initial title/preferences messages after a correct token"
    conn.close()


def test_session_cookie_authenticates_the_websocket(server):
    """A browser sends the session cookie with the upgrade itself, so no
    AuthToken is needed in the first message."""
    cookie = session_for(server.port)
    conn = WsConn(server.port, cookie=cookie)
    conn.send(json.dumps({"columns": 80, "rows": 24}).encode())
    frame = conn.recv_raw(timeout=2.0)
    assert conn.close_code(frame) is None, f"a cookie-authenticated client should not be rejected, got {frame!r}"
    assert len(frame) > 0, "expected the initial title/preferences messages for a cookie-authenticated client"
    conn.close()


def test_websocket_without_cookie_or_token_is_rejected(server):
    conn = WsConn(server.port)
    conn.send(json.dumps({"columns": 80, "rows": 24}).encode())
    frame = conn.recv_raw()
    assert conn.close_code(frame) == CLOSE_POLICY_VIOLATION, (
        f"a client sending neither cookie nor token must be closed, got {frame!r}"
    )
    conn.close()


PASSWORD_TESTS = [
    test_index_redirects_to_login,
    test_login_page_is_served,
    test_wrong_password_is_rejected,
    test_correct_password_sets_session_cookie,
    test_session_cookie_opens_the_terminal,
    test_stale_session_cookie_is_rejected,
    test_login_page_redirects_when_already_logged_in,
    test_logout_clears_the_session_cookie,
    test_token_endpoint_requires_a_session,
    test_token_endpoint_returns_the_session_token,
    test_ws_handshake_succeeds_without_a_session,
    test_unauthenticated_input_is_rejected,
    test_wrong_token_is_rejected_with_no_data_leaked,
    test_password_is_not_accepted_as_a_ws_token,
    test_correct_token_succeeds_and_spawns_process,
    test_session_cookie_authenticates_the_websocket,
    test_websocket_without_cookie_or_token_is_rejected,
]


# ---- tests against other config-file states --------------------------------

def test_auth_none_serves_the_terminal_directly(server):
    resp = request(server.port, "GET", "/")
    assert resp.status == 200, f"with auth: none, GET / should serve the terminal, got {resp.status}"


def test_auth_none_redirects_the_login_page_away(server):
    resp = request(server.port, "GET", "/login")
    assert resp.status == 302, f"with auth: none there is nothing to log into, got {resp.status}"
    assert resp.location == "/", f"expected a redirect to /, got {resp.location!r}"


NO_AUTH_TESTS = [
    test_auth_none_serves_the_terminal_directly,
    test_auth_none_redirects_the_login_page_away,
]


def test_missing_config_is_generated(server):
    assert os.path.exists(server.config_path), "wettyd should create the config file when it is missing"
    with open(server.config_path) as f:
        config = f.read()
    match = re.search(r"^password:\s*(\S+)$", config, re.MULTILINE)
    assert match, f"the generated config should contain a password, got {config!r}"
    assert len(match.group(1)) >= 16, "the generated password should not be trivially short"
    assert oct(os.stat(server.config_path).st_mode & 0o777) == oct(0o600), (
        "the generated config file should only be readable by its owner"
    )


def test_generated_password_logs_in(server):
    with open(server.config_path) as f:
        password = re.search(r"^password:\s*(\S+)$", f.read(), re.MULTILINE).group(1)
    assert login(server.port, password).session_cookie(), "the generated password should open a session"
    assert login(server.port, "wrong").session_cookie() is None, "a wrong password should still be refused"


GENERATED_TESTS = [
    test_missing_config_is_generated,
    test_generated_password_logs_in,
]


SUITES = [
    (f"auth: password\npassword: {PASSWORD}\n", PASSWORD_TESTS),
    ("auth: none\n", NO_AUTH_TESTS),
    (None, GENERATED_TESTS),
]


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <path-to-wettyd-binary>", file=sys.stderr)
        return 2

    binary = sys.argv[1]
    failures = []
    total = 0

    for config, tests in SUITES:
        server = Server(binary, config)
        try:
            for test in tests:
                total += 1
                name = test.__name__
                try:
                    test(server)
                    print(f"PASS {name}")
                except (Failure, AssertionError) as e:
                    print(f"FAIL {name}: {e}")
                    failures.append(name)
                except Exception as e:  # noqa: BLE001 - report, don't hide, unexpected errors too
                    print(f"ERROR {name}: {e!r}")
                    failures.append(name)
        finally:
            server.stop()

    if failures:
        print(f"\n{len(failures)}/{total} tests failed: {', '.join(failures)}")
        return 1
    print(f"\nall {total} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
