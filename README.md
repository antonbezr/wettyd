# wettyd

wetty's browser frontend, running on ttyd's C/libwebsockets backend.

## Why

[wetty](https://github.com/butlerx/wetty) has a nicer, more featureful
frontend, but its Node/Socket.IO backend can end up stuck on HTTP
long-polling instead of a real WebSocket, adding real typing latency.
[ttyd](https://github.com/tsl0922/ttyd)'s small C backend has no such
fallback, always a single persistent WebSocket, but a plainer frontend.

wettyd is wetty's frontend running on ttyd's backend instead, keeping the
better UI without the latency.

## What's reused from each project

- **Backend** - ttyd's C source, unmodified aside from cosmetic branding and
  the fixes/features documented below.
- **Frontend** - wetty's client as-is: styling, xterm.js config, mobile
  keyboard, file-download detection, options editor.
- **New** - `ttydSocket.ts`, a small transport adapter speaking ttyd's binary
  WS protocol behind the same interface wetty's client already expected, so
  the rest of the frontend needed minimal changes.
- **Dropped** - wetty's Node server, SSH, and PWA/service-worker entirely;
  ttyd's backend spawns the configured command directly.

## What's new

Things wettyd has that neither upstream project does, beyond gluing the two
together:

- **Password login page** - the password lives in a config file and the
  browser gets a real login page, replacing ttyd's HTTP Basic Auth dialog
  and its password-on-the-command-line. See
  [Authentication](#authentication).
- **Native OSC 52 clipboard** - copying from the remote shell, tmux
  passthrough included, lands in the local clipboard.
- **Safari WebSocket auth** - ttyd's handshake refuses clients that cannot
  attach credentials to the upgrade request, so Safari never connects at
  all. wettyd defers the check to the session cookie or the first WS
  message, without loosening what an unauthenticated client can see.
- **UTF-8 across message boundaries** - PTY output is decoded as one
  continuous stream, so a multi-byte character split across two WebSocket
  messages no longer turns into replacement glyphs.

## Building

```sh
# 1. Frontend -> src/html.h
cd frontend
npm install
npm run build

# 2. C backend (needs cmake, libwebsockets, libuv, json-c, zlib, e.g. via
#    `brew install cmake libwebsockets libuv json-c` on macOS)
cd ..
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j4
```

The build runs the test suite automatically as part of that last step, and
fails if any test fails. To run it again on demand without rebuilding:

```sh
cd build && ctest --output-on-failure
```

`tests/test_auth.c`, `tests/test_config.c`, `tests/test_sha256.c` and
`tests/test_homedir.c` are pure C unit tests for the matching `src/*.c`, no
server, no sockets. `tests/test_auth_protocol.py` is a protocol-level test
that spawns real `wettyd` processes and drives the login flow and the WS
wire protocol directly, checking the actual bytes sent, not just the
underlying decision logic.

The frontend has its own tests, run separately:

```sh
cd frontend && npm test
```

`src/client/wetty/outputDecoder.test.ts` covers `outputDecoder.ts`, which
reassembles PTY output that arrives with a multi-byte UTF-8 character split
across two WebSocket messages. wettyd's C backend forwards PTY output in
raw OS read() chunks with no regard for character boundaries, so this can
and does happen, decoding each message in isolation instead corrupts the
split character into replacement glyphs.

### How the build works

ttyd embeds its entire frontend as a gzip-compressed byte array baked into
`src/html.h` (see `html/gulpfile.js` upstream) and serves it as one HTTP
response with no other static routes. `frontend/build.js` reproduces that
pipeline against wetty's frontend instead of ttyd's:

1. `esbuild` bundles `frontend/src/client/wetty.ts` (+ its Sass) into a single
   IIFE `wetty.js` / `wetty.css`.
2. The xterm options editor (`assets/xterm_config/`) and the favicon are
   inlined by hand into `frontend/src/template.html`'s placeholders (a
   `srcdoc` iframe and a `data:` URI, respectively, both fully static, no
   server route needed).
3. [`inline-source`](https://www.npmjs.com/package/inline-source) inlines the
   bundled JS/CSS into that template, producing one self-contained
   `frontend/build/index.html`.
4. That file is gzipped and written out as `src/html.h` in ttyd's exact
   format, ready for the C build to embed.
5. `frontend/src/login.html`, the login page, goes through the same gzip and
   byte-array step into `src/login_html.h`. It is a standalone page with its
   own inline CSS, no bundling, no JS beyond showing the error banner.

## Running

Same CLI as ttyd (see `./build/wettyd --help`), **ttyd is read-only by
default**, pass `-W`/`--writable` or nothing you type will reach the shell:

```sh
./build/wettyd --writable --port 7681 bash
```

Then open `http://localhost:7681/`.

## Authentication

ttyd protects the terminal with HTTP Basic Auth, which means the browser's
own credential dialog rather than a page, and a password on the command
line, visible to anyone running `ps`. wettyd replaces both: the password
lives in a config file, and the browser gets a real login page.

On first run, wettyd writes `~/.config/wettyd/config.yaml` with a generated
password, and prints the path it wrote:

```yaml
auth: password
password: 8Kd2pQmXvR7nLzYt4WfA
```

Edit that file to set your own password, then restart wettyd. `--config
<path>` points at a different file, and `$XDG_CONFIG_HOME` is honoured when
set. The file is created `0600`, and only understands two keys:

- `auth` - `password` (the default) or `none` to disable auth entirely.
- `password` - the login password.

Logging in posts the password to `/login`, and the server replies with an
`HttpOnly`, `SameSite=Lax` session cookie holding a SHA-256 token derived
from the password, not the password itself. The cookie is good for 30 days,
survives restarts, and every cookie is invalidated by changing the password.
`/logout` clears it.

The WebSocket upgrade is accepted without credentials, and enforced
afterwards, from the session cookie the browser sends with the upgrade, or
from the `AuthToken` in the client's first message, because
[Safari cannot attach headers to a WS handshake](https://github.com/tsl0922/ttyd/issues/1437).
Until one of those checks passes, the connection is sent nothing at all, not
even the window title, and is closed on the first input.

`-H`/`--auth-header` still works as in ttyd, and takes precedence: with it
set, the config file is not read and an authenticating reverse proxy is
trusted instead.

Note that the session cookie is not marked `Secure`, so that plain-HTTP
access to localhost keeps working. Serve wettyd over HTTPS (`--ssl`, or a
TLS-terminating proxy such as a Cloudflare tunnel) if it is reachable from
anywhere else.