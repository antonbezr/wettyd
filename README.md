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

`tests/test_auth.c` is pure C unit tests for `src/auth.c`, no server, no
sockets. `tests/test_auth_protocol.py` is a protocol-level test that spawns
a real `wettyd` process and drives the WS wire protocol directly, checking
the actual bytes sent, not just the underlying decision logic.

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

## Running

Same CLI as ttyd (see `./build/wettyd --help`), **ttyd is read-only by
default**, pass `-W`/`--writable` or nothing you type will reach the shell:

```sh
./build/wettyd --writable --port 7681 bash
```

Then open `http://localhost:7681/`.

## License

MIT, combining ttyd and wetty, see [LICENSE](./LICENSE) for both original
copyright notices.
