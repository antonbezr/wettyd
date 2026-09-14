/**
 * Decodes a continuous stream of PTY output bytes arriving as separate,
 * arbitrarily-sized WebSocket messages into text.
 *
 * wettyd's C backend forwards PTY output in whatever chunks the OS read()
 * call happens to return (see src/pty.c's alloc_cb), with no regard for
 * UTF-8 character boundaries. A multi-byte character, box-drawing glyphs
 * included, can land right on a chunk boundary and arrive split across two
 * separate WS messages. Decoding each message independently corrupts that
 * split character into replacement glyphs. Streaming mode carries an
 * incomplete trailing byte sequence over to the next decode() call instead.
 */
export class OutputDecoder {
  private readonly decoder = new TextDecoder();

  decode(bytes: Uint8Array): string {
    return this.decoder.decode(bytes, { stream: true });
  }
}
