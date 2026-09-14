/**
 * Pure OSC 52 clipboard logic, kept dependency-free (no xterm.js, no
 * addon-clipboard, no DOM) so it can be unit tested directly under Node.
 * osc52.ts wires this up against real xterm.js addons and browser APIs.
 */

/**
 * xterm.js's official addon-clipboard enables clipboard *reads* by default
 * with no confirmation, which would let any program running in the shell
 * silently exfiltrate the system clipboard just by printing an escape
 * sequence. This provider disables reads and only ever reports an empty
 * clipboard back, keeping writes working normally.
 *
 * Deliberately untyped against addon-clipboard's IClipboardProvider/
 * ClipboardSelectionType: those are declared as a const enum, and esbuild
 * transpiles files independently without full type information from
 * node_modules, so it cannot inline a const enum's values from another
 * package. Structural typing against the plain method shape below still
 * satisfies the interface at the ClipboardAddon call site.
 */
export class WriteOnlyClipboardProvider {
  readText(_selection: string): Promise<string> {
    return Promise.resolve('');
  }

  writeText(_selection: string, text: string): Promise<void> {
    return navigator.clipboard.writeText(text);
  }
}

export function decodeBase64Utf8(base64: string): string {
  const cleaned = base64.replace(/\s/g, '');
  const binary = atob(cleaned);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/**
 * tmux, when a pane wraps its own escapes for multiplexer nesting, some
 * OSC 52 clipboard providers do this regardless of tmux's own
 * set-clipboard/allow-passthrough settings, sends:
 *   ESC P tmux ; <payload with ESC doubled> ESC \
 * xterm.js has no native handler for this DCS, so without one it's
 * silently dropped even though addon-clipboard's direct OSC 52 handling
 * works fine on its own.
 *
 * Takes the raw data xterm's parser hands a DCS handler registered for
 * final byte 't', and returns the base64 clipboard payload if it's a
 * tmux OSC 52 passthrough, or null otherwise, including for a bare '?'
 * clipboard query, which is a read request and is ignored, matching the
 * write-only policy above.
 */
export function parseTmuxOsc52Passthrough(dcsData: string): string | null {
  // xterm's parser consumes the leading 't' of "tmux;" as the DCS final
  // byte identifying this handler, so the data it hands back starts with
  // the remainder, "mux;".
  if (!dcsData.startsWith('mux;')) return null;

  const unescaped = dcsData.slice(4).replace(/\x1b\x1b/g, '\x1b');
  const match = /\x1b\]52;([^\x07\x1b]*)(?:\x07|\x1b\\)/.exec(unescaped);
  if (!match) return null;

  const afterSelection = match[1].slice(match[1].indexOf(';') + 1);
  const payload = afterSelection.replace(/\s/g, '');
  if (!payload || payload === '?') return null;

  return payload;
}
