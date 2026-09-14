import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  decodeBase64Utf8,
  parseTmuxOsc52Passthrough,
  WriteOnlyClipboardProvider,
} from './osc52Clipboard';

test('WriteOnlyClipboardProvider always reports an empty clipboard on read', async () => {
  // The security-relevant guarantee this whole module exists for: no
  // program running in the shell can read the real system clipboard
  // through OSC 52, only write to it.
  const provider = new WriteOnlyClipboardProvider();
  assert.equal(await provider.readText('c'), '');
  assert.equal(await provider.readText('p'), '');
});

test('decodeBase64Utf8 decodes plain ASCII', () => {
  assert.equal(decodeBase64Utf8('aGVsbG8='), 'hello');
});

test('decodeBase64Utf8 decodes multi-byte UTF-8 text', () => {
  const original = 'héllo 世界';
  const base64 = Buffer.from(original, 'utf8').toString('base64');
  assert.equal(decodeBase64Utf8(base64), original);
});

test('decodeBase64Utf8 tolerates embedded whitespace', () => {
  assert.equal(decodeBase64Utf8('aGVs\nbG8=\n'), 'hello');
});

function tmuxDcs(oscInner: string): string {
  // Mirrors what xterm's parser hands the DCS handler: the leading 't' of
  // "tmux;" is already consumed as the DCS final byte, so the data starts
  // with "mux;", followed by the wrapped OSC 52 sequence with ESC doubled.
  const wrapped = `\x1b]52;${oscInner}\x07`.replace(/\x1b/g, '\x1b\x1b');
  return `mux;${wrapped}`;
}

test('parseTmuxOsc52Passthrough extracts the base64 payload', () => {
  const payload = parseTmuxOsc52Passthrough(tmuxDcs('c;aGVsbG8='));
  assert.equal(payload, 'aGVsbG8=');
});

test('parseTmuxOsc52Passthrough works with the primary selection too', () => {
  const payload = parseTmuxOsc52Passthrough(tmuxDcs('p;aGVsbG8='));
  assert.equal(payload, 'aGVsbG8=');
});

test('parseTmuxOsc52Passthrough ignores a clipboard read query', () => {
  // This is the security-relevant case: a bare '?' is a request to read the
  // clipboard, not write to it, and must never be treated as a payload.
  assert.equal(parseTmuxOsc52Passthrough(tmuxDcs('c;?')), null);
});

test('parseTmuxOsc52Passthrough ignores an empty payload', () => {
  assert.equal(parseTmuxOsc52Passthrough(tmuxDcs('c;')), null);
});

test('parseTmuxOsc52Passthrough returns null for an unrelated DCS payload', () => {
  assert.equal(parseTmuxOsc52Passthrough('not a tmux passthrough'), null);
});

test('parseTmuxOsc52Passthrough returns null when the wrapper has no OSC 52 inside', () => {
  const notOsc52 = 'mux;\x1b\x1b]4;1;rgb:00/00/00\x1b\x1b\\';
  assert.equal(parseTmuxOsc52Passthrough(notOsc52), null);
});
