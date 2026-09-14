import assert from 'node:assert/strict';
import { test } from 'node:test';

import { OutputDecoder } from './outputDecoder';

test('reassembles a multi-byte UTF-8 character split across chunk boundaries', () => {
  // U+2500 (BOX DRAWINGS LIGHT HORIZONTAL, one of the characters Claude
  // Code's CLI uses for its boxes) is 3 bytes in UTF-8. Split right after
  // the first byte to reproduce a chunk boundary landing mid-character, as
  // wettyd's C backend forwards PTY output in raw OS read() chunks with no
  // regard for character boundaries, see outputDecoder.ts.
  const bytes = new TextEncoder().encode('─── test ───');
  const chunk1 = bytes.subarray(0, 1);
  const chunk2 = bytes.subarray(1);

  const decoder = new OutputDecoder();
  const result = decoder.decode(chunk1) + decoder.decode(chunk2);

  assert.equal(result, '─── test ───');
});

test('decodes a message that arrives whole, not split at all', () => {
  const bytes = new TextEncoder().encode('hello ─ world');
  const decoder = new OutputDecoder();

  assert.equal(decoder.decode(bytes), 'hello ─ world');
});

test('reassembles a 4-byte character split across more than two chunks', () => {
  // An emoji outside the Basic Multilingual Plane is 4 bytes in UTF-8, one
  // byte at a time is the worst case a chunk boundary could produce.
  const bytes = new TextEncoder().encode('😀');
  const decoder = new OutputDecoder();

  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += decoder.decode(bytes.subarray(i, i + 1));
  }

  assert.equal(result, '😀');
});

test('keeps decoding correctly across many consecutive split characters', () => {
  const text = '╭─────╮\n│ hi ─ │\n╰─────╯';
  const bytes = new TextEncoder().encode(text);
  const decoder = new OutputDecoder();

  // Split into arbitrary small chunks, deliberately not aligned to
  // character boundaries, and confirm the reassembled text still matches
  // regardless of exactly where each split falls.
  let result = '';
  for (let i = 0; i < bytes.length; i += 2) {
    result += decoder.decode(bytes.subarray(i, i + 2));
  }

  assert.equal(result, text);
});
