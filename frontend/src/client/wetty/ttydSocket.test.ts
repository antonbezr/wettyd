import assert from 'node:assert/strict';
import { test } from 'node:test';

import { reconnectDelay, shouldReconnect } from './ttydSocket';

test('a dropped connection is reconnected', () => {
  assert.equal(shouldReconnect(1006), true);
  assert.equal(shouldReconnect(1001), true);
  assert.equal(shouldReconnect(1011), true);
});

test('an exited command, refused auth, or a takeover is not', () => {
  assert.equal(shouldReconnect(1000), false);
  assert.equal(shouldReconnect(1008), false);
  assert.equal(shouldReconnect(4000), false);
});

test('reconnect attempts back off, then keep retrying at a ceiling', () => {
  const delays = [0, 1, 2, 3, 4, 5, 50].map(reconnectDelay);
  for (let i = 1; i < delays.length; i++) {
    assert.ok(delays[i] >= delays[i - 1], `delay ${i} should not shrink`);
  }
  assert.equal(delays[0], 500);
  assert.equal(delays[5], 10000);
  assert.equal(delays[6], 10000);
});
