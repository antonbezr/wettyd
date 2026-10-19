// Unit tests for src/replay.c: the scrollback ring a reconnecting client is
// caught up from.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/replay.h"

static int failures = 0;

static void check(int condition, const char *description) {
  if (condition) {
    printf("PASS %s\n", description);
  } else {
    printf("FAIL %s\n", description);
    failures++;
  }
}

static int read_equals(const replay_buf_t *r, uint64_t offset, const char *expected) {
  char out[64];
  size_t n = replay_read(r, offset, out, sizeof(out));
  return n == strlen(expected) && memcmp(out, expected, n) == 0;
}

int main(void) {
  replay_buf_t r;

  replay_init(&r, 8);
  check(r.total == 0 && replay_oldest(&r) == 0, "a new buffer is empty");
  check(replay_read(&r, 0, NULL, 0) == 0, "reading an empty buffer returns nothing");

  replay_append(&r, "hello", 5);
  check(read_equals(&r, 0, "hello"), "reads back what was appended");
  check(read_equals(&r, 2, "llo"), "reads from a mid-stream offset");
  check(replay_read(&r, 5, NULL, 0) == 0, "nothing to read once caught up");

  replay_append(&r, "world", 5);
  check(r.total == 10, "total counts every byte ever appended");
  check(replay_oldest(&r) == 2, "the oldest bytes fall off once the ring is full");
  check(read_equals(&r, 2, "lloworld"), "reads across the ring's wrap point");
  check(read_equals(&r, 7, "rld"), "reads the newest bytes after a wrap");
  check(replay_read(&r, 1, (char[8]){0}, 8) == 0, "an offset that already fell off reads nothing");

  char small[3];
  check(replay_read(&r, 2, small, sizeof(small)) == 3 && memcmp(small, "llo", 3) == 0,
        "a read stops at the caller's buffer size");

  replay_append(&r, "0123456789ABC", 13);
  check(r.total == 23 && read_equals(&r, 15, "56789ABC"),
        "an append larger than the ring keeps only its newest bytes");
  replay_free(&r);

  replay_init(&r, 16);
  replay_append(&r, "abcdef", 6);
  check(replay_resume_offset(&r, 4, 16) == 4, "a client still within the buffer resumes where it left off");
  check(replay_resume_offset(&r, 6, 16) == 6, "a caught-up client resumes at the end");
  check(replay_resume_offset(&r, 0, 16) == 0, "a fresh client gets everything when nothing was dropped");
  check(replay_resume_offset(&r, 99, 16) == 0, "a client claiming more than was ever sent gets a full replay");
  check(replay_resume_offset(&r, 0, 4) == 2, "a full replay goes back no further than the limit");
  replay_free(&r);

  // "é" is 0xC3 0xA9, so after dropping the first byte the ring opens on a
  // continuation byte.
  replay_init(&r, 4);
  replay_append(&r, "x\xC3\xA9yz", 5);
  check(replay_oldest(&r) == 1, "setup: the ring now starts at the second byte");
  check(replay_resume_offset(&r, 0, 4) == 1, "a replay starting on a lead byte keeps it");
  replay_append(&r, "!", 1);
  check(replay_resume_offset(&r, 0, 4) == 3, "a replay skips a leading UTF-8 continuation byte");
  replay_free(&r);

  if (failures > 0) {
    printf("\n%d test(s) failed\n", failures);
    return 1;
  }
  printf("\nall tests passed\n");
  return 0;
}
