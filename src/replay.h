#ifndef WETTYD_REPLAY_H
#define WETTYD_REPLAY_H

#include <stddef.h>
#include <stdint.h>

// A fixed-size ring of the most recent PTY output, addressed by absolute
// byte offset into the session's whole output stream, so a reconnecting
// client can say "I have everything up to offset N" and get exactly the rest.
typedef struct {
  char *data;
  size_t capacity;
  uint64_t total;  // bytes ever appended, i.e. the offset just past the newest byte
} replay_buf_t;

void replay_init(replay_buf_t *r, size_t capacity);

void replay_free(replay_buf_t *r);

void replay_append(replay_buf_t *r, const char *data, size_t len);

// Offset of the oldest byte still held.
uint64_t replay_oldest(const replay_buf_t *r);

// Where to resume a client that already has everything before `requested`.
// Returns `requested` itself when the buffer still holds everything from
// there on, otherwise the earliest offset worth replaying: no further back
// than `limit` bytes, and moved past any UTF-8 continuation bytes so the
// replay doesn't open on half a character.
uint64_t replay_resume_offset(const replay_buf_t *r, uint64_t requested, size_t limit);

// Copies up to `max` bytes starting at `offset` into `out`, returning how
// many were copied. Returns 0 if `offset` is no longer, or not yet, held.
size_t replay_read(const replay_buf_t *r, uint64_t offset, char *out, size_t max);

#endif
