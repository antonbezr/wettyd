#include "replay.h"

#include <stdlib.h>
#include <string.h>

void replay_init(replay_buf_t *r, size_t capacity) {
  r->data = malloc(capacity);
  r->capacity = r->data != NULL ? capacity : 0;
  r->total = 0;
}

void replay_free(replay_buf_t *r) {
  free(r->data);
  r->data = NULL;
  r->capacity = 0;
}

void replay_append(replay_buf_t *r, const char *data, size_t len) {
  if (r->capacity == 0) {
    r->total += len;
    return;
  }

  // Only the newest `capacity` bytes can survive anyway.
  if (len > r->capacity) {
    r->total += len - r->capacity;
    data += len - r->capacity;
    len = r->capacity;
  }

  size_t pos = (size_t)(r->total % r->capacity);
  size_t first = r->capacity - pos;
  if (first > len) first = len;
  memcpy(r->data + pos, data, first);
  memcpy(r->data, data + first, len - first);
  r->total += len;
}

uint64_t replay_oldest(const replay_buf_t *r) { return r->total > r->capacity ? r->total - r->capacity : 0; }

static unsigned char byte_at(const replay_buf_t *r, uint64_t offset) {
  return (unsigned char)r->data[offset % r->capacity];
}

uint64_t replay_resume_offset(const replay_buf_t *r, uint64_t requested, size_t limit) {
  uint64_t earliest = replay_oldest(r);
  if (r->total > limit && r->total - limit > earliest) earliest = r->total - limit;

  if (requested >= earliest && requested <= r->total) return requested;

  uint64_t start = earliest;
  if (start > 0) {
    for (int i = 0; i < 3 && start < r->total && (byte_at(r, start) & 0xC0) == 0x80; i++) start++;
  }
  return start;
}

size_t replay_read(const replay_buf_t *r, uint64_t offset, char *out, size_t max) {
  if (r->capacity == 0 || offset < replay_oldest(r) || offset >= r->total) return 0;

  size_t len = (size_t)(r->total - offset);
  if (len > max) len = max;

  size_t pos = (size_t)(offset % r->capacity);
  size_t first = r->capacity - pos;
  if (first > len) first = len;
  memcpy(out, r->data + pos, first);
  memcpy(out + first, r->data, len - first);
  return len;
}
