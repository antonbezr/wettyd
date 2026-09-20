#ifndef WETTYD_SHA256_H
#define WETTYD_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define WETTYD_SHA256_DIGEST_LEN 32
#define WETTYD_SHA256_HEX_LEN 65

void wettyd_sha256(const void *data, size_t len, uint8_t out[WETTYD_SHA256_DIGEST_LEN]);

void wettyd_sha256_hex(const void *data, size_t len, char out[WETTYD_SHA256_HEX_LEN]);

#endif
