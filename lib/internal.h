// SPDX-License-Identifier: ISC
/* Internal definitions shared between library sources. Not installed. */
#ifndef BITCHAT_INTERNAL_H
#define BITCHAT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "bitchat/ble.h"
#include "bitchat/crypto.h"
#include "bitchat/identity.h"
#include "bitchat/mesh.h"
#include "bitchat/noise.h"
#include "bitchat/packet.h"
#include "bitchat/tcp.h"
#include "bitchat/tlv.h"

#include "lib/cleanup.h"
#include "include/useful.h"

/* Milliseconds since the epoch. */
int64_t bc_now_ms(void);

/* SHA-256 over two buffers, without joining them first. */
void bc_sha256_two(const uint8_t *a, size_t alen, const uint8_t *b,
                   size_t blen, uint8_t out[BC_HASH_LEN]);

/* Upstream's rule for whether a payload is worth deflating. */
bool bc_should_compress(const uint8_t *data, size_t len);

/* Uniform random integer in [0, n). */
uint32_t bc_rand_below(uint32_t n);

/* Raw deflate, as Apple's COMPRESSION_ZLIB produces. */
int bc_deflate(const uint8_t *in, size_t len, uint8_t **out, size_t *outlen);
int bc_inflate(const uint8_t *in, size_t len, size_t original, uint8_t **out);

#include "banned.h"

#endif
