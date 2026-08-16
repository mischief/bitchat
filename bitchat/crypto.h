// SPDX-License-Identifier: ISC
/* Thin OpenSSL wrappers for the primitives BitChat uses. */
#ifndef BITCHAT_CRYPTO_H
#define BITCHAT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "bitchat/export.h"

#define BC_KEY_LEN 32
#define BC_HASH_LEN 32
#define BC_AEAD_TAG_LEN 16

BC_API int bc_random(void *buf, size_t len);

BC_API void bc_sha256(const uint8_t *in, size_t len, uint8_t out[BC_HASH_LEN]);
BC_API void bc_hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *in,
                           size_t len, uint8_t out[BC_HASH_LEN]);

/* Noise HKDF: two or three outputs from a chaining key and input material. */
BC_API void bc_hkdf(const uint8_t ck[BC_HASH_LEN], const uint8_t *ikm,
                    size_t ikmlen, uint8_t *o1, uint8_t *o2, uint8_t *o3);

BC_API int bc_x25519_keygen(uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN]);
BC_API int bc_x25519_pub(const uint8_t priv[BC_KEY_LEN],
                         uint8_t pub[BC_KEY_LEN]);
BC_API int bc_x25519_dh(const uint8_t priv[BC_KEY_LEN],
                        const uint8_t peer[BC_KEY_LEN],
                        uint8_t out[BC_KEY_LEN]);

BC_API int bc_ed25519_keygen(uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN]);
BC_API int bc_ed25519_pub(const uint8_t priv[BC_KEY_LEN],
                          uint8_t pub[BC_KEY_LEN]);
BC_API int bc_ed25519_sign(const uint8_t priv[BC_KEY_LEN], const uint8_t *msg,
                           size_t len, uint8_t sig[64]);
BC_API int bc_ed25519_verify(const uint8_t pub[BC_KEY_LEN], const uint8_t *msg,
                             size_t len, const uint8_t sig[64]);

/*
 * ChaCha20-Poly1305 as Noise uses it: a 12-byte nonce built from a 64-bit
 * counter in little endian, preceded by four zero bytes. out must hold
 * len + BC_AEAD_TAG_LEN bytes for the seal, len - BC_AEAD_TAG_LEN for the
 * open. Returns the output length, or a negative errno.
 */
BC_API long bc_aead_seal(const uint8_t key[BC_KEY_LEN], uint64_t counter,
                         const uint8_t *ad, size_t adlen, const uint8_t *in,
                         size_t len, uint8_t *out);
BC_API long bc_aead_open(const uint8_t key[BC_KEY_LEN], uint64_t counter,
                         const uint8_t *ad, size_t adlen, const uint8_t *in,
                         size_t len, uint8_t *out);

#endif
