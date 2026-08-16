// SPDX-License-Identifier: ISC
/* Noise_XX_25519_ChaChaPoly_SHA256 handshake and transport state. */
#ifndef BITCHAT_NOISE_H
#define BITCHAT_NOISE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bitchat/crypto.h"
#include "bitchat/export.h"

struct bc_noise_hs;

#define BC_REPLAY_WINDOW_BYTES 128 /* 1024 nonces */

/*
 * An established session: one cipher state per direction. Transport frames
 * carry their own nonce, so the receive side keeps a sliding window of the
 * nonces it has already accepted rather than a counter.
 */
struct bc_noise_session {
	uint8_t send_key[BC_KEY_LEN];
	uint8_t recv_key[BC_KEY_LEN];
	uint64_t send_nonce;
	uint64_t highest_recv;
	uint8_t replay_window[BC_REPLAY_WINDOW_BYTES];
	uint8_t remote_static[BC_KEY_LEN];
	uint8_t handshake_hash[BC_HASH_LEN];
	bool established;
};

BC_API int bc_noise_hs_new(struct bc_noise_hs **ret, bool initiator,
                           const uint8_t static_priv[BC_KEY_LEN]);
BC_API void bc_noise_hs_free(struct bc_noise_hs *hs);

/*
 * Write the next handshake message into out (which must hold at least
 * len + 96 bytes). Returns the written length or a negative errno.
 */
BC_API long bc_noise_hs_write(struct bc_noise_hs *hs, const uint8_t *payload,
                              size_t len, uint8_t *out);

/* Read one handshake message; payload out is optional. */
BC_API long bc_noise_hs_read(struct bc_noise_hs *hs, const uint8_t *in,
                             size_t len, uint8_t *payload_out);

BC_API bool bc_noise_hs_done(const struct bc_noise_hs *hs);

/* The running handshake hash, for tests and channel binding. */
BC_API void bc_noise_hs_hash(const struct bc_noise_hs *hs,
                             uint8_t out[BC_HASH_LEN]);

/* Split the completed handshake into transport keys. */
BC_API int bc_noise_hs_split(struct bc_noise_hs *hs,
                             struct bc_noise_session *out);

/* Transport frames are <nonce[4] big endian><ciphertext><tag[16]>. */
#define BC_NOISE_NONCE_LEN 4
#define BC_NOISE_OVERHEAD (BC_NOISE_NONCE_LEN + BC_AEAD_TAG_LEN)

BC_API long bc_noise_encrypt(struct bc_noise_session *s, const uint8_t *in,
                             size_t len, uint8_t *out);
BC_API long bc_noise_decrypt(struct bc_noise_session *s, const uint8_t *in,
                             size_t len, uint8_t *out);

#endif
