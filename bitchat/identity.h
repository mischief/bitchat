// SPDX-License-Identifier: ISC
/* Long-term device identity: a Noise static key and an Ed25519 signing key. */
#ifndef BITCHAT_IDENTITY_H
#define BITCHAT_IDENTITY_H

#include <stdint.h>

#include "bitchat/crypto.h"
#include "bitchat/export.h"
#include "bitchat/packet.h"

struct bc_identity {
	uint8_t noise_priv[BC_KEY_LEN];
	uint8_t noise_pub[BC_KEY_LEN];
	uint8_t sign_priv[BC_KEY_LEN];
	uint8_t sign_pub[BC_KEY_LEN];
	uint8_t fingerprint[BC_HASH_LEN]; /* SHA-256 of noise_pub */
	uint8_t peer_id[BC_PEER_ID_LEN];  /* first 8 fingerprint bytes */
};

/*
 * Load the identity from path, creating and saving a new one when the file is
 * absent. The file holds the two private keys and is written 0600.
 */
BC_API int bc_identity_load(struct bc_identity *id, const char *path);

/* Derive the fingerprint and peer ID from the Noise public key. */
BC_API void bc_identity_derive(struct bc_identity *id);

/* Default identity path: $XDG_CONFIG_HOME/bitchat/identity, else under ~. */
BC_API int bc_identity_default_path(char *buf, size_t len);

#endif
