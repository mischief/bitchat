// SPDX-License-Identifier: ISC
/* Payload bodies: announcements and chat messages. */
#ifndef BITCHAT_TLV_H
#define BITCHAT_TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bitchat/crypto.h"
#include "bitchat/export.h"
#include "bitchat/packet.h"

#define BC_NICK_MAX 64
#define BC_MAX_NEIGHBORS 10
#define BC_CONTENT_MAX 1024

struct bc_announce {
	char nickname[BC_NICK_MAX];
	uint8_t noise_pub[BC_KEY_LEN];
	uint8_t sign_pub[BC_KEY_LEN];
	uint8_t neighbors[BC_MAX_NEIGHBORS][BC_PEER_ID_LEN];
	uint8_t neighbor_count;
};

BC_API int bc_announce_encode(const struct bc_announce *a, uint8_t **out,
                              size_t *outlen);
BC_API int bc_announce_decode(const uint8_t *in, size_t len,
                              struct bc_announce *out);

/*
 * A public chat packet carries the message text as bare UTF-8. The sender
 * name is not in the payload: receivers take it from the sender's announce.
 */

/* Private messages ride a Noise session as this TLV. */
#define BC_PM_CONTENT_MAX 256

struct bc_private_message {
	char id[40]; /* UUID string */
	char content[BC_PM_CONTENT_MAX];
};

BC_API int bc_private_message_encode(const char *id, const char *content,
                                     uint8_t **out, size_t *outlen);
BC_API int bc_private_message_decode(const uint8_t *in, size_t len,
                                     struct bc_private_message *out);

/*
 * Text arriving from the mesh is untrusted. Peers may send any bytes, so
 * strings are checked before they reach a terminal or a fixed buffer.
 */
BC_API bool bc_utf8_valid(const char *s, size_t len);

/* Largest length <= max that does not split a UTF-8 sequence. */
BC_API size_t bc_utf8_truncate(const char *s, size_t max);

/*
 * True when text names nick: an @ followed by the nickname, optionally with
 * a #abcd peer-ID suffix, and not running on into a longer name.
 */
BC_API bool bc_mentions(const char *text, const char *nick);

/* Fill buf with a random lowercase UUID string. */
BC_API void bc_uuid(char buf[40]);

#endif
