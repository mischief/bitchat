// SPDX-License-Identifier: ISC
/* BitChat wire format: binary packet encode and decode. */
#ifndef BITCHAT_PACKET_H
#define BITCHAT_PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bitchat/export.h"

#define BC_PEER_ID_LEN 8
#define BC_SIG_LEN 64
#define BC_MAX_ROUTE_HOPS 16
#define BC_MAX_PAYLOAD (1024 * 1024)

/* Wire message types. */
enum bc_msg_type {
	BC_MSG_ANNOUNCE = 0x01,
	BC_MSG_MESSAGE = 0x02,
	BC_MSG_LEAVE = 0x03,
	BC_MSG_COURIER_ENVELOPE = 0x04,
	BC_MSG_NOISE_HANDSHAKE = 0x10,
	BC_MSG_NOISE_ENCRYPTED = 0x11,
	BC_MSG_FRAGMENT = 0x20,
	BC_MSG_REQUEST_SYNC = 0x21,
	BC_MSG_FILE_TRANSFER = 0x22,
	BC_MSG_BOARD_POST = 0x23,
	BC_MSG_PREKEY_BUNDLE = 0x24,
	BC_MSG_GROUP_MESSAGE = 0x25,
	BC_MSG_PING = 0x26,
	BC_MSG_PONG = 0x27,
	BC_MSG_NOSTR_CARRIER = 0x28,
	BC_MSG_VOICE_FRAME = 0x29,
	BC_MSG_ANNOUNCE_V2 = 0x2c,
};

/* Payload types inside a noiseEncrypted frame. */
enum bc_noise_payload_type {
	BC_NP_PRIVATE_MESSAGE = 0x01,
	BC_NP_READ_RECEIPT = 0x02,
	BC_NP_DELIVERED = 0x03,
	BC_NP_AUTH_PEER_STATE = 0x21,
};

/*
 * A decoded packet. payload is heap allocated and owned by the packet; free
 * it with bc_packet_free. All other fields are inline.
 */
struct bc_packet {
	uint8_t version; /* 1 or 2 */
	uint8_t type;
	uint8_t ttl;
	uint64_t timestamp; /* milliseconds since the epoch */
	uint8_t sender[BC_PEER_ID_LEN];
	uint8_t recipient[BC_PEER_ID_LEN];
	bool has_recipient;
	bool is_rsr; /* relay-sourced restore flag */
	uint8_t route[BC_MAX_ROUTE_HOPS][BC_PEER_ID_LEN];
	uint8_t route_len;
	uint8_t *payload;
	size_t payload_len;
	uint8_t sig[BC_SIG_LEN];
	bool has_sig;
};

/* The broadcast recipient ID: eight 0xff bytes. */
BC_API bool bc_is_broadcast(const uint8_t id[BC_PEER_ID_LEN]);

/*
 * Encode p into a freshly allocated buffer. With pad set, the frame is
 * PKCS#7-padded toward the next 256/512/1024/2048-byte bucket, which is what
 * Noise frames and signing input use. Returns 0 or a negative errno.
 */
BC_API int bc_packet_encode(const struct bc_packet *p, bool pad, uint8_t **out,
                            size_t *outlen);

/*
 * Decode one frame. Padding is removed if the frame does not parse as-is.
 * out->payload is allocated; the caller frees it with bc_packet_free.
 * Returns 0, -EBADMSG for a malformed frame, or -ENOMEM.
 */
BC_API int bc_packet_decode(const uint8_t *buf, size_t len,
                            struct bc_packet *out);

/*
 * Serialize p the way signatures cover it: TTL forced to 0, signature and RSR
 * flag omitted, padded.
 */
BC_API int bc_packet_signing_data(const struct bc_packet *p, uint8_t **out,
                                  size_t *outlen);

BC_API void bc_packet_free(struct bc_packet *p);

/* Hex helpers for peer IDs and keys. */
BC_API void bc_hex_encode(const uint8_t *in, size_t len, char *out);
BC_API int bc_hex_decode(const char *in, uint8_t *out, size_t outlen);

#endif
