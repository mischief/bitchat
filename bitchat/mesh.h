// SPDX-License-Identifier: ISC
/* Mesh engine: dedup, flood relay, fragments, sessions, presence. */
#ifndef BITCHAT_MESH_H
#define BITCHAT_MESH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bitchat/export.h"
#include "bitchat/identity.h"
#include "bitchat/packet.h"

struct bc_mesh;

/* A link is an opaque token owned by the transport. */
struct bc_mesh_ops {
	/* Write one frame to a single link. */
	void (*send)(void *ud, void *link, const uint8_t *frame, size_t len);
	/* Write one frame to every link except one (NULL for all). */
	void (*broadcast)(void *ud, void *except, const uint8_t *frame,
	                  size_t len);
	void (*on_public)(void *ud, const char *peer_id, const char *nick,
	                  const char *text, uint64_t timestamp);
	void (*on_private)(void *ud, const char *peer_id, const char *nick,
	                   const char *text, uint64_t timestamp);
	void (*on_peer)(void *ud, const char *peer_id, const char *nick,
	                bool joined);
	/* A private message we sent was delivered, or read. */
	void (*on_receipt)(void *ud, const char *peer_id, const char *nick,
	                   const char *message_id, bool read);
	void (*on_log)(void *ud, const char *line);
};

struct bc_peer_info {
	char peer_id[BC_PEER_ID_LEN * 2 + 1];
	char nickname[64];
	bool direct;
	bool encrypted;      /* a Noise session is established */
	int rssi;            /* dBm, 0 when unknown */
	int64_t rssi_age_ms; /* how old that reading is */
	int64_t last_seen_ms;
};

BC_API int bc_mesh_new(struct bc_mesh **ret, const struct bc_identity *id,
                       const char *nickname, const struct bc_mesh_ops *ops,
                       void *ud);
BC_API void bc_mesh_free(struct bc_mesh *m);

BC_API void bc_mesh_link_up(struct bc_mesh *m, void *link);
BC_API void bc_mesh_link_down(struct bc_mesh *m, const void *link);
BC_API void bc_mesh_recv(struct bc_mesh *m, void *link, const uint8_t *frame,
                         size_t len);

/* Record the signal strength the transport measured for a link. */
BC_API void bc_mesh_link_rssi(struct bc_mesh *m, const void *link, int rssi);

BC_API int bc_mesh_send_public(struct bc_mesh *m, const char *text);
/*
 * Send a private message. msg_id, when given, receives the ID the receipts
 * will quote; it is assigned even when the message waits for a handshake.
 */
BC_API int bc_mesh_send_private(struct bc_mesh *m, const char *peer_id,
                                const char *text, char msg_id[40]);
BC_API int bc_mesh_announce(struct bc_mesh *m);
BC_API int bc_mesh_leave(struct bc_mesh *m);

/* Milliseconds until bc_mesh_tick wants to run again. */
BC_API int bc_mesh_timeout(struct bc_mesh *m);
BC_API void bc_mesh_tick(struct bc_mesh *m);

BC_API size_t bc_mesh_peers(struct bc_mesh *m, struct bc_peer_info *out,
                            size_t max);
BC_API const char *bc_mesh_nickname(const struct bc_mesh *m);
BC_API void bc_mesh_set_nickname(struct bc_mesh *m, const char *nickname);

/* Look up a peer by nickname prefix or peer ID prefix. */
BC_API bool bc_mesh_resolve_peer(struct bc_mesh *m, const char *needle,
                                 char out[BC_PEER_ID_LEN * 2 + 1]);

#endif
