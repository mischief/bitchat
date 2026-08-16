// SPDX-License-Identifier: ISC
/*
 * A socket transport carrying the same frames as the radio, so a mesh can run
 * without Bluetooth. Frames are length-prefixed: two bytes big endian, then
 * the frame.
 */
#ifndef BITCHAT_TCP_H
#define BITCHAT_TCP_H

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bitchat/export.h"

struct bc_tcp;

struct bc_tcp_ops {
	void (*on_link_up)(void *ud, void *link);
	void (*on_link_down)(void *ud, void *link);
	void (*on_frame)(void *ud, void *link, const uint8_t *frame,
	                 size_t len);
	void (*on_log)(void *ud, const char *line);
};

/* Listen on port, or pass 0 for an outbound-only node. */
BC_API int bc_tcp_new(struct bc_tcp **ret, uint16_t port,
                      const struct bc_tcp_ops *ops, void *ud);
BC_API void bc_tcp_free(struct bc_tcp *t);

/* Open a link to another node. Reconnects on its own if it drops. */
BC_API int bc_tcp_connect(struct bc_tcp *t, const char *host, uint16_t port);

/* The port actually bound, useful when the caller asked for any. */
BC_API uint16_t bc_tcp_port(const struct bc_tcp *t);

BC_API size_t bc_tcp_pollfds(struct bc_tcp *t, struct pollfd *fds, size_t max);
BC_API void bc_tcp_dispatch(struct bc_tcp *t, const struct pollfd *fds,
                            size_t n);
BC_API int bc_tcp_timeout(const struct bc_tcp *t);
BC_API void bc_tcp_tick(struct bc_tcp *t);

BC_API int bc_tcp_send(struct bc_tcp *t, void *link, const uint8_t *frame,
                       size_t len);
BC_API int bc_tcp_broadcast(struct bc_tcp *t, const void *except,
                            const uint8_t *frame, size_t len);

BC_API size_t bc_tcp_link_count(const struct bc_tcp *t);

#endif
