// SPDX-License-Identifier: ISC
/*
 * BLE transport. Scan and advertise over a raw HCI socket; the GATT link is a
 * minimal ATT client and server on L2CAP CID 4.
 *
 * bluetoothd must not own the adapter: it serves ATT on the same channel.
 */
#ifndef BITCHAT_BLE_H
#define BITCHAT_BLE_H

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bitchat/export.h"

struct bc_ble;

struct bc_ble_ops {
	void (*on_link_up)(void *ud, void *link);
	void (*on_link_down)(void *ud, void *link);
	void (*on_frame)(void *ud, void *link, const uint8_t *frame,
	                 size_t len);
	/* Signal strength for a link, in dBm, as BlueZ reports it. */
	void (*on_rssi)(void *ud, void *link, int rssi);
	void (*on_log)(void *ud, const char *line);
	/*
	 * The descriptor to watch, or the events wanted on it, changed.
	 * Loops that arm a watch once (weechat, glib) re-arm here; a
	 * poll(2) loop can ignore this and call bc_ble_pollfds each turn.
	 */
	void (*on_events)(void *ud, int fd, short events);
};

BC_API int bc_ble_new(struct bc_ble **ret, int hci_index,
                      const struct bc_ble_ops *ops, void *ud);
BC_API void bc_ble_free(struct bc_ble *b);

/* Fill fds with the descriptors to poll. Returns the count used. */
BC_API size_t bc_ble_pollfds(struct bc_ble *b, struct pollfd *fds, size_t max);
BC_API void bc_ble_dispatch(struct bc_ble *b, const struct pollfd *fds,
                            size_t n);
BC_API int bc_ble_timeout(struct bc_ble *b);
BC_API void bc_ble_tick(struct bc_ble *b);

/* Queue one frame on a link, or on every link but except. */
BC_API int bc_ble_send(struct bc_ble *b, void *link, const uint8_t *frame,
                       size_t len);
BC_API int bc_ble_broadcast(struct bc_ble *b, const void *except,
                            const uint8_t *frame, size_t len);

/*
 * Signal strength as last seen from a device advertising our service. BlueZ
 * reports RSSI from advertising only, and BitChat peers advertise under a
 * rotating address, so these are sightings rather than per-peer readings.
 */
struct bc_rssi_info {
	char address[24]; /* the BlueZ device path leaf, MAC-like */
	int rssi;
	int64_t age_ms;
};

BC_API size_t bc_ble_rssi(const struct bc_ble *b, struct bc_rssi_info *out,
                          size_t max);

/* The single descriptor this transport runs on, and what it wants on it. */
BC_API int bc_ble_fd(const struct bc_ble *b);
BC_API short bc_ble_events(struct bc_ble *b);

BC_API size_t bc_ble_link_count(const struct bc_ble *b);

#endif
