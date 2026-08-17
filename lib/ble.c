// SPDX-License-Identifier: ISC
/*
 * BLE transport over bluetoothd: a registered GATT application plus an
 * advertisement, driven from one system bus connection. Frames ride a single
 * characteristic -- writes toward a peripheral, notifications back.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <systemd/sd-bus.h>

#include "lib/internal.h"

#define BLUEZ "org.bluez"
#define ADAPTER_IFACE BLUEZ ".Adapter1"
#define DEVICE_IFACE BLUEZ ".Device1"
#define GATT_MANAGER_IFACE BLUEZ ".GattManager1"
#define ADV_MANAGER_IFACE BLUEZ ".LEAdvertisingManager1"
#define GATT_CHAR_IFACE BLUEZ ".GattCharacteristic1"
#define ADV_IFACE BLUEZ ".LEAdvertisement1"
#define SERVICE_IFACE BLUEZ ".GattService1"

#define APP_PATH "/org/bitchat"
#define SERVICE_PATH APP_PATH "/service0"
#define CHAR_PATH SERVICE_PATH "/char0"
#define ADV_PATH APP_PATH "/adv0"

#define SERVICE_UUID "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
#define CHAR_UUID "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

#define MAX_LINKS 8
#define MAX_FRAME 512
#define RETRY_COOLDOWN_MS 30000

struct bc_link {
	struct bc_ble *b;
	char device[128];
	char chr[192]; /* remote characteristic, empty in peripheral role */
	bool central;  /* we write, they notify */
	bool up;
	size_t max_frame;
	struct bc_link *next;
};

struct attempt {
	char device[128];
	int64_t last;
	unsigned fails;
	bool used;
};

/* BlueZ reports RSSI from advertising reports, so it can arrive before the
 * link exists and go stale once connected. */
struct rssi_entry {
	char device[128];
	int rssi;
	int64_t at;
	bool used;
};

/* Ties an async Connect reply back to the device it was made for. */
struct connect_ctx {
	struct bc_ble *b;
	char device[128];
};

struct bc_ble {
	sd_bus *bus;
	char adapter[64];
	struct bc_ble_ops ops;
	void *ud;

	sd_bus_slot *app_slot;
	sd_bus_slot *service_slot;
	sd_bus_slot *char_slot;
	sd_bus_slot *adv_slot;
	sd_bus_slot *added_slot;
	sd_bus_slot *changed_slot;
	sd_bus_slot *removed_slot;

	struct bc_link *links;
	size_t link_count;
	size_t connecting;
	struct attempt attempts[32];
	struct rssi_entry rssi[32];

	uint8_t value[MAX_FRAME]; /* last notified frame */
	size_t value_len;
	bool notifying;
	int64_t next_scan;
	short last_events;
};

static void blog(struct bc_ble *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void
blog(struct bc_ble *b, const char *fmt, ...)
{
	char line[256];
	va_list ap;

	if (b->ops.on_log == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	b->ops.on_log(b->ud, line);
}

static struct bc_link *link_find(struct bc_ble *b, const char *device,
                                 const char *chr);

/* Remember a device's signal strength, and pass it on if it has a link. */
static void
note_rssi(struct bc_ble *b, const char *device, int rssi)
{
	struct rssi_entry *slot = NULL;
	struct bc_link *l;
	size_t i;

	for (i = 0; i < sizeof(b->rssi) / sizeof(b->rssi[0]); i++) {
		struct rssi_entry *e = &b->rssi[i];

		if (e->used && strcmp(e->device, device) == 0) {
			slot = e;
			break;
		}
		if (!e->used && slot == NULL)
			slot = e;
	}
	if (slot != NULL) {
		slot->used = true;
		snprintf(slot->device, sizeof(slot->device), "%s", device);
		slot->rssi = rssi;
		slot->at = bc_now_ms();
	}

	blog(b, "rssi %d dBm from %s", rssi, device);

	l = link_find(b, device, NULL);
	if (l != NULL && b->ops.on_rssi != NULL)
		b->ops.on_rssi(b->ud, l, rssi);
}

static int
known_rssi(const struct bc_ble *b, const char *device)
{
	size_t i;

	for (i = 0; i < sizeof(b->rssi) / sizeof(b->rssi[0]); i++)
		if (b->rssi[i].used && strcmp(b->rssi[i].device, device) == 0)
			return b->rssi[i].rssi;
	return 0;
}

/* Tell an embedder when the poll mask changes, so it can re-arm its watch. */
static void
notify_events(struct bc_ble *b)
{
	short events;

	if (b->ops.on_events == NULL)
		return;

	events = bc_ble_events(b);
	if (events == b->last_events)
		return;
	b->last_events = events;
	b->ops.on_events(b->ud, sd_bus_get_fd(b->bus), events);
}

static bool
uuid_eq(const char *a, const char *want)
{
	return a != NULL && strcasecmp(a, want) == 0;
}

/* Strip the service and characteristic suffix to get the device path. */
static void
device_of(const char *char_path, char *out, size_t len)
{
	const char *cut = strstr(char_path, "/service");

	if (cut == NULL) {
		snprintf(out, len, "%s", char_path);
		return;
	}
	snprintf(out, len, "%.*s", (int)(cut - char_path), char_path);
}

static struct bc_link *
link_find(struct bc_ble *b, const char *device, const char *chr)
{
	struct bc_link *l;

	for (l = b->links; l != NULL; l = l->next) {
		if (chr != NULL && strcmp(l->chr, chr) == 0)
			return l;
		if (chr == NULL && strcmp(l->device, device) == 0)
			return l;
	}
	return NULL;
}

/*
 * One link per device. A peer can be both our peripheral and our central at
 * once; keeping two links would duplicate every broadcast to it.
 */
static struct bc_link *
link_add(struct bc_ble *b, const char *device, const char *chr, bool central)
{
	struct bc_link *l = link_find(b, device, NULL);

	if (l != NULL) {
		if (chr != NULL && l->chr[0] == '\0') {
			snprintf(l->chr, sizeof(l->chr), "%s", chr);
			l->central = central;
		}
		return l;
	}

	if (b->link_count >= MAX_LINKS)
		return NULL;

	l = calloc(1, sizeof(*l));
	if (l == NULL)
		return NULL;

	l->b = b;
	l->central = central;
	snprintf(l->device, sizeof(l->device), "%s", device);
	if (chr != NULL)
		snprintf(l->chr, sizeof(l->chr), "%s", chr);

	l->next = b->links;
	b->links = l;
	b->link_count++;

	l->up = true;
	blog(b, "linked with %s", device);
	if (b->ops.on_link_up != NULL)
		b->ops.on_link_up(b->ud, l);
	if (b->ops.on_rssi != NULL && known_rssi(b, device) != 0)
		b->ops.on_rssi(b->ud, l, known_rssi(b, device));
	return l;
}

static void
link_drop(struct bc_ble *b, struct bc_link *link)
{
	struct bc_link **pp;

	for (pp = &b->links; *pp != NULL; pp = &(*pp)->next) {
		if (*pp != link)
			continue;
		*pp = link->next;
		break;
	}

	if (link->up && b->ops.on_link_down != NULL)
		b->ops.on_link_down(b->ud, link);

	b->link_count--;
	free(link);
}

static void
drop_device_links(struct bc_ble *b, const char *device)
{
	struct bc_link *l, *next;

	for (l = b->links; l != NULL; l = next) {
		next = l->next;
		if (strcmp(l->device, device) == 0)
			link_drop(b, l);
	}
}

static void
deliver(struct bc_ble *b, struct bc_link *link, const uint8_t *data, size_t len)
{
	if (b->ops.on_frame != NULL)
		b->ops.on_frame(b->ud, link, data, len);
}

/* --- exported advertisement --- */

static int
adv_release(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;

	blog(b, "advertisement released by bluez");
	return sd_bus_reply_method_return(msg, "");
}

static int
adv_uuids(sd_bus *bus, const char *path, const char *iface,
          const char *property, sd_bus_message *reply, void *ud,
          sd_bus_error *err)
{
	return sd_bus_message_append_strv(
	    reply, (char *[]){(char *)SERVICE_UUID, NULL});
}

static int
adv_type(sd_bus *bus, const char *path, const char *iface, const char *property,
         sd_bus_message *reply, void *ud, sd_bus_error *err)
{
	return sd_bus_message_append(reply, "s", "peripheral");
}

static const sd_bus_vtable adv_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Release", "", "", adv_release, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("Type", "s", adv_type, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("ServiceUUIDs", "as", adv_uuids, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END,
};

/* --- exported GATT service and characteristic --- */

static int
prop_service_uuid(sd_bus *bus, const char *path, const char *iface,
                  const char *property, sd_bus_message *reply, void *ud,
                  sd_bus_error *err)
{
	return sd_bus_message_append(reply, "s", SERVICE_UUID);
}

static int
prop_primary(sd_bus *bus, const char *path, const char *iface,
             const char *property, sd_bus_message *reply, void *ud,
             sd_bus_error *err)
{
	return sd_bus_message_append(reply, "b", 1);
}

static const sd_bus_vtable service_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("UUID", "s", prop_service_uuid, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Primary", "b", prop_primary, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END,
};

static int
prop_char_uuid(sd_bus *bus, const char *path, const char *iface,
               const char *property, sd_bus_message *reply, void *ud,
               sd_bus_error *err)
{
	return sd_bus_message_append(reply, "s", CHAR_UUID);
}

static int
prop_char_service(sd_bus *bus, const char *path, const char *iface,
                  const char *property, sd_bus_message *reply, void *ud,
                  sd_bus_error *err)
{
	return sd_bus_message_append(reply, "o", SERVICE_PATH);
}

static int
prop_char_flags(sd_bus *bus, const char *path, const char *iface,
                const char *property, sd_bus_message *reply, void *ud,
                sd_bus_error *err)
{
	return sd_bus_message_append_strv(
	    reply,
	    (char *[]){"write", "write-without-response", "notify", NULL});
}

static int
prop_char_value(sd_bus *bus, const char *path, const char *iface,
                const char *property, sd_bus_message *reply, void *ud,
                sd_bus_error *err)
{
	struct bc_ble *b = ud;

	return sd_bus_message_append_array(reply, 'y', b->value, b->value_len);
}

static int
prop_char_notifying(sd_bus *bus, const char *path, const char *iface,
                    const char *property, sd_bus_message *reply, void *ud,
                    sd_bus_error *err)
{
	struct bc_ble *b = ud;

	return sd_bus_message_append(reply, "b", b->notifying ? 1 : 0);
}

static int
char_read_value(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;
	sd_bus_message *reply = NULL;
	int r;

	r = sd_bus_message_new_method_return(msg, &reply);
	if (r < 0)
		return r;
	r = sd_bus_message_append_array(reply, 'y', b->value, b->value_len);
	if (r < 0)
		return r;
	r = sd_bus_send(NULL, reply, NULL);
	sd_bus_message_unref(reply);
	return r;
}

/* A remote central wrote a frame to our characteristic. */
static int
char_write_value(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;
	struct bc_link *link;
	const void *data = NULL;
	char device[128] = "";
	size_t len = 0;
	int r;

	r = sd_bus_message_read_array(msg, 'y', &data, &len);
	if (r < 0)
		return r;

	/* Options carry the writing device path. */
	r = sd_bus_message_enter_container(msg, 'a', "{sv}");
	if (r >= 0) {
		while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
			const char *key = NULL;

			if (sd_bus_message_read(msg, "s", &key) < 0)
				break;
			if (key != NULL && strcmp(key, "device") == 0) {
				const char *path = NULL;

				if (sd_bus_message_read(msg, "v", "o", &path) >=
				        0 &&
				    path != NULL)
					snprintf(device, sizeof(device), "%s",
					         path);
			} else {
				sd_bus_message_skip(msg, "v");
			}
			sd_bus_message_exit_container(msg);
		}
		sd_bus_message_exit_container(msg);
	}

	if (device[0] == '\0')
		snprintf(device, sizeof(device), "unknown");

	link = link_find(b, device, NULL);
	if (link == NULL)
		link = link_add(b, device, NULL, false);
	if (link != NULL && len > 0)
		deliver(b, link, data, len);

	return sd_bus_reply_method_return(msg, "");
}

static int
char_start_notify(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;

	b->notifying = true;
	return sd_bus_reply_method_return(msg, "");
}

static int
char_stop_notify(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;

	b->notifying = false;
	return sd_bus_reply_method_return(msg, "");
}

static const sd_bus_vtable char_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("ReadValue", "a{sv}", "ay", char_read_value,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("WriteValue", "aya{sv}", "", char_write_value,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("StartNotify", "", "", char_start_notify,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("StopNotify", "", "", char_stop_notify,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("UUID", "s", prop_char_uuid, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Service", "o", prop_char_service, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Flags", "as", prop_char_flags, 0,
                    SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Notifying", "b", prop_char_notifying, 0,
                    SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_PROPERTY("Value", "ay", prop_char_value, 0,
                    SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
    SD_BUS_VTABLE_END,
};

/* --- discovery --- */

static struct attempt *
attempt_for(struct bc_ble *b, const char *device)
{
	struct attempt *slot = NULL;
	size_t i;

	for (i = 0; i < sizeof(b->attempts) / sizeof(b->attempts[0]); i++) {
		struct attempt *a = &b->attempts[i];

		if (a->used && strcmp(a->device, device) == 0)
			return a;
		if (!a->used && slot == NULL)
			slot = a;
	}
	if (slot == NULL)
		return NULL;
	slot->used = true;
	slot->last = 0;
	snprintf(slot->device, sizeof(slot->device), "%s", device);
	return slot;
}

static struct attempt *attempt_for(struct bc_ble *b, const char *device);

static int
connect_done(sd_bus_message *reply, void *ud, sd_bus_error *err)
{
	struct connect_ctx *ctx = ud;
	const sd_bus_error *e = sd_bus_message_get_error(reply);
	struct attempt *a;

	if (ctx->b->connecting > 0)
		ctx->b->connecting--;

	a = attempt_for(ctx->b, ctx->device);
	if (e != NULL && e->message != NULL) {
		blog(ctx->b, "connect failed: %s", e->message);
		if (a != NULL && a->fails < 8)
			a->fails++;
	} else if (a != NULL) {
		a->fails = 0;
	}

	free(ctx);
	return 0;
}

/* Back off per device: a phone that refuses now tends to refuse again. */
static int64_t
retry_delay(const struct attempt *a)
{
	unsigned shift = a->fails > 3 ? 3 : a->fails;

	return (int64_t)RETRY_COOLDOWN_MS << shift;
}

static void
try_connect(struct bc_ble *b, const char *device)
{
	struct attempt *a = attempt_for(b, device);
	struct connect_ctx *ctx;
	int64_t now = bc_now_ms();

	if (b->link_count >= MAX_LINKS)
		return;
	if (a == NULL || now - a->last < retry_delay(a))
		return;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return;
	ctx->b = b;
	snprintf(ctx->device, sizeof(ctx->device), "%s", device);

	a->last = now;
	b->connecting++;
	if (sd_bus_call_method_async(b->bus, NULL, BLUEZ, device, DEVICE_IFACE,
	                             "Connect", connect_done, ctx, NULL) < 0) {
		b->connecting--;
		free(ctx);
	}
}

/* An ATT write carries the opcode and the handle before the value. */
#define ATT_WRITE_OVERHEAD 3

struct mtu_ctx {
	struct bc_ble *b;
	char chr[192];
};

static void report_mtu(struct bc_ble *b, struct bc_link *l, uint16_t mtu);

/*
 * BlueZ fills in the MTU once the link is negotiated, which is usually after
 * the characteristic object appears, so ask for it rather than wait.
 */
static int
mtu_done(sd_bus_message *reply, void *ud, sd_bus_error *ret_error)
{
	struct mtu_ctx *ctx = ud;
	uint16_t mtu = 0;
	char device[128];

	if (sd_bus_message_get_error(reply) == NULL &&
	    sd_bus_message_read(reply, "v", "q", &mtu) >= 0) {
		device_of(ctx->chr, device, sizeof(device));
		report_mtu(ctx->b, link_find(ctx->b, device, ctx->chr), mtu);
	}
	free(ctx);
	return 0;
}

static void
ask_mtu(struct bc_ble *b, const char *char_path)
{
	struct mtu_ctx *ctx = calloc(1, sizeof(*ctx));

	if (ctx == NULL)
		return;
	ctx->b = b;
	snprintf(ctx->chr, sizeof(ctx->chr), "%s", char_path);

	if (sd_bus_call_method_async(b->bus, NULL, BLUEZ, char_path,
	                             "org.freedesktop.DBus.Properties", "Get",
	                             mtu_done, ctx, "ss", GATT_CHAR_IFACE,
	                             "MTU") < 0)
		free(ctx);
}

static void
report_mtu(struct bc_ble *b, struct bc_link *l, uint16_t mtu)
{
	size_t max_frame;

	if (mtu <= ATT_WRITE_OVERHEAD || l == NULL)
		return;

	/* BlueZ re-reports the same value on every rescan; say it once. */
	max_frame = (size_t)(mtu - ATT_WRITE_OVERHEAD);
	if (l->max_frame == max_frame)
		return;
	l->max_frame = max_frame;

	blog(b, "link mtu %u", mtu);
	if (b->ops.on_mtu != NULL)
		b->ops.on_mtu(b->ud, l, max_frame);
}

static void
subscribe_char(struct bc_ble *b, const char *char_path, uint16_t mtu)
{
	struct bc_link *l;
	char device[128];

	device_of(char_path, device, sizeof(device));
	l = link_find(b, device, char_path);
	if (l != NULL) {
		report_mtu(b, l, mtu);
		return;
	}

	sd_bus_call_method_async(b->bus, NULL, BLUEZ, char_path,
	                         GATT_CHAR_IFACE, "StartNotify", NULL, NULL,
	                         NULL);

	report_mtu(b, link_add(b, device, char_path, true), mtu);
	if (mtu == 0)
		ask_mtu(b, char_path);
}

/*
 * True when the dictionary advertises our service UUID. Any RSSI seen along
 * the way is recorded: it rides the same property set.
 */
static bool
props_have_service(struct bc_ble *b, const char *path, sd_bus_message *msg)
{
	bool found = false;

	if (sd_bus_message_enter_container(msg, 'a', "{sv}") < 0)
		return false;

	while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
		const char *key = NULL;

		if (sd_bus_message_read(msg, "s", &key) < 0)
			break;
		if (key != NULL && strcmp(key, "RSSI") == 0) {
			int16_t rssi = 0;

			if (sd_bus_message_read(msg, "v", "n", &rssi) >= 0 &&
			    rssi != 0)
				note_rssi(b, path, rssi);
		} else if (key != NULL && strcmp(key, "UUIDs") == 0) {
			if (sd_bus_message_enter_container(msg, 'v', "as") >=
			    0) {
				const char *uuid = NULL;

				if (sd_bus_message_enter_container(msg, 'a',
				                                   "s") >= 0) {
					while (sd_bus_message_read(msg, "s",
					                           &uuid) > 0)
						if (uuid_eq(uuid, SERVICE_UUID))
							found = true;
					sd_bus_message_exit_container(msg);
				}
				sd_bus_message_exit_container(msg);
			}
		} else {
			sd_bus_message_skip(msg, "v");
		}
		sd_bus_message_exit_container(msg);
	}
	sd_bus_message_exit_container(msg);
	return found;
}

/* Read the UUID out of a characteristic dictionary, and its MTU if present. */
static bool
props_char_uuid(sd_bus_message *msg, char *out, size_t len, uint16_t *mtu)
{
	bool found = false;

	if (sd_bus_message_enter_container(msg, 'a', "{sv}") < 0)
		return false;

	while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
		const char *key = NULL;

		if (sd_bus_message_read(msg, "s", &key) < 0)
			break;
		if (key != NULL && strcmp(key, "UUID") == 0) {
			const char *uuid = NULL;

			if (sd_bus_message_read(msg, "v", "s", &uuid) >= 0 &&
			    uuid != NULL) {
				snprintf(out, len, "%s", uuid);
				found = true;
			}
		} else if (key != NULL && strcmp(key, "MTU") == 0) {
			uint16_t value = 0;

			if (sd_bus_message_read(msg, "v", "q", &value) >= 0)
				*mtu = value;
		} else {
			sd_bus_message_skip(msg, "v");
		}
		sd_bus_message_exit_container(msg);
	}
	sd_bus_message_exit_container(msg);
	return found;
}

static int
on_interfaces_added(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;
	const char *path = NULL;
	int r;

	r = sd_bus_message_read(msg, "o", &path);
	if (r < 0 || path == NULL)
		return 0;

	r = sd_bus_message_enter_container(msg, 'a', "{sa{sv}}");
	if (r < 0)
		return 0;

	while (sd_bus_message_enter_container(msg, 'e', "sa{sv}") > 0) {
		const char *iface = NULL;

		if (sd_bus_message_read(msg, "s", &iface) < 0)
			break;

		if (iface != NULL && strcmp(iface, DEVICE_IFACE) == 0) {
			if (props_have_service(b, path, msg))
				try_connect(b, path);
		} else if (iface != NULL &&
		           strcmp(iface, GATT_CHAR_IFACE) == 0) {
			char uuid[64] = "";
			uint16_t mtu = 0;

			if (props_char_uuid(msg, uuid, sizeof(uuid), &mtu) &&
			    uuid_eq(uuid, CHAR_UUID))
				subscribe_char(b, path, mtu);
		} else {
			sd_bus_message_skip(msg, "a{sv}");
		}
		sd_bus_message_exit_container(msg);
	}
	sd_bus_message_exit_container(msg);
	return 0;
}

static int
on_interfaces_removed(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;
	const char *path = NULL;
	struct bc_link *l, *next;

	if (sd_bus_message_read(msg, "o", &path) < 0 || path == NULL)
		return 0;

	for (l = b->links; l != NULL; l = next) {
		next = l->next;
		if (strcmp(l->device, path) == 0 || strcmp(l->chr, path) == 0)
			link_drop(b, l);
	}
	return 0;
}

static int
on_properties_changed(sd_bus_message *msg, void *ud, sd_bus_error *err)
{
	struct bc_ble *b = ud;
	const char *path = sd_bus_message_get_path(msg);
	const char *iface = NULL;

	if (path == NULL || sd_bus_message_read(msg, "s", &iface) < 0 ||
	    iface == NULL)
		return 0;

	if (strcmp(iface, DEVICE_IFACE) == 0) {
		bool disconnected = false;

		if (sd_bus_message_enter_container(msg, 'a', "{sv}") < 0)
			return 0;
		while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
			const char *key = NULL;

			if (sd_bus_message_read(msg, "s", &key) < 0)
				break;
			if (key != NULL && strcmp(key, "Connected") == 0) {
				int on = 0;

				if (sd_bus_message_read(msg, "v", "b", &on) >=
				        0 &&
				    !on)
					disconnected = true;
			} else if (key != NULL && strcmp(key, "RSSI") == 0) {
				int16_t rssi = 0;

				if (sd_bus_message_read(msg, "v", "n", &rssi) >=
				        0 &&
				    rssi != 0)
					note_rssi(b, path, rssi);
			} else {
				sd_bus_message_skip(msg, "v");
			}
			sd_bus_message_exit_container(msg);
		}
		sd_bus_message_exit_container(msg);

		if (disconnected)
			drop_device_links(b, path);
		return 0;
	}

	if (strcmp(iface, GATT_CHAR_IFACE) != 0)
		return 0;

	if (sd_bus_message_enter_container(msg, 'a', "{sv}") < 0)
		return 0;

	while (sd_bus_message_enter_container(msg, 'e', "sv") > 0) {
		const char *key = NULL;

		if (sd_bus_message_read(msg, "s", &key) < 0)
			break;
		if (key != NULL && strcmp(key, "MTU") == 0) {
			uint16_t mtu = 0;
			char device[128];

			if (sd_bus_message_read(msg, "v", "q", &mtu) >= 0) {
				device_of(path, device, sizeof(device));
				report_mtu(b, link_find(b, device, path), mtu);
			}
		} else if (key != NULL && strcmp(key, "Value") == 0) {
			const void *data = NULL;
			size_t len = 0;

			if (sd_bus_message_enter_container(msg, 'v', "ay") >=
			    0) {
				if (sd_bus_message_read_array(msg, 'y', &data,
				                              &len) >= 0) {
					char device[128];
					struct bc_link *link;

					device_of(path, device, sizeof(device));
					link = link_find(b, device, path);
					if (link == NULL)
						link = link_add(b, device, path,
						                true);
					if (link != NULL && len > 0)
						deliver(b, link, data, len);
				}
				sd_bus_message_exit_container(msg);
			}
		} else {
			sd_bus_message_skip(msg, "v");
		}
		sd_bus_message_exit_container(msg);
	}
	sd_bus_message_exit_container(msg);
	return 0;
}

/*
 * Walk what BlueZ already knows about. Async throughout: an embedder's event
 * loop must never stall on the daemon.
 */
static int
managed_objects_done(sd_bus_message *reply, void *ud, sd_bus_error *ret_error)
{
	struct bc_ble *b = ud;
	const sd_bus_error *e = sd_bus_message_get_error(reply);

	if (e != NULL) {
		blog(b, "GetManagedObjects: %s",
		     e->message ? e->message : "failed");
		return 0;
	}

	if (sd_bus_message_enter_container(reply, 'a', "{oa{sa{sv}}}") < 0)
		return 0;

	while (sd_bus_message_enter_container(reply, 'e', "oa{sa{sv}}") > 0) {
		const char *path = NULL;

		if (sd_bus_message_read(reply, "o", &path) < 0)
			break;
		if (sd_bus_message_enter_container(reply, 'a', "{sa{sv}}") < 0)
			break;

		while (sd_bus_message_enter_container(reply, 'e', "sa{sv}") >
		       0) {
			const char *iface = NULL;

			if (sd_bus_message_read(reply, "s", &iface) < 0)
				break;
			if (iface != NULL && strcmp(iface, DEVICE_IFACE) == 0) {
				if (props_have_service(b, path, reply))
					try_connect(b, path);
			} else if (iface != NULL &&
			           strcmp(iface, GATT_CHAR_IFACE) == 0) {
				char uuid[64] = "";
				uint16_t mtu = 0;

				if (props_char_uuid(reply, uuid, sizeof(uuid),
				                    &mtu) &&
				    uuid_eq(uuid, CHAR_UUID))
					subscribe_char(b, path, mtu);
			} else {
				sd_bus_message_skip(reply, "a{sv}");
			}
			sd_bus_message_exit_container(reply);
		}
		sd_bus_message_exit_container(reply);
		sd_bus_message_exit_container(reply);
	}
	sd_bus_message_exit_container(reply);
	return 0;
}

static void
seed_from_managed_objects(struct bc_ble *b)
{
	sd_bus_call_method_async(
	    b->bus, NULL, BLUEZ, "/", "org.freedesktop.DBus.ObjectManager",
	    "GetManagedObjects", managed_objects_done, b, "");
}

/* InProgress just means discovery is already running, which is fine. */
static int
discovery_done(sd_bus_message *reply, void *ud, sd_bus_error *ret_error)
{
	struct bc_ble *b = ud;
	const sd_bus_error *e = sd_bus_message_get_error(reply);

	if (e == NULL || e->name == NULL)
		return 0;
	if (strcmp(e->name, "org.bluez.Error.InProgress") == 0)
		return 0;
	blog(b, "discovery: %s", e->message ? e->message : e->name);
	return 0;
}

static int
start_discovery(struct bc_ble *b)
{
	sd_bus_message *call = NULL;
	int r;

	r = sd_bus_message_new_method_call(b->bus, &call, BLUEZ, b->adapter,
	                                   ADAPTER_IFACE, "SetDiscoveryFilter");
	if (r < 0)
		return r;

	r = sd_bus_message_open_container(call, 'a', "{sv}");
	if (r < 0)
		goto out;
	r = sd_bus_message_append(call, "{sv}", "Transport", "s", "le");
	if (r < 0)
		goto out;
	r = sd_bus_message_open_container(call, 'e', "sv");
	if (r < 0)
		goto out;
	sd_bus_message_append(call, "s", "UUIDs");
	sd_bus_message_open_container(call, 'v', "as");
	sd_bus_message_append_strv(call,
	                           (char *[]){(char *)SERVICE_UUID, NULL});
	sd_bus_message_close_container(call);
	sd_bus_message_close_container(call);
	r = sd_bus_message_close_container(call);
	if (r < 0)
		goto out;

	r = sd_bus_call_async(b->bus, NULL, call, discovery_done, b, 0);
	if (r < 0)
		goto out;

	r = sd_bus_call_method_async(b->bus, NULL, BLUEZ, b->adapter,
	                             ADAPTER_IFACE, "StartDiscovery",
	                             discovery_done, b, "");
out:
	sd_bus_message_unref(call);
	return r < 0 ? r : 0;
}

static int
register_done(sd_bus_message *reply, void *ud, sd_bus_error *err)
{
	const sd_bus_error *e = sd_bus_message_get_error(reply);

	if (e != NULL && e->message != NULL) {
		struct bc_ble *b = ud;

		blog(b, "bluez registration failed: %s", e->message);
	}
	return 0;
}

static int
register_objects(struct bc_ble *b)
{
	int r;

	r = sd_bus_add_object_manager(b->bus, &b->app_slot, APP_PATH);
	if (r < 0)
		return r;

	r = sd_bus_add_object_vtable(b->bus, &b->service_slot, SERVICE_PATH,
	                             SERVICE_IFACE, service_vtable, b);
	if (r < 0)
		return r;

	r = sd_bus_add_object_vtable(b->bus, &b->char_slot, CHAR_PATH,
	                             GATT_CHAR_IFACE, char_vtable, b);
	if (r < 0)
		return r;

	r = sd_bus_add_object_vtable(b->bus, &b->adv_slot, ADV_PATH, ADV_IFACE,
	                             adv_vtable, b);
	if (r < 0)
		return r;

	/*
	 * Async on purpose: BlueZ calls back into our object manager while
	 * it processes these, and a blocking call would deadlock.
	 */
	r = sd_bus_call_method_async(b->bus, NULL, BLUEZ, b->adapter,
	                             GATT_MANAGER_IFACE, "RegisterApplication",
	                             register_done, b, "oa{sv}", APP_PATH, 0);
	if (r < 0)
		return r;

	r = sd_bus_call_method_async(b->bus, NULL, BLUEZ, b->adapter,
	                             ADV_MANAGER_IFACE, "RegisterAdvertisement",
	                             register_done, b, "oa{sv}", ADV_PATH, 0);
	if (r < 0)
		return r;

	return 0;
}

int
bc_ble_new(struct bc_ble **ret, int hci_index, const struct bc_ble_ops *ops,
           void *ud)
{
	struct bc_ble *b;
	int r;

	ASSERT_RETURN(ret != NULL && ops != NULL, -EINVAL);

	b = calloc(1, sizeof(*b));
	if (b == NULL)
		return -ENOMEM;

	b->ops = *ops;
	b->ud = ud;
	snprintf(b->adapter, sizeof(b->adapter), "/org/bluez/hci%d",
	         hci_index >= 0 ? hci_index : 0);

	r = sd_bus_open_system(&b->bus);
	if (r < 0) {
		free(b);
		return r;
	}

	r = sd_bus_call_method_async(
	    b->bus, NULL, BLUEZ, b->adapter, "org.freedesktop.DBus.Properties",
	    "Set", register_done, b, "ssv", ADAPTER_IFACE, "Powered", "b", 1);
	if (r < 0) {
		blog(b, "cannot power the adapter: %s", strerror(-r));
		sd_bus_unref(b->bus);
		free(b);
		return r;
	}

	r = register_objects(b);
	if (r < 0) {
		bc_ble_free(b);
		return r;
	}

	sd_bus_match_signal(b->bus, &b->added_slot, BLUEZ, NULL,
	                    "org.freedesktop.DBus.ObjectManager",
	                    "InterfacesAdded", on_interfaces_added, b);
	sd_bus_match_signal(b->bus, &b->removed_slot, BLUEZ, NULL,
	                    "org.freedesktop.DBus.ObjectManager",
	                    "InterfacesRemoved", on_interfaces_removed, b);
	sd_bus_match_signal(b->bus, &b->changed_slot, BLUEZ, NULL,
	                    "org.freedesktop.DBus.Properties",
	                    "PropertiesChanged", on_properties_changed, b);

	start_discovery(b);
	seed_from_managed_objects(b);

	b->last_events = bc_ble_events(b);
	*ret = b;
	return 0;
}

void
bc_ble_free(struct bc_ble *b)
{
	if (b == NULL)
		return;

	while (b->links != NULL)
		link_drop(b, b->links);

	if (b->bus != NULL) {
		sd_bus_call_method(b->bus, BLUEZ, b->adapter, ADV_MANAGER_IFACE,
		                   "UnregisterAdvertisement", NULL, NULL, "o",
		                   ADV_PATH);
		sd_bus_call_method(b->bus, BLUEZ, b->adapter,
		                   GATT_MANAGER_IFACE, "UnregisterApplication",
		                   NULL, NULL, "o", APP_PATH);
		sd_bus_call_method(b->bus, BLUEZ, b->adapter, ADAPTER_IFACE,
		                   "StopDiscovery", NULL, NULL, "");
	}

	sd_bus_slot_unref(b->added_slot);
	sd_bus_slot_unref(b->removed_slot);
	sd_bus_slot_unref(b->changed_slot);
	sd_bus_slot_unref(b->adv_slot);
	sd_bus_slot_unref(b->char_slot);
	sd_bus_slot_unref(b->service_slot);
	sd_bus_slot_unref(b->app_slot);
	sd_bus_unref(b->bus);
	free(b);
}

/* Newest sighting first, so a caller can print the list as it stands. */
size_t
bc_ble_rssi(const struct bc_ble *b, struct bc_rssi_info *out, size_t max)
{
	int64_t now;
	size_t n = 0, i, j;

	if (b == NULL || out == NULL)
		return 0;
	now = bc_now_ms();

	for (i = 0; i < sizeof(b->rssi) / sizeof(b->rssi[0]) && n < max; i++) {
		const struct rssi_entry *e = &b->rssi[i];
		const char *leaf;

		if (!e->used)
			continue;
		leaf = strrchr(e->device, '/');
		leaf = leaf != NULL ? leaf + 1 : e->device;
		if (strncmp(leaf, "dev_", 4) == 0)
			leaf += 4;

		snprintf(out[n].address, sizeof(out[n].address), "%.*s",
		         (int)sizeof(out[n].address) - 1, leaf);
		out[n].rssi = e->rssi;
		out[n].age_ms = now - e->at;
		n++;
	}

	/* Insertion sort: the table is small and this keeps the list stable. */
	for (i = 1; i < n; i++) {
		struct bc_rssi_info tmp = out[i];

		for (j = i; j > 0 && out[j - 1].age_ms > tmp.age_ms; j--)
			out[j] = out[j - 1];
		out[j] = tmp;
	}
	return n;
}

int
bc_ble_fd(const struct bc_ble *b)
{
	return b != NULL ? sd_bus_get_fd(b->bus) : -1;
}

short
bc_ble_events(struct bc_ble *b)
{
	int events;

	if (b == NULL)
		return 0;
	events = sd_bus_get_events(b->bus);
	return events < 0 ? 0 : (short)events;
}

size_t
bc_ble_pollfds(struct bc_ble *b, struct pollfd *fds, size_t max)
{
	if (b == NULL || fds == NULL || max < 1)
		return 0;

	fds[0].fd = bc_ble_fd(b);
	fds[0].events = bc_ble_events(b);
	fds[0].revents = 0;
	return fds[0].fd < 0 ? 0 : 1;
}

void
bc_ble_dispatch(struct bc_ble *b, const struct pollfd *fds, size_t n)
{
	if (b == NULL)
		return;
	while (sd_bus_process(b->bus, NULL) > 0)
		;
	notify_events(b);
}

int
bc_ble_timeout(struct bc_ble *b)
{
	uint64_t usec = 0;

	if (b == NULL || sd_bus_get_timeout(b->bus, &usec) < 0)
		return 1000;
	if (usec == UINT64_MAX)
		return 1000;
	if (usec / 1000 > 1000)
		return 1000;
	return (int)(usec / 1000);
}

void
bc_ble_tick(struct bc_ble *b)
{
	int64_t now;

	if (b == NULL)
		return;

	now = bc_now_ms();
	notify_events(b);
	if (now < b->next_scan)
		return;
	b->next_scan = now + 10000;

	/*
	 * Discovery stops itself after a while, so it is restarted here --
	 * but never while a Connect is outstanding, which the controller
	 * answers with br-connection-busy.
	 */
	if (b->link_count < MAX_LINKS && b->connecting == 0) {
		start_discovery(b);
		seed_from_managed_objects(b);
	}
}

int
bc_ble_send(struct bc_ble *b, void *link, const uint8_t *frame, size_t len)
{
	struct bc_link *l = link;
	sd_bus_message *call = NULL;
	int r;

	ASSERT_RETURN(b != NULL && l != NULL && frame != NULL, -EINVAL);

	if (len > MAX_FRAME)
		return -EMSGSIZE;

	if (!l->central) {
		/* Peripheral role: notify every subscribed central. */
		if (!b->notifying)
			return -ENOTCONN;
		memcpy(b->value, frame, len);
		b->value_len = len;
		return sd_bus_emit_properties_changed(
		    b->bus, CHAR_PATH, GATT_CHAR_IFACE, "Value", NULL);
	}

	r = sd_bus_message_new_method_call(b->bus, &call, BLUEZ, l->chr,
	                                   GATT_CHAR_IFACE, "WriteValue");
	if (r < 0)
		return r;

	r = sd_bus_message_append_array(call, 'y', frame, len);
	if (r < 0)
		goto out;
	r = sd_bus_message_open_container(call, 'a', "{sv}");
	if (r < 0)
		goto out;
	r = sd_bus_message_append(call, "{sv}", "type", "s", "command");
	if (r < 0)
		goto out;
	r = sd_bus_message_close_container(call);
	if (r < 0)
		goto out;

	r = sd_bus_call_async(b->bus, NULL, call, NULL, NULL, 0);
out:
	sd_bus_message_unref(call);
	return r < 0 ? r : 0;
}

int
bc_ble_broadcast(struct bc_ble *b, const void *except, const uint8_t *frame,
                 size_t len)
{
	struct bc_link *l;
	bool notified = false;
	int sent = 0;

	ASSERT_RETURN(b != NULL && frame != NULL, -EINVAL);

	for (l = b->links; l != NULL; l = l->next) {
		if (l == except)
			continue;
		if (!l->central) {
			/* One notification reaches every central at once. */
			if (notified)
				continue;
			notified = true;
		}
		if (bc_ble_send(b, l, frame, len) == 0)
			sent++;
	}
	return sent;
}

size_t
bc_ble_link_count(const struct bc_ble *b)
{
	return b != NULL ? b->link_count : 0;
}
