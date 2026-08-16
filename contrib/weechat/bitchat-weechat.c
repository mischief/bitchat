// SPDX-License-Identifier: ISC
/*
 * WeeChat plugin: a bitchat buffer backed by libbitchat. The transport's
 * wanted events change as the bus queues writes, so the fd hook is re-armed
 * from the on_events callback.
 */
#include <errno.h>
#include <stdbool.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <weechat/weechat-plugin.h>

#include "bitchat/ble.h"
#include "bitchat/identity.h"
#include "bitchat/mesh.h"
#include "bitchat/packet.h"
#include "bitchat/tlv.h"

WEECHAT_PLUGIN_NAME("bitchat")
WEECHAT_PLUGIN_DESCRIPTION("BitChat Bluetooth mesh chat")
WEECHAT_PLUGIN_AUTHOR("Nick Owens <mischief@offblast.org>")
WEECHAT_PLUGIN_VERSION("0.1")
WEECHAT_PLUGIN_LICENSE("ISC")

struct t_weechat_plugin *weechat_plugin = NULL;

static struct bc_mesh *mesh;
static struct bc_ble *ble;
static struct bc_identity identity;
static struct t_gui_buffer *buffer;
static struct t_hook *fd_hook;
static struct t_hook *timer_hook;
static char peer_hex[BC_PEER_ID_LEN * 2 + 1];
static bool debug;
static short want_events;
static short armed_events;

static void say(const char *prefix, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void
say(const char *prefix, const char *fmt, ...)
{
	char line[1024];
	va_list ap;

	if (buffer == NULL)
		return;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	weechat_printf(buffer, "%s%s", prefix, line);
}

/* --- library callbacks --- */

static void
on_public(void *ud, const char *peer_id, const char *nick, const char *text,
          uint64_t timestamp)
{
	bool mine = bc_mentions(text, bc_mesh_nickname(mesh));

	weechat_printf_date_tags(buffer, (time_t)(timestamp / 1000),
	                         mine ? "notify_highlight" : "notify_message",
	                         "%s%s\t%s", mine ? weechat_color("red") : "",
	                         nick, text);
}

static void
on_private(void *ud, const char *peer_id, const char *nick, const char *text,
           uint64_t timestamp)
{
	weechat_printf_date_tags(buffer, (time_t)(timestamp / 1000),
	                         "notify_private", "%s[%s]\t%s",
	                         weechat_color("magenta"), nick, text);
}

static void
on_peer(void *ud, const char *peer_id, const char *nick, bool joined)
{
	say(weechat_prefix(joined ? "join" : "quit"), "%s (%.8s)", nick,
	    peer_id);
}

static void
on_receipt(void *ud, const char *peer_id, const char *nick,
           const char *message_id, bool read)
{
	say(weechat_prefix("network"), "%s %s a message", nick,
	    read ? "read" : "received");
}

static void
on_log(void *ud, const char *line)
{
	if (debug)
		say(weechat_prefix("network"), "%s", line);
}

static void
mesh_send(void *ud, void *link, const uint8_t *frame, size_t len)
{
	bc_ble_send(ble, link, frame, len);
}

static void
mesh_broadcast(void *ud, void *except, const uint8_t *frame, size_t len)
{
	bc_ble_broadcast(ble, except, frame, len);
}

static void
ble_link_up(void *ud, void *link)
{
	bc_mesh_link_up(mesh, link);
}

static void
ble_link_down(void *ud, void *link)
{
	bc_mesh_link_down(mesh, link);
}

static void
ble_mtu(void *ud, void *link, size_t max_frame)
{
	bc_mesh_set_link_mtu(mesh, link, max_frame);
}

static void
ble_rssi(void *ud, void *link, int rssi)
{
	bc_mesh_link_rssi(mesh, link, rssi);
}

static void
ble_frame(void *ud, void *link, const uint8_t *frame, size_t len)
{
	bc_mesh_recv(mesh, link, frame, len);
}

/* --- weechat hooks --- */

static int
on_fd(const void *pointer, void *data, int fd)
{
	struct pollfd pfd[2];
	size_t n = bc_ble_pollfds(ble, pfd, 2);

	if (n > 0) {
		pfd[0].revents = pfd[0].events;
		bc_ble_dispatch(ble, pfd, n);
	}
	return WEECHAT_RC_OK;
}

static void arm_fd(int fd, short events);

static void
on_events(void *ud, int fd, short events)
{
	arm_fd(fd, events);
}

static void
arm_fd(int fd, short events)
{
	if (fd_hook != NULL)
		weechat_unhook(fd_hook);
	fd_hook =
	    weechat_hook_fd(fd, (events & POLLIN) ? 1 : 0,
	                    (events & POLLOUT) ? 1 : 0, 0, &on_fd, NULL, NULL);
}

static void arm_fd(int fd, short events);

static int
on_timer(const void *pointer, void *data, int remaining)
{
	if (want_events != armed_events)
		arm_fd(bc_ble_fd(ble), want_events);

	/*
	 * Also pump here: the bus can have work queued that no readable
	 * event announces, and a missed wakeup would stall the mesh.
	 */
	bc_ble_dispatch(ble, NULL, 0);
	bc_ble_tick(ble);
	bc_mesh_tick(mesh);
	return WEECHAT_RC_OK;
}

static int
on_input(const void *pointer, void *data, struct t_gui_buffer *buf,
         const char *input)
{
	int r;

	if (input == NULL || input[0] == '\0')
		return WEECHAT_RC_OK;

	r = bc_mesh_send_public(mesh, input);
	if (r < 0) {
		say(weechat_prefix("error"), "send failed: %s", strerror(-r));
		return WEECHAT_RC_OK;
	}
	weechat_printf(buf, "%s\t%s", bc_mesh_nickname(mesh), input);
	return WEECHAT_RC_OK;
}

static int
cmd_bitchat(const void *pointer, void *data, struct t_gui_buffer *buf, int argc,
            char **argv, char **argv_eol)
{
	if (argc >= 2 && strcmp(argv[1], "who") == 0) {
		static struct bc_peer_info peers[16];
		size_t n, i;

		n = bc_mesh_peers(mesh, peers,
		                  sizeof(peers) / sizeof(peers[0]));
		for (i = 0; i < n; i++) {
			char signal[32] = "";

			if (peers[i].rssi != 0)
				snprintf(
				    signal, sizeof(signal), " %d dBm %llds ago",
				    peers[i].rssi,
				    (long long)(peers[i].rssi_age_ms / 1000));
			say(weechat_prefix("network"), "%s (%.8s)%s%s",
			    peers[i].nickname, peers[i].peer_id,
			    peers[i].encrypted ? " encrypted" : "", signal);
		}
		if (n == 0)
			say(weechat_prefix("network"), "nobody around");
		return WEECHAT_RC_OK;
	}

	if (argc >= 4 && strcmp(argv[1], "msg") == 0) {
		char id[BC_PEER_ID_LEN * 2 + 1];
		int r;

		if (!bc_mesh_resolve_peer(mesh, argv[2], id)) {
			say(weechat_prefix("error"), "no such peer: %s",
			    argv[2]);
			return WEECHAT_RC_OK;
		}
		r = bc_mesh_send_private(mesh, id, argv_eol[3], NULL);
		if (r < 0)
			say(weechat_prefix("error"), "send failed: %s",
			    strerror(-r));
		else
			say(weechat_prefix("network"), "[to %s] %s", argv[2],
			    argv_eol[3]);
		return WEECHAT_RC_OK;
	}

	if (argc >= 2 && strcmp(argv[1], "debug") == 0) {
		debug = !debug;
		say(weechat_prefix("network"), "transport log %s",
		    debug ? "on" : "off");
		return WEECHAT_RC_OK;
	}

	if (argc >= 3 && strcmp(argv[1], "nick") == 0) {
		bc_mesh_set_nickname(mesh, argv[2]);
		say(weechat_prefix("network"), "nickname is now %s", argv[2]);
		return WEECHAT_RC_OK;
	}

	say(weechat_prefix("network"), "you are %s (%s)",
	    bc_mesh_nickname(mesh), peer_hex);
	return WEECHAT_RC_OK;
}

int
weechat_plugin_init(struct t_weechat_plugin *plugin, int argc, char *argv[])
{
	static const struct bc_mesh_ops mesh_ops = {
	    .send = mesh_send,
	    .broadcast = mesh_broadcast,
	    .on_public = on_public,
	    .on_private = on_private,
	    .on_peer = on_peer,
	    .on_receipt = on_receipt,
	    .on_log = on_log,
	};
	static const struct bc_ble_ops ble_ops = {
	    .on_link_up = ble_link_up,
	    .on_link_down = ble_link_down,
	    .on_frame = ble_frame,
	    .on_mtu = ble_mtu,
	    .on_rssi = ble_rssi,
	    .on_log = on_log,
	    .on_events = on_events,
	};
	char path[512];
	const char *nick;
	int r;

	weechat_plugin = plugin;

	if (bc_identity_default_path(path, sizeof(path)) < 0)
		return WEECHAT_RC_ERROR;
	if (bc_identity_load(&identity, path) < 0)
		return WEECHAT_RC_ERROR;
	bc_hex_encode(identity.peer_id, BC_PEER_ID_LEN, peer_hex);

	nick = getenv("USER");
	if (nick == NULL || nick[0] == '\0')
		nick = "anon";

	if (bc_mesh_new(&mesh, &identity, nick, &mesh_ops, NULL) < 0)
		return WEECHAT_RC_ERROR;

	buffer =
	    weechat_buffer_new("mesh", &on_input, NULL, NULL, NULL, NULL, NULL);
	if (buffer == NULL) {
		bc_mesh_free(mesh);
		return WEECHAT_RC_ERROR;
	}
	weechat_buffer_set(buffer, "title", "bitchat mesh");

	r = bc_ble_new(&ble, -1, &ble_ops, NULL);
	if (r < 0) {
		say(weechat_prefix("error"), "radio unavailable: %s",
		    strerror(-r));
	} else {
		arm_fd(bc_ble_fd(ble), bc_ble_events(ble));
	}

	timer_hook = weechat_hook_timer(200, 0, 0, &on_timer, NULL, NULL);

	weechat_hook_command("bitchat", "bitchat mesh control",
	                     "who || msg <peer> <text> || nick <name> || debug",
	                     "who: list peers\n"
	                     "msg: send a private message\n"
	                     "nick: change the announced nickname\n"
	                     "debug: toggle the transport log",
	                     "who || msg || nick || debug", &cmd_bitchat, NULL,
	                     NULL);

	say(weechat_prefix("network"), "bitchat up as %s (%s)", nick, peer_hex);
	return WEECHAT_RC_OK;
}

int
weechat_plugin_end(struct t_weechat_plugin *plugin)
{
	if (mesh != NULL)
		bc_mesh_leave(mesh);
	if (fd_hook != NULL)
		weechat_unhook(fd_hook);
	if (timer_hook != NULL)
		weechat_unhook(timer_hook);
	bc_ble_free(ble);
	bc_mesh_free(mesh);
	return WEECHAT_RC_OK;
}
