// SPDX-License-Identifier: ISC
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bitchat/ble.h"
#include "bitchat/identity.h"
#include "bitchat/mesh.h"
#include "bitchat/packet.h"
#include "bitchat/tcp.h"
#include "bitchat/tlv.h"
#include "version.h"

#include "src/ui.h"
#include "banned.h"

#define MAX_FDS 16

/* Recent outgoing private messages, so a receipt can name what it acks. */
#define SENT_SLOTS 16

struct sent {
	char id[40];
	char text[128];
};

struct app {
	struct ui *ui;
	struct bc_mesh *mesh;
	struct bc_ble *ble;
	struct bc_tcp *net; /* socket transport, when running without a radio */
	struct bc_identity id;
	char peer_hex[BC_PEER_ID_LEN * 2 + 1];
	char target[BC_PEER_ID_LEN * 2 + 1]; /* current /msg peer */
	bool debug; /* show transport chatter in the pane */
	bool quit;
	struct sent sent[SENT_SLOTS];
	size_t sent_next;
};

static volatile sig_atomic_t interrupted;

static void
on_signal(int sig)
{
	interrupted = 1;
}

static void
stamp(char out[16])
{
	time_t now = time(NULL);
	struct tm tm;

	localtime_r(&now, &tm);
	strftime(out, 16, "%H:%M", &tm);
}

static void
mesh_send(void *ud, void *link, const uint8_t *frame, size_t len)
{
	struct app *a = ud;

	if (a->net != NULL)
		bc_tcp_send(a->net, link, frame, len);
	else
		bc_ble_send(a->ble, link, frame, len);
}

static void
mesh_broadcast(void *ud, void *except, const uint8_t *frame, size_t len)
{
	struct app *a = ud;

	if (a->net != NULL)
		bc_tcp_broadcast(a->net, except, frame, len);
	else
		bc_ble_broadcast(a->ble, except, frame, len);
}

static void
mesh_public(void *ud, const char *peer_id, const char *nick, const char *text,
            uint64_t timestamp)
{
	struct app *a = ud;
	bool mine = bc_mentions(text, bc_mesh_nickname(a->mesh));
	char at[16];

	stamp(at);
	ui_printf(a->ui, mine ? UI_MENTION : UI_PUBLIC, "%s <%s> %s", at, nick,
	          text);
	if (mine)
		ui_alert(a->ui);
}

static void
mesh_private(void *ud, const char *peer_id, const char *nick, const char *text,
             uint64_t timestamp)
{
	struct app *a = ud;
	char at[16];

	stamp(at);
	ui_printf(a->ui, UI_PRIVATE, "%s [%s -> you] %s", at, nick, text);
}

static void
mesh_receipt(void *ud, const char *peer_id, const char *nick,
             const char *message_id, bool read)
{
	struct app *a = ud;
	size_t i;

	for (i = 0; i < SENT_SLOTS; i++) {
		if (strcmp(a->sent[i].id, message_id) != 0)
			continue;
		ui_printf(a->ui, UI_SYSTEM, "* %s %s: %s", nick,
		          read ? "read" : "received", a->sent[i].text);
		return;
	}
	ui_printf(a->ui, UI_SYSTEM, "* %s %s a message", nick,
	          read ? "read" : "received");
}

static void
mesh_peer(void *ud, const char *peer_id, const char *nick, bool joined)
{
	struct app *a = ud;

	ui_printf(a->ui, UI_SYSTEM, "* %s (%.8s) %s", nick, peer_id,
	          joined ? "joined" : "left");
}

/* Transport and mesh chatter: useful when a link misbehaves, noise otherwise.
 */
static void
debug_log(void *ud, const char *line)
{
	struct app *a = ud;

	if (!a->debug)
		return;
	ui_printf(a->ui, UI_DEBUG, "- %s", line);
}

static void
ble_link_up(void *ud, void *link)
{
	struct app *a = ud;

	debug_log(a, "link up");
	bc_mesh_link_up(a->mesh, link);
}

static void
ble_link_down(void *ud, void *link)
{
	struct app *a = ud;

	debug_log(a, "link down");
	bc_mesh_link_down(a->mesh, link);
}

static void
ble_rssi(void *ud, void *link, int rssi)
{
	struct app *a = ud;

	bc_mesh_link_rssi(a->mesh, link, rssi);
}

static void
ble_frame(void *ud, void *link, const uint8_t *frame, size_t len)
{
	struct app *a = ud;

	bc_mesh_recv(a->mesh, link, frame, len);
}

/* Completion candidates: the nicknames of peers we can see. */
static size_t
peer_names(void *ud, const char *out[], size_t max)
{
	static struct bc_peer_info peers[12];
	struct app *a = ud;
	size_t n, i;

	n = bc_mesh_peers(a->mesh, peers, sizeof(peers) / sizeof(peers[0]));
	if (n > max)
		n = max;
	for (i = 0; i < n; i++)
		out[i] = peers[i].nickname;
	return n;
}

static const struct bc_tcp_ops tcp_ops = {
    .on_link_up = ble_link_up,
    .on_link_down = ble_link_down,
    .on_frame = ble_frame,
    .on_log = debug_log,
};

static void
show_peers(struct app *a)
{
	struct bc_peer_info peers[12];
	size_t n, i;

	n = bc_mesh_peers(a->mesh, peers, sizeof(peers) / sizeof(peers[0]));
	if (n == 0) {
		ui_printf(a->ui, UI_SYSTEM, "* nobody around");
		return;
	}
	for (i = 0; i < n; i++) {
		char signal[32] = "";

		if (peers[i].rssi != 0)
			snprintf(signal, sizeof(signal), " %d dBm %llds ago",
			         peers[i].rssi,
			         (long long)(peers[i].rssi_age_ms / 1000));
		ui_printf(a->ui, UI_SYSTEM, "* %-16s %.8s %s%s%s",
		          peers[i].nickname, peers[i].peer_id,
		          peers[i].direct ? "direct" : "relayed",
		          peers[i].encrypted ? " encrypted" : "", signal);
	}
}

static void
send_private(struct app *a, const char *needle, const char *text)
{
	char id[BC_PEER_ID_LEN * 2 + 1];
	char msg_id[40] = "";
	char at[16];
	int r;

	if (!bc_mesh_resolve_peer(a->mesh, needle, id)) {
		ui_printf(a->ui, UI_SYSTEM, "* no such peer: %s", needle);
		return;
	}

	r = bc_mesh_send_private(a->mesh, id, text, msg_id);
	if (r < 0) {
		ui_printf(a->ui, UI_SYSTEM, "* send failed: %s", strerror(-r));
		return;
	}
	snprintf(a->target, sizeof(a->target), "%s", id);
	snprintf(a->sent[a->sent_next].id, sizeof(a->sent[0].id), "%s", msg_id);
	snprintf(a->sent[a->sent_next].text, sizeof(a->sent[0].text), "%s",
	         text);
	a->sent_next = (a->sent_next + 1) % SENT_SLOTS;
	stamp(at);
	ui_printf(a->ui, UI_SELF, "%s [you -> %s] %s", at, needle, text);
}

static void
handle_command(struct app *a, char *line)
{
	char *arg = strchr(line, ' ');

	if (arg != NULL)
		*arg++ = '\0';

	if (strcmp(line, "/quit") == 0 || strcmp(line, "/q") == 0) {
		a->quit = true;
	} else if (strcmp(line, "/who") == 0 || strcmp(line, "/w") == 0) {
		show_peers(a);
	} else if (strcmp(line, "/nick") == 0 && arg != NULL) {
		bc_mesh_set_nickname(a->mesh, arg);
		ui_printf(a->ui, UI_SYSTEM, "* nickname is now %s", arg);
	} else if (strcmp(line, "/msg") == 0 && arg != NULL) {
		char *text = strchr(arg, ' ');

		if (text == NULL) {
			ui_printf(a->ui, UI_SYSTEM,
			          "* usage: /msg <peer> <text>");
			return;
		}
		*text++ = '\0';
		send_private(a, arg, text);
	} else if (strcmp(line, "/rssi") == 0) {
		struct bc_rssi_info seen[12];
		size_t n, i;

		n = a->ble != NULL ? bc_ble_rssi(a->ble, seen,
		                                 sizeof(seen) / sizeof(seen[0]))
		                   : 0;
		if (n == 0)
			ui_printf(a->ui, UI_SYSTEM, "* nothing sighted yet");
		for (i = 0; i < n; i++)
			ui_printf(a->ui, UI_SYSTEM, "* %s  %d dBm  %llds ago",
			          seen[i].address, seen[i].rssi,
			          (long long)(seen[i].age_ms / 1000));
	} else if (strcmp(line, "/debug") == 0) {
		a->debug = !a->debug;
		ui_printf(a->ui, UI_SYSTEM, "* transport log %s",
		          a->debug ? "on" : "off");
	} else if (strcmp(line, "/id") == 0) {
		ui_printf(a->ui, UI_SYSTEM, "* your peer id is %s",
		          a->peer_hex);
	} else if (strcmp(line, "/help") == 0) {
		ui_printf(a->ui, UI_SYSTEM,
		          "* /who /msg <peer> <text> /nick <name> /id "
		          "/rssi /debug /quit");
	} else {
		ui_printf(a->ui, UI_SYSTEM, "* unknown command: %s", line);
	}
}

static void
handle_line(struct app *a, const char *input)
{
	char line[1024];
	char at[16];
	int r;

	snprintf(line, sizeof(line), "%s", input);

	if (line[0] == '/') {
		handle_command(a, line);
		return;
	}

	r = bc_mesh_send_public(a->mesh, line);
	if (r < 0) {
		ui_printf(a->ui, UI_SYSTEM, "* send failed: %s", strerror(-r));
		return;
	}
	stamp(at);
	ui_printf(a->ui, UI_SELF, "%s <%s> %s", at, bc_mesh_nickname(a->mesh),
	          line);
}

static void
usage(void)
{
	fprintf(stderr, "usage: bitchat [-d] [-i hci-index] [-n nickname]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	static const struct bc_mesh_ops mesh_ops = {
	    .send = mesh_send,
	    .broadcast = mesh_broadcast,
	    .on_public = mesh_public,
	    .on_private = mesh_private,
	    .on_peer = mesh_peer,
	    .on_receipt = mesh_receipt,
	    .on_log = debug_log,
	};
	static const struct bc_ble_ops ble_ops = {
	    .on_link_up = ble_link_up,
	    .on_link_down = ble_link_down,
	    .on_frame = ble_frame,
	    .on_rssi = ble_rssi,
	    .on_log = debug_log,
	};
	static struct app app;
	char path[512];
	const char *peers[8];
	const char *nick = NULL;
	size_t peer_count = 0;
	long listen_port = -1;
	int hci_index = -1;
	int ch, r;

	while ((ch = getopt(argc, argv, "dC:i:L:n:hv")) != -1) {
		switch (ch) {
		case 'd':
			app.debug = true;
			break;
		case 'C':
			if (peer_count < sizeof(peers) / sizeof(peers[0]))
				peers[peer_count++] = optarg;
			break;
		case 'L':
			listen_port = strtol(optarg, NULL, 10);
			if (listen_port < 0 || listen_port > 65535)
				usage();
			break;
		case 'i':
			hci_index = (int)strtol(optarg, NULL, 10);
			break;
		case 'n':
			nick = optarg;
			break;
		case 'v':
			printf("bitchat %s\n", BITCHAT_VERSION);
			return 0;
		default:
			usage();
		}
	}

	r = bc_identity_default_path(path, sizeof(path));
	if (r < 0)
		errx(1, "cannot locate the identity file");

	r = bc_identity_load(&app.id, path);
	if (r < 0) {
		errno = -r;
		err(1, "identity");
	}
	bc_hex_encode(app.id.peer_id, BC_PEER_ID_LEN, app.peer_hex);

	if (nick == NULL)
		nick = getenv("USER");
	if (nick == NULL)
		nick = "anon";

	if (ui_new(&app.ui) < 0)
		errx(1, "cannot start the terminal interface");

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGPIPE, SIG_IGN);

	r = bc_mesh_new(&app.mesh, &app.id, nick, &mesh_ops, &app);
	if (r < 0) {
		ui_free(app.ui);
		errx(1, "mesh: %s", strerror(-r));
	}

	if (listen_port >= 0 || peer_count > 0) {
		r = bc_tcp_new(&app.net,
		               (uint16_t)(listen_port > 0 ? listen_port : 0),
		               &tcp_ops, &app);
		if (r < 0)
			errx(1, "socket transport: %s", strerror(-r));

		ui_printf(app.ui, UI_SYSTEM, "* listening on port %u",
		          bc_tcp_port(app.net));

		for (r = 0; (size_t)r < peer_count; r++) {
			const char *spec = peers[r];
			size_t hostlen = strcspn(spec, ":");
			char host[64];
			long port;

			if (spec[hostlen] != ':')
				errx(1, "expected host:port, got %s", spec);
			snprintf(host, sizeof(host), "%.*s", (int)hostlen,
			         spec);
			port = strtol(spec + hostlen + 1, NULL, 10);
			bc_tcp_connect(app.net, host, (uint16_t)port);
			ui_printf(app.ui, UI_SYSTEM, "* dialing %s", peers[r]);
		}
	} else {
		r = bc_ble_new(&app.ble, hci_index, &ble_ops, &app);
		if (r < 0)
			ui_printf(app.ui, UI_SYSTEM,
			          "* radio unavailable (%s), running offline",
			          strerror(-r));
	}

	ui_set_names(app.ui, peer_names, &app);

	ui_printf(app.ui, UI_SYSTEM, "* bitchat %s, /help for commands",
	          BITCHAT_VERSION);
	ui_printf(app.ui, UI_SYSTEM, "* you are %s (%s)", nick, app.peer_hex);

	while (!app.quit && !interrupted) {
		static struct bc_peer_info seen[12];
		struct pollfd fds[MAX_FDS];
		const char *line;
		size_t n = 1, peers_now;
		int timeout;

		fds[0].fd = STDIN_FILENO;
		fds[0].events = POLLIN;
		fds[0].revents = 0;

		if (app.net != NULL)
			n += bc_tcp_pollfds(app.net, fds + 1, MAX_FDS - 1);
		else if (app.ble != NULL)
			n += bc_ble_pollfds(app.ble, fds + 1, MAX_FDS - 1);

		timeout = bc_mesh_timeout(app.mesh);
		{
			int t = app.net != NULL ? bc_tcp_timeout(app.net)
			                        : bc_ble_timeout(app.ble);

			if (t >= 0 && (timeout < 0 || t < timeout))
				timeout = t;
		}

		peers_now = bc_mesh_peers(app.mesh, seen,
		                          sizeof(seen) / sizeof(seen[0]));
		ui_status(app.ui, bc_mesh_nickname(app.mesh), app.peer_hex,
		          app.net != NULL ? bc_tcp_link_count(app.net)
		                          : bc_ble_link_count(app.ble),
		          peers_now);
		ui_draw(app.ui);

		if (poll(fds, (nfds_t)n, timeout) < 0 && errno != EINTR)
			break;

		while ((line = ui_input(app.ui)) != NULL)
			handle_line(&app, line);

		if (app.net != NULL) {
			bc_tcp_dispatch(app.net, fds + 1, n - 1);
			bc_tcp_tick(app.net);
		} else if (app.ble != NULL) {
			bc_ble_dispatch(app.ble, fds + 1, n - 1);
			bc_ble_tick(app.ble);
		}
		bc_mesh_tick(app.mesh);
	}

	bc_mesh_leave(app.mesh);
	bc_tcp_free(app.net);
	bc_ble_free(app.ble);
	bc_mesh_free(app.mesh);
	ui_free(app.ui);
	return 0;
}
