// SPDX-License-Identifier: ISC
/*
 * The same three-node chain as the relay test, but over real sockets: three
 * meshes, two TCP hops, one poll loop. No Bluetooth controller involved.
 */
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>

#include "bitchat/crypto.h"
#include "bitchat/identity.h"
#include "bitchat/mesh.h"
#include "bitchat/tcp.h"

#define NODES 3

struct node {
	struct bc_mesh *mesh;
	struct bc_tcp *net;
	const char *nick;
	char last_public[256];
	char last_private[256];
	int peers_seen;
};

static struct node nodes[NODES];

static void
node_send(void *ud, void *link, const uint8_t *frame, size_t len)
{
	struct node *n = ud;

	bc_tcp_send(n->net, link, frame, len);
}

static void
node_broadcast(void *ud, void *except, const uint8_t *frame, size_t len)
{
	struct node *n = ud;

	bc_tcp_broadcast(n->net, except, frame, len);
}

static void
node_public(void *ud, const char *peer_id, const char *nick, const char *text,
            uint64_t timestamp)
{
	struct node *n = ud;

	snprintf(n->last_public, sizeof(n->last_public), "%s: %s", nick, text);
}

static void
node_private(void *ud, const char *peer_id, const char *nick, const char *text,
             uint64_t timestamp)
{
	struct node *n = ud;

	snprintf(n->last_private, sizeof(n->last_private), "%s: %s", nick,
	         text);
}

static void
node_peer(void *ud, const char *peer_id, const char *nick, bool joined)
{
	if (joined)
		((struct node *)ud)->peers_seen++;
}

static void
link_up(void *ud, void *link)
{
	struct node *n = ud;

	bc_mesh_link_up(n->mesh, link);
}

static void
link_down(void *ud, void *link)
{
	struct node *n = ud;

	bc_mesh_link_down(n->mesh, link);
}

static void
frame(void *ud, void *link, const uint8_t *data, size_t len)
{
	struct node *n = ud;

	bc_mesh_recv(n->mesh, link, data, len);
}

static const struct bc_mesh_ops mesh_ops = {
    .send = node_send,
    .broadcast = node_broadcast,
    .on_public = node_public,
    .on_private = node_private,
    .on_peer = node_peer,
};

static const struct bc_tcp_ops tcp_ops = {
    .on_link_up = link_up,
    .on_link_down = link_down,
    .on_frame = frame,
};

static void
make_identity(struct bc_identity *id)
{
	memset(id, 0, sizeof(*id));
	assert(bc_x25519_keygen(id->noise_priv, id->noise_pub) == 0);
	assert(bc_ed25519_keygen(id->sign_priv, id->sign_pub) == 0);
	bc_identity_derive(id);
}

/* Run every node's loop for the given time. */
static void
run(int ms)
{
	int elapsed;

	for (elapsed = 0; elapsed < ms; elapsed += 20) {
		struct pollfd fds[32];
		size_t counts[NODES];
		size_t total = 0, i;

		for (i = 0; i < NODES; i++) {
			counts[i] = bc_tcp_pollfds(nodes[i].net, fds + total,
			                           32 - total);
			total += counts[i];
		}

		poll(fds, (nfds_t)total, 20);

		total = 0;
		for (i = 0; i < NODES; i++) {
			bc_tcp_dispatch(nodes[i].net, fds + total, counts[i]);
			total += counts[i];
			bc_tcp_tick(nodes[i].net);
			bc_mesh_tick(nodes[i].mesh);
		}
	}
}

int
main(void)
{
	struct bc_identity ids[NODES];
	char peer_id[BC_PEER_ID_LEN * 2 + 1];
	uint16_t ports[NODES];
	size_t i;

	nodes[0].nick = "alice";
	nodes[1].nick = "bob";
	nodes[2].nick = "carol";

	for (i = 0; i < NODES; i++) {
		make_identity(&ids[i]);
		assert(bc_mesh_new(&nodes[i].mesh, &ids[i], nodes[i].nick,
		                   &mesh_ops, &nodes[i]) == 0);
		assert(bc_tcp_new(&nodes[i].net, 0, &tcp_ops, &nodes[i]) == 0);
		ports[i] = bc_tcp_port(nodes[i].net);
		assert(ports[i] != 0);
	}

	/* A chain: alice - bob - carol. The ends never dial each other. */
	assert(bc_tcp_connect(nodes[0].net, "127.0.0.1", ports[1]) == 0);
	assert(bc_tcp_connect(nodes[2].net, "127.0.0.1", ports[1]) == 0);
	run(300);

	assert(bc_tcp_link_count(nodes[1].net) == 2);

	/* Presence crosses the middle node. */
	run(1500);
	assert(nodes[0].peers_seen >= 2);
	assert(nodes[2].peers_seen >= 2);

	/* Public chat reaches the far end. */
	assert(bc_mesh_send_public(nodes[0].mesh, "rock good") == 0);
	run(1500);
	assert(strcmp(nodes[2].last_public, "alice: rock good") == 0);

	/* A private message opens a Noise session two hops away. */
	assert(bc_mesh_resolve_peer(nodes[0].mesh, "carol", peer_id));
	assert(bc_mesh_send_private(nodes[0].mesh, peer_id, "meet at cave",
	                            NULL) == 0);
	run(3000);
	assert(strcmp(nodes[2].last_private, "alice: meet at cave") == 0);

	for (i = 0; i < NODES; i++) {
		bc_tcp_free(nodes[i].net);
		bc_mesh_free(nodes[i].mesh);
	}
	return 0;
}
