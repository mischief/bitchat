// SPDX-License-Identifier: ISC
/* Two mesh engines wired to each other over a fake link. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitchat/crypto.h"
#include "bitchat/identity.h"
#include "bitchat/mesh.h"

#define LINK ((void *)0x1)
#define QUEUE_MAX 64

struct frame {
	uint8_t data[2048];
	size_t len;
};

struct node {
	struct bc_mesh *mesh;
	struct node *other;
	struct frame queue[QUEUE_MAX];
	size_t queued;
	char last_public[256];
	char last_private[256];
	char joined[64];
	char last_receipt[64];
	int peers_seen;
};

static void
enqueue(struct node *n, const uint8_t *frame, size_t len)
{
	if (n->queued >= QUEUE_MAX || len > sizeof(n->queue[0].data))
		return;
	memcpy(n->queue[n->queued].data, frame, len);
	n->queue[n->queued].len = len;
	n->queued++;
}

static void
node_send(void *ud, void *link, const uint8_t *frame, size_t len)
{
	struct node *n = ud;

	enqueue(n->other, frame, len);
}

static void
node_broadcast(void *ud, void *except, const uint8_t *frame, size_t len)
{
	struct node *n = ud;

	enqueue(n->other, frame, len);
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
node_receipt(void *ud, const char *peer_id, const char *nick,
             const char *message_id, bool read)
{
	struct node *n = ud;

	snprintf(n->last_receipt, sizeof(n->last_receipt), "%s %s", message_id,
	         read ? "read" : "delivered");
}

static void
node_peer(void *ud, const char *peer_id, const char *nick, bool joined)
{
	struct node *n = ud;

	if (!joined)
		return;
	snprintf(n->joined, sizeof(n->joined), "%s", nick);
	n->peers_seen++;
}

static const struct bc_mesh_ops ops = {
    .send = node_send,
    .broadcast = node_broadcast,
    .on_public = node_public,
    .on_private = node_private,
    .on_peer = node_peer,
    .on_receipt = node_receipt,
};

static void
make_identity(struct bc_identity *id)
{
	memset(id, 0, sizeof(*id));
	assert(bc_x25519_keygen(id->noise_priv, id->noise_pub) == 0);
	assert(bc_ed25519_keygen(id->sign_priv, id->sign_pub) == 0);
	bc_identity_derive(id);
}

/* Deliver everything queued, in both directions, until both queues drain. */
static void
pump(struct node *a, struct node *b)
{
	int rounds;

	for (rounds = 0; rounds < 16; rounds++) {
		struct node *nodes[2] = {a, b};
		size_t which, i;
		bool moved = false;

		for (which = 0; which < 2; which++) {
			struct node *n = nodes[which];
			size_t queued = n->queued;

			n->queued = 0;
			for (i = 0; i < queued; i++) {
				moved = true;
				bc_mesh_recv(n->mesh, LINK, n->queue[i].data,
				             n->queue[i].len);
			}
		}
		if (!moved)
			return;
	}
}

int
main(void)
{
	static struct node a, b;
	struct bc_identity ida, idb;
	struct bc_peer_info info[4];
	char peer_id[BC_PEER_ID_LEN * 2 + 1];
	char sent_id[40] = "";
	int i;

	make_identity(&ida);
	make_identity(&idb);

	a.other = &b;
	b.other = &a;
	assert(bc_mesh_new(&a.mesh, &ida, "alice", &ops, &a) == 0);
	assert(bc_mesh_new(&b.mesh, &idb, "bob", &ops, &b) == 0);

	bc_mesh_link_up(a.mesh, LINK);
	bc_mesh_link_up(b.mesh, LINK);

	/* Presence: each side learns the other from a signed announce. */
	assert(bc_mesh_announce(a.mesh) == 0);
	assert(bc_mesh_announce(b.mesh) == 0);
	pump(&a, &b);
	assert(strcmp(a.joined, "bob") == 0);
	assert(strcmp(b.joined, "alice") == 0);

	/* Public chat. */
	assert(bc_mesh_send_public(a.mesh, "rock good") == 0);
	pump(&a, &b);
	assert(strcmp(b.last_public, "alice: rock good") == 0);

	/* Public payloads are the bare text, as upstream sends them. */
	assert(a.queue[0].len > 0);

	/* A repeat of the same frame must be dropped by the seen set. */
	b.last_public[0] = '\0';
	enqueue(&b, a.queue[0].data, a.queue[0].len);
	pump(&a, &b);
	assert(b.last_public[0] == '\0');

	/* Private chat: the first send opens a Noise session. */
	assert(bc_mesh_resolve_peer(a.mesh, "bob", peer_id));
	assert(bc_mesh_send_private(a.mesh, peer_id, "meet at cave", sent_id) ==
	       0);
	for (i = 0; i < 4; i++)
		pump(&a, &b);
	assert(strcmp(b.last_private, "alice: meet at cave") == 0);

	/* The receiver acks: delivered, then read, quoting our message ID. */
	assert(sent_id[0] != '\0');
	{
		char want[64];

		snprintf(want, sizeof(want), "%s read", sent_id);
		assert(strcmp(a.last_receipt, want) == 0);
	}

	/* The session stays up for later messages, in both directions. */
	assert(bc_mesh_resolve_peer(b.mesh, "alice", peer_id));
	assert(bc_mesh_send_private(b.mesh, peer_id, "bring fire", NULL) == 0);
	pump(&a, &b);
	assert(strcmp(a.last_private, "bob: bring fire") == 0);

	assert(bc_mesh_peers(a.mesh, info, 4) == 1);
	assert(info[0].encrypted);

	/* Leaving removes the peer. */
	assert(bc_mesh_leave(b.mesh) == 0);
	pump(&a, &b);
	assert(bc_mesh_peers(a.mesh, info, 4) == 0);

	bc_mesh_free(a.mesh);
	bc_mesh_free(b.mesh);
	return 0;
}
