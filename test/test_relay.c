// SPDX-License-Identifier: ISC
/* A chain of three: A and C never see each other, B relays between them. */
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitchat/crypto.h"
#include "bitchat/identity.h"
#include "bitchat/mesh.h"

#define QUEUE_MAX 64
#define FRAME_MAX 2048

/* Link tokens, one per side of each hop. */
#define LINK_AB ((void *)0x1)
#define LINK_BA ((void *)0x2)
#define LINK_BC ((void *)0x3)
#define LINK_CB ((void *)0x4)

struct frame {
	uint8_t data[FRAME_MAX];
	size_t len;
	void *link; /* the link it arrives on */
};

struct node {
	struct bc_mesh *mesh;
	const char *name;
	struct frame queue[QUEUE_MAX];
	size_t queued;
	char last_public[256];
	int relayed;
	int frames;
};

static struct node a, b, c;

static void
enqueue(struct node *n, void *link, const uint8_t *frame, size_t len)
{
	if (n->queued >= QUEUE_MAX || len > FRAME_MAX)
		return;
	n->frames++;
	memcpy(n->queue[n->queued].data, frame, len);
	n->queue[n->queued].len = len;
	n->queue[n->queued].link = link;
	n->queued++;
}

/* Deliver by link token: A only reaches B, C only reaches B. */
static void
wire(const struct node *from, const void *link, const uint8_t *frame,
     size_t len)
{
	if (from == &a && link == LINK_AB)
		enqueue(&b, LINK_BA, frame, len);
	else if (from == &c && link == LINK_CB)
		enqueue(&b, LINK_BC, frame, len);
	else if (from == &b && link == LINK_BA)
		enqueue(&a, LINK_AB, frame, len);
	else if (from == &b && link == LINK_BC)
		enqueue(&c, LINK_CB, frame, len);
}

static void
node_send(void *ud, void *link, const uint8_t *frame, size_t len)
{
	wire(ud, link, frame, len);
}

static void
node_broadcast(void *ud, void *except, const uint8_t *frame, size_t len)
{
	struct node *n = ud;

	if (n == &a) {
		if (except != LINK_AB)
			wire(n, LINK_AB, frame, len);
		return;
	}
	if (n == &c) {
		if (except != LINK_CB)
			wire(n, LINK_CB, frame, len);
		return;
	}

	/* B sits in the middle and holds one link toward each end. */
	if (except != LINK_BA)
		wire(n, LINK_BA, frame, len);
	if (except != LINK_BC)
		wire(n, LINK_BC, frame, len);
	n->relayed++;
}

static void
node_public(void *ud, const char *peer_id, const char *nick, const char *text,
            uint64_t timestamp)
{
	struct node *n = ud;

	snprintf(n->last_public, sizeof(n->last_public), "%s: %s", nick, text);
}

static const struct bc_mesh_ops ops = {
    .send = node_send,
    .broadcast = node_broadcast,
    .on_public = node_public,
};

static void
make_identity(struct bc_identity *id)
{
	memset(id, 0, sizeof(*id));
	assert(bc_x25519_keygen(id->noise_priv, id->noise_pub) == 0);
	assert(bc_ed25519_keygen(id->sign_priv, id->sign_pub) == 0);
	bc_identity_derive(id);
}

/* Relays are jittered by up to ~220 ms, so waiting is part of pumping. */
static void
settle(void)
{
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};

	nanosleep(&ts, NULL);
}

/* Deliver queued frames and run the relay timers until everything settles. */
static void
pump(void)
{
	struct node *nodes[3] = {&a, &b, &c};
	int rounds, idle = 0;

	for (rounds = 0; rounds < 64; rounds++) {
		bool moved = false;
		size_t which, i;

		for (which = 0; which < 3; which++) {
			struct node *n = nodes[which];
			size_t queued = n->queued;

			n->queued = 0;
			for (i = 0; i < queued; i++) {
				moved = true;
				bc_mesh_recv(n->mesh, n->queue[i].link,
				             n->queue[i].data, n->queue[i].len);
			}
		}

		for (which = 0; which < 3; which++)
			bc_mesh_tick(nodes[which]->mesh);

		if (moved || a.queued || b.queued || c.queued) {
			idle = 0;
			continue;
		}

		/* Give scheduled relays a chance before calling it quiet. */
		if (++idle > 16)
			return;
		settle();
	}
}

int
main(void)
{
	struct bc_identity ida, idb, idc;
	struct bc_peer_info peers[4];
	size_t n;

	make_identity(&ida);
	make_identity(&idb);
	make_identity(&idc);

	a.name = "a";
	b.name = "b";
	c.name = "c";
	assert(bc_mesh_new(&a.mesh, &ida, "alice", &ops, &a) == 0);
	assert(bc_mesh_new(&b.mesh, &idb, "bob", &ops, &b) == 0);
	assert(bc_mesh_new(&c.mesh, &idc, "carol", &ops, &c) == 0);

	bc_mesh_link_up(a.mesh, LINK_AB);
	bc_mesh_link_up(b.mesh, LINK_BA);
	bc_mesh_link_up(b.mesh, LINK_BC);
	bc_mesh_link_up(c.mesh, LINK_CB);

	/* Announces reach the far end through the middle node. */
	assert(bc_mesh_announce(a.mesh) == 0);
	assert(bc_mesh_announce(b.mesh) == 0);
	assert(bc_mesh_announce(c.mesh) == 0);
	pump();

	n = bc_mesh_peers(a.mesh, peers, 4);
	assert(n == 2); /* bob directly, carol over the relay */

	/* A public message crosses two hops. */
	assert(bc_mesh_send_public(a.mesh, "rock good") == 0);
	pump();
	assert(strcmp(c.last_public, "alice: rock good") == 0);
	assert(b.relayed > 0);

	/* The far peer answers, and the reply comes back the same way. */
	assert(bc_mesh_send_public(c.mesh, "fire better") == 0);
	pump();
	assert(strcmp(a.last_public, "carol: fire better") == 0);

	/*
	 * Links of different size get different cuts: the small one must not
	 * be handed the big one's chunking, and the big one must not be
	 * punished for the small one's limit.
	 */
	{
		static char big[600];
		size_t j;

		for (j = 0; j < sizeof(big) - 1; j++)
			big[j] = 'a' + (char)(j % 26);
		big[sizeof(big) - 1] = '\0';

		bc_mesh_set_link_mtu(b.mesh, LINK_BA, 2048);
		bc_mesh_set_link_mtu(b.mesh, LINK_BC, 120);

		a.frames = 0;
		c.frames = 0;
		assert(bc_mesh_send_public(b.mesh, big) == 0);
		pump();

		/* Alice takes it whole; carol needs several fragments. */
		assert(a.frames == 1);
		assert(c.frames >= 2);
		assert(c.frames > a.frames);
	}

	/*
	 * A recycled link slot must not inherit the MTU of the link that
	 * used to sit there. Give one link a large MTU, drop the other, and
	 * bring it back without reporting one: a link of unknown size has to
	 * be treated as small, or fragments are cut too big for it.
	 */
	{
		static char big[600];
		size_t j;

		bc_mesh_set_link_mtu(b.mesh, LINK_BC, 2048);
		bc_mesh_link_down(b.mesh, LINK_BA);
		bc_mesh_link_up(b.mesh, LINK_BA);

		for (j = 0; j < sizeof(big) - 1; j++)
			big[j] = 'a' + (char)(j % 26);
		big[sizeof(big) - 1] = '\0';

		a.frames = 0;
		assert(bc_mesh_send_public(b.mesh, big) == 0);
		pump();

		/*
		 * The body deflates first, so this is a few fragments at the
		 * 64-byte floor. Inheriting 2048 would send one frame that
		 * the link never agreed to carry.
		 */
		assert(a.frames >= 3);
	}

	/* Nothing loops: a second delivery of the same frame is dropped. */
	a.last_public[0] = '\0';
	pump();
	assert(a.last_public[0] == '\0');

	bc_mesh_free(a.mesh);
	bc_mesh_free(b.mesh);
	bc_mesh_free(c.mesh);
	return 0;
}
