// SPDX-License-Identifier: ISC
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/internal.h"

#define DEFAULT_TTL 7
#define SEEN_SLOTS 1024
#define SEEN_TTL_MS (5 * 60 * 1000)
#define PEER_STALE_MS (3 * 60 * 1000)
#define ANNOUNCE_ALONE_MS 4000
#define ANNOUNCE_LINKED_MS 15000
#define HIGH_DEGREE 6 /* a node this well connected floods less far */
#define DENSE_TTL_CAP 5
#define FRAGMENT_TTL_CAP 7
#define FRAGMENT_TTL_CAP_DENSE 5
#define RELAY_SLOTS 128
#define FRAG_CHUNK 400 /* used until a link reports its own limit */
#define FRAG_CHUNK_MIN 64
#define FRAG_OVERHEAD 48 /* packet header, IDs and the fragment header */
#define FRAG_SLOTS 16
#define FRAG_MAX_PARTS 512      /* accepted on receive */
#define FRAG_MAX_SEND_PARTS 256 /* deployed clients reject more */
#define MAX_FRAME (64 * 1024)

struct peer {
	uint8_t id[BC_PEER_ID_LEN];
	char nick[BC_NICK_MAX];
	uint8_t noise_pub[BC_KEY_LEN];
	uint8_t sign_pub[BC_KEY_LEN];
	bool have_keys;
	bool announced; /* reported to the caller as present */
	bool direct;
	void *link;
	int rssi;
	int64_t rssi_at;
	int64_t last_seen;
	struct bc_noise_hs *hs;
	bool hs_initiator;
	struct bc_noise_session sess;
	char *pending;       /* text waiting for the session to come up */
	char pending_id[40]; /* its message ID, assigned when queued */
	struct peer *next;
};

struct seen_entry {
	uint8_t key[BC_HASH_LEN];
	int64_t at;
};

/* What a fragment header needs from the packet being carried. */
struct frag_meta {
	uint8_t sender[BC_PEER_ID_LEN];
	uint8_t recipient[BC_PEER_ID_LEN];
	bool has_recipient;
	uint8_t ttl;
	uint8_t type;
	uint64_t timestamp;
};

struct relay_entry {
	uint8_t key[BC_HASH_LEN];
	uint8_t *frame;
	size_t len;
	void *except;
	int64_t due;
	struct frag_meta meta; /* a small link may need this re-cut */
	bool subset;           /* send to a few links rather than all */
	bool used;
};

struct frag_asm {
	uint64_t sender;
	uint64_t id;
	uint16_t total;
	uint16_t got;
	uint8_t type;
	int64_t started;
	size_t size;
	uint8_t *parts[FRAG_MAX_PARTS];
	size_t part_len[FRAG_MAX_PARTS];
	bool used;
};

struct bc_mesh {
	struct bc_identity id;
	char nickname[BC_NICK_MAX];
	struct bc_mesh_ops ops;
	void *ud;

	struct peer *peers;
	void *links[64];
	size_t link_mtu[64];
	size_t link_count;

	struct seen_entry seen[SEEN_SLOTS];
	struct relay_entry relays[RELAY_SLOTS];
	struct frag_asm frags[FRAG_SLOTS];

	int64_t next_announce;
	int64_t next_sweep;
};

static void mlog(struct bc_mesh *m, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void
mlog(struct bc_mesh *m, const char *fmt, ...)
{
	char line[256];
	va_list ap;

	if (m->ops.on_log == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	m->ops.on_log(m->ud, line);
}

static void
peer_id_hex(const uint8_t id[BC_PEER_ID_LEN], char out[BC_PEER_ID_LEN * 2 + 1])
{
	bc_hex_encode(id, BC_PEER_ID_LEN, out);
}

static struct peer *
peer_find(struct bc_mesh *m, const uint8_t id[BC_PEER_ID_LEN])
{
	struct peer *p;

	for (p = m->peers; p != NULL; p = p->next)
		if (memcmp(p->id, id, BC_PEER_ID_LEN) == 0)
			return p;
	return NULL;
}

static struct peer *
peer_get(struct bc_mesh *m, const uint8_t id[BC_PEER_ID_LEN])
{
	struct peer *p = peer_find(m, id);

	if (p != NULL)
		return p;

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		return NULL;
	memcpy(p->id, id, BC_PEER_ID_LEN);
	p->next = m->peers;
	m->peers = p;
	return p;
}

static void
peer_drop(struct bc_mesh *m, struct peer *target)
{
	struct peer **pp;

	for (pp = &m->peers; *pp != NULL; pp = &(*pp)->next) {
		if (*pp != target)
			continue;
		*pp = target->next;
		bc_noise_hs_free(target->hs);
		free(target->pending);
		free(target);
		return;
	}
}

/* Dedup key: sender, timestamp, type and a digest of the payload. */
static void
packet_key(const struct bc_packet *p, uint8_t out[BC_HASH_LEN])
{
	uint8_t buf[BC_PEER_ID_LEN + 8 + 1 + BC_HASH_LEN];
	uint8_t digest[BC_HASH_LEN];
	size_t off = 0;
	int i;

	bc_sha256(p->payload, p->payload_len, digest);
	memcpy(buf, p->sender, BC_PEER_ID_LEN);
	off += BC_PEER_ID_LEN;
	for (i = 7; i >= 0; i--)
		buf[off++] = (uint8_t)((p->timestamp >> (i * 8)) & 0xff);
	buf[off++] = p->type;
	memcpy(buf + off, digest, BC_HASH_LEN);
	off += BC_HASH_LEN;
	bc_sha256(buf, off, out);
}

static bool
seen_check_add(struct bc_mesh *m, const uint8_t key[BC_HASH_LEN])
{
	int64_t now = bc_now_ms();
	size_t slot = ((size_t)key[0] << 8 | key[1]) % SEEN_SLOTS;
	size_t i;

	for (i = 0; i < SEEN_SLOTS; i++) {
		struct seen_entry *e = &m->seen[(slot + i) % SEEN_SLOTS];

		if (e->at != 0 && now - e->at > SEEN_TTL_MS)
			e->at = 0;
		if (e->at == 0) {
			memcpy(e->key, key, BC_HASH_LEN);
			e->at = now;
			return false;
		}
		if (memcmp(e->key, key, BC_HASH_LEN) == 0) {
			e->at = now;
			return true;
		}
	}

	/* Table full: overwrite the home slot. */
	memcpy(m->seen[slot].key, key, BC_HASH_LEN);
	m->seen[slot].at = now;
	return false;
}

/*
 * What a fragment must fit on one link. A link that has not reported an MTU
 * counts as the floor rather than as no opinion: it still receives what we
 * send it.
 */
static size_t
link_frame_limit(const struct bc_mesh *m, const void *link)
{
	size_t i;

	for (i = 0; i < m->link_count; i++)
		if (m->links[i] == link && m->link_mtu[i] != 0)
			return m->link_mtu[i];
	return FRAG_CHUNK_MIN + FRAG_OVERHEAD;
}

/* The smallest of them, which is what an untargeted send has to satisfy. */
static size_t
link_limit(const struct bc_mesh *m)
{
	size_t limit = 0, i;

	for (i = 0; i < m->link_count; i++) {
		size_t mtu = link_frame_limit(m, m->links[i]);

		if (limit == 0 || mtu < limit)
			limit = mtu;
	}
	return limit;
}

static size_t
chunk_for(size_t limit)
{
	size_t chunk;

	if (limit == 0)
		return FRAG_CHUNK;

	chunk = limit > FRAG_OVERHEAD ? limit - FRAG_OVERHEAD : 0;
	if (chunk > FRAG_CHUNK)
		chunk = FRAG_CHUNK;
	if (chunk < FRAG_CHUNK_MIN)
		chunk = FRAG_CHUNK_MIN;
	return chunk;
}

static void
frag_meta_of(struct frag_meta *meta, const struct bc_packet *p)
{
	memset(meta, 0, sizeof(*meta));
	memcpy(meta->sender, p->sender, BC_PEER_ID_LEN);
	meta->has_recipient = p->has_recipient;
	if (p->has_recipient)
		memcpy(meta->recipient, p->recipient, BC_PEER_ID_LEN);
	meta->ttl = p->ttl;
	meta->type = p->type;
	meta->timestamp = p->timestamp;
}

/*
 * Cut a frame for one link. Each link gets its own fragment ID because the
 * chunking differs per link, and a receiver hearing two cuts under one ID
 * would splice pieces that do not line up.
 */
static int
send_fragments(struct bc_mesh *m, void *link, const struct frag_meta *meta,
               const uint8_t *frame, size_t len)
{
	uint8_t frag_id[8];
	size_t cut = chunk_for(link_frame_limit(m, link));
	size_t total = (len + cut - 1) / cut;
	size_t i;

	if (total > FRAG_MAX_SEND_PARTS)
		return -EMSGSIZE;
	if (bc_random(frag_id, sizeof(frag_id)) < 0)
		return -EIO;

	for (i = 0; i < total; i++) {
		struct bc_packet f = {0};
		autofree uint8_t *payload = NULL;
		autofree uint8_t *out = NULL;
		size_t chunk = len - i * cut;
		size_t outlen;
		int r;

		if (chunk > cut)
			chunk = cut;

		payload = malloc(13 + chunk);
		if (payload == NULL)
			return -ENOMEM;
		memcpy(payload, frag_id, 8);
		payload[8] = (uint8_t)(i >> 8);
		payload[9] = (uint8_t)i;
		payload[10] = (uint8_t)(total >> 8);
		payload[11] = (uint8_t)total;
		payload[12] = meta->type;
		memcpy(payload + 13, frame + i * cut, chunk);

		f.version = 1;
		f.type = BC_MSG_FRAGMENT;
		f.ttl = meta->ttl;
		f.timestamp = meta->timestamp;
		memcpy(f.sender, meta->sender, BC_PEER_ID_LEN);
		f.has_recipient = meta->has_recipient;
		if (meta->has_recipient)
			memcpy(f.recipient, meta->recipient, BC_PEER_ID_LEN);
		f.payload = payload;
		f.payload_len = 13 + chunk;

		r = bc_packet_encode(&f, false, &out, &outlen);
		if (r < 0)
			return r;
		if (m->ops.send != NULL)
			m->ops.send(m->ud, link, out, outlen);
	}
	return 0;
}

/* One link, fragmenting only if that link cannot take the frame whole. */
static int
send_one(struct bc_mesh *m, void *link, const struct frag_meta *meta,
         const uint8_t *frame, size_t len)
{
	if (len > link_frame_limit(m, link))
		return send_fragments(m, link, meta, frame, len);

	if (m->ops.send != NULL)
		m->ops.send(m->ud, link, frame, len);
	return 0;
}

/*
 * Every link but one. The transport's own broadcast is used when the frame
 * fits everywhere, since a peripheral reaches all its subscribers with a
 * single notification; per-link sends are for when the sizes differ.
 */
static int
send_all(struct bc_mesh *m, void *except, const struct frag_meta *meta,
         const uint8_t *frame, size_t len)
{
	size_t i;

	if (len <= link_limit(m) || m->link_count == 0) {
		if (m->ops.broadcast != NULL)
			m->ops.broadcast(m->ud, except, frame, len);
		return 0;
	}

	for (i = 0; i < m->link_count; i++) {
		if (m->links[i] == except)
			continue;
		send_one(m, m->links[i], meta, frame, len);
	}
	return 0;
}

/* Encode a packet and hand it to the transport, sized for each link. */
static int
transmit(struct bc_mesh *m, const struct bc_packet *p, void *link, void *except)
{
	autofree uint8_t *frame = NULL;
	struct frag_meta meta;
	size_t len;
	bool pad;
	int r;

	pad = p->type == BC_MSG_NOISE_ENCRYPTED ||
	      p->type == BC_MSG_NOISE_HANDSHAKE;

	r = bc_packet_encode(p, pad, &frame, &len);
	if (r < 0)
		return r;

	frag_meta_of(&meta, p);
	if (link != NULL)
		return send_one(m, link, &meta, frame, len);
	return send_all(m, except, &meta, frame, len);
}

static int
sign_packet(struct bc_mesh *m, struct bc_packet *p)
{
	autofree uint8_t *data = NULL;
	size_t len;
	int r;

	r = bc_packet_signing_data(p, &data, &len);
	if (r < 0)
		return r;
	r = bc_ed25519_sign(m->id.sign_priv, data, len, p->sig);
	if (r < 0)
		return r;
	p->has_sig = true;
	return 0;
}

static bool
verify_packet(const struct bc_packet *p, const uint8_t sign_pub[BC_KEY_LEN])
{
	autofree uint8_t *data = NULL;
	size_t len;

	if (!p->has_sig)
		return false;
	if (bc_packet_signing_data(p, &data, &len) < 0)
		return false;
	return bc_ed25519_verify(sign_pub, data, len, p->sig) == 0;
}

static void
packet_init(const struct bc_mesh *m, struct bc_packet *p, uint8_t type)
{
	memset(p, 0, sizeof(*p));
	p->version = 1;
	p->type = type;
	p->ttl = DEFAULT_TTL;
	p->timestamp = (uint64_t)bc_now_ms();
	memcpy(p->sender, m->id.peer_id, BC_PEER_ID_LEN);
}

int
bc_mesh_announce(struct bc_mesh *m)
{
	struct bc_announce a = {0};
	struct bc_packet p;
	autofree uint8_t *payload = NULL;
	struct peer *peer;
	size_t len;
	int r;

	ASSERT_RETURN(m != NULL, -EINVAL);

	snprintf(a.nickname, sizeof(a.nickname), "%s", m->nickname);
	memcpy(a.noise_pub, m->id.noise_pub, BC_KEY_LEN);
	memcpy(a.sign_pub, m->id.sign_pub, BC_KEY_LEN);

	for (peer = m->peers; peer != NULL; peer = peer->next) {
		if (!peer->direct || a.neighbor_count >= BC_MAX_NEIGHBORS)
			continue;
		memcpy(a.neighbors[a.neighbor_count], peer->id, BC_PEER_ID_LEN);
		a.neighbor_count++;
	}

	r = bc_announce_encode(&a, &payload, &len);
	if (r < 0)
		return r;

	packet_init(m, &p, BC_MSG_ANNOUNCE);
	p.payload = payload;
	p.payload_len = len;

	r = sign_packet(m, &p);
	if (r < 0)
		return r;

	return transmit(m, &p, NULL, NULL);
}

int
bc_mesh_leave(struct bc_mesh *m)
{
	struct bc_packet p;
	int r;

	ASSERT_RETURN(m != NULL, -EINVAL);

	/* A leave carries no payload; the sender ID is the whole message. */
	packet_init(m, &p, BC_MSG_LEAVE);

	r = sign_packet(m, &p);
	if (r < 0)
		return r;
	return transmit(m, &p, NULL, NULL);
}

/* A public message is the text itself: no envelope, no sender name. */
int
bc_mesh_send_public(struct bc_mesh *m, const char *text)
{
	struct bc_packet p;
	size_t len;
	int r;

	ASSERT_RETURN(m != NULL && text != NULL, -EINVAL);

	len = strlen(text);
	if (len == 0 || len > BC_CONTENT_MAX)
		return -EINVAL;
	if (!bc_utf8_valid(text, len))
		return -EINVAL;

	packet_init(m, &p, BC_MSG_MESSAGE);
	p.payload = (uint8_t *)(uintptr_t)text;
	p.payload_len = len;

	r = sign_packet(m, &p);
	if (r < 0)
		return r;
	return transmit(m, &p, NULL, NULL);
}

static int
send_handshake(struct bc_mesh *m, struct peer *peer)
{
	uint8_t buf[256];
	struct bc_packet p;
	long n;

	n = bc_noise_hs_write(peer->hs, NULL, 0, buf);
	if (n < 0)
		return (int)n;

	packet_init(m, &p, BC_MSG_NOISE_HANDSHAKE);
	p.has_recipient = true;
	memcpy(p.recipient, peer->id, BC_PEER_ID_LEN);
	p.payload = buf;
	p.payload_len = (size_t)n;

	return transmit(m, &p, peer->direct ? peer->link : NULL, NULL);
}

static int
start_handshake(struct bc_mesh *m, struct peer *peer)
{
	int r;

	if (peer->hs != NULL)
		return 0;

	r = bc_noise_hs_new(&peer->hs, true, m->id.noise_priv);
	if (r < 0)
		return r;
	peer->hs_initiator = true;
	return send_handshake(m, peer);
}

static int
send_noise_payload(struct bc_mesh *m, struct peer *peer, uint8_t type,
                   const uint8_t *data, size_t len)
{
	autofree uint8_t *plain = NULL;
	autofree uint8_t *cipher = NULL;
	struct bc_packet p;
	long n;

	plain = malloc(len + 1);
	if (plain == NULL)
		return -ENOMEM;
	plain[0] = type;
	memcpy(plain + 1, data, len);

	cipher = malloc(len + 1 + BC_NOISE_OVERHEAD);
	if (cipher == NULL)
		return -ENOMEM;

	n = bc_noise_encrypt(&peer->sess, plain, len + 1, cipher);
	if (n < 0)
		return (int)n;

	packet_init(m, &p, BC_MSG_NOISE_ENCRYPTED);
	p.has_recipient = true;
	memcpy(p.recipient, peer->id, BC_PEER_ID_LEN);
	p.payload = cipher;
	p.payload_len = (size_t)n;

	return transmit(m, &p, peer->direct ? peer->link : NULL, NULL);
}

int
bc_mesh_send_private(struct bc_mesh *m, const char *peer_id, const char *text,
                     char msg_id[40])
{
	uint8_t raw[BC_PEER_ID_LEN];
	autofree uint8_t *payload = NULL;
	struct peer *peer;
	char id[40];
	size_t len;
	int r;

	ASSERT_RETURN(m != NULL && peer_id != NULL && text != NULL, -EINVAL);

	if (strlen(peer_id) != BC_PEER_ID_LEN * 2 ||
	    bc_hex_decode(peer_id, raw, BC_PEER_ID_LEN) < 0)
		return -EINVAL;

	peer = peer_find(m, raw);
	if (peer == NULL)
		return -ENOENT;

	if (strlen(text) >= BC_PM_CONTENT_MAX)
		return -EMSGSIZE;
	if (!bc_utf8_valid(text, strlen(text)))
		return -EINVAL;

	bc_uuid(id);
	if (msg_id != NULL)
		memcpy(msg_id, id, sizeof(id));

	if (!peer->sess.established) {
		free(peer->pending);
		peer->pending = strdup(text);
		if (peer->pending == NULL)
			return -ENOMEM;
		memcpy(peer->pending_id, id, sizeof(id));
		return start_handshake(m, peer);
	}

	r = bc_private_message_encode(id, text, &payload, &len);
	if (r < 0)
		return r;
	return send_noise_payload(m, peer, BC_NP_PRIVATE_MESSAGE, payload, len);
}

static void
flush_pending(struct bc_mesh *m, struct peer *peer)
{
	autofree uint8_t *payload = NULL;
	char *text = peer->pending;
	size_t len;

	peer->pending = NULL;
	if (text == NULL)
		return;

	if (bc_private_message_encode(peer->pending_id, text, &payload, &len) ==
	    0)
		send_noise_payload(m, peer, BC_NP_PRIVATE_MESSAGE, payload,
		                   len);
	free(text);
}

static void
report_peer(struct bc_mesh *m, struct peer *peer, bool joined)
{
	char hex[BC_PEER_ID_LEN * 2 + 1];

	if (m->ops.on_peer == NULL)
		return;
	peer_id_hex(peer->id, hex);
	m->ops.on_peer(m->ud, hex, peer->nick, joined);
}

static void
handle_announce(struct bc_mesh *m, const struct bc_packet *p, void *link)
{
	struct bc_announce a;
	struct peer *peer;
	uint8_t fingerprint[BC_HASH_LEN];
	bool fresh;

	if (bc_announce_decode(p->payload, p->payload_len, &a) < 0)
		return;

	/* The peer ID must be the first 8 bytes of the static key digest. */
	bc_sha256(a.noise_pub, BC_KEY_LEN, fingerprint);
	if (memcmp(fingerprint, p->sender, BC_PEER_ID_LEN) != 0)
		return;

	if (!verify_packet(p, a.sign_pub)) {
		mlog(m, "announce with a bad signature dropped");
		return;
	}

	peer = peer_get(m, p->sender);
	if (peer == NULL)
		return;

	fresh = !peer->announced;
	snprintf(peer->nick, sizeof(peer->nick), "%s", a.nickname);
	memcpy(peer->noise_pub, a.noise_pub, BC_KEY_LEN);
	memcpy(peer->sign_pub, a.sign_pub, BC_KEY_LEN);
	peer->have_keys = true;
	peer->last_seen = bc_now_ms();
	if (link != NULL && p->ttl == DEFAULT_TTL) {
		peer->direct = true;
		peer->link = link;
	}

	if (fresh) {
		peer->announced = true;
		report_peer(m, peer, true);
	}
}

static void
handle_leave(struct bc_mesh *m, const struct bc_packet *p)
{
	struct peer *peer = peer_find(m, p->sender);

	if (peer == NULL)
		return;
	if (peer->have_keys && !verify_packet(p, peer->sign_pub))
		return;
	if (peer->announced)
		report_peer(m, peer, false);
	peer_drop(m, peer);
}

/*
 * The payload is the message text itself. The sender ID in the header is
 * attacker-controlled, so a message whose signature does not check against a
 * known announce is dropped rather than shown under a borrowed name.
 */
static void
handle_message(struct bc_mesh *m, const struct bc_packet *p)
{
	char text[BC_CONTENT_MAX + 1];
	char hex[BC_PEER_ID_LEN * 2 + 1];
	struct peer *peer;
	size_t len = p->payload_len;

	if (len == 0 || len > BC_CONTENT_MAX)
		return;

	peer = peer_find(m, p->sender);
	if (peer == NULL || !peer->have_keys)
		return;
	if (!verify_packet(p, peer->sign_pub))
		return;

	if (!bc_utf8_valid((const char *)p->payload, len))
		return; /* upstream drops what will not decode as UTF-8 */

	memcpy(text, p->payload, len);
	text[len] = '\0';

	peer_id_hex(p->sender, hex);
	if (m->ops.on_public != NULL)
		m->ops.on_public(m->ud, hex, peer->nick, text, p->timestamp);
}

static void
handle_noise_payload(struct bc_mesh *m, struct peer *peer, const uint8_t *data,
                     size_t len)
{
	struct bc_private_message msg;
	char hex[BC_PEER_ID_LEN * 2 + 1];
	char id[40];
	size_t idlen;

	if (len < 1)
		return;

	peer_id_hex(peer->id, hex);

	switch (data[0]) {
	case BC_NP_PRIVATE_MESSAGE:
		if (bc_private_message_decode(data + 1, len - 1, &msg) < 0)
			return;
		if (m->ops.on_private != NULL)
			m->ops.on_private(m->ud, hex, peer->nick, msg.content,
			                  (uint64_t)bc_now_ms());
		/*
		 * The message reaches the screen the moment it arrives, so
		 * both receipts are honest to send here.
		 */
		send_noise_payload(m, peer, BC_NP_DELIVERED,
		                   (const uint8_t *)msg.id, strlen(msg.id));
		send_noise_payload(m, peer, BC_NP_READ_RECEIPT,
		                   (const uint8_t *)msg.id, strlen(msg.id));
		break;
	case BC_NP_DELIVERED:
	case BC_NP_READ_RECEIPT:
		/* The payload is the original message ID as UTF-8. */
		idlen = len - 1;
		if (idlen == 0 || idlen >= sizeof(id))
			return;
		if (!bc_utf8_valid((const char *)data + 1, idlen))
			return;
		memcpy(id, data + 1, idlen);
		id[idlen] = '\0';
		if (m->ops.on_receipt != NULL)
			m->ops.on_receipt(m->ud, hex, peer->nick, id,
			                  data[0] == BC_NP_READ_RECEIPT);
		break;
	default:
		break;
	}
}

static void
handle_handshake(struct bc_mesh *m, const struct bc_packet *p, void *link)
{
	struct peer *peer;
	uint8_t payload[512];
	long n;
	int r;

	peer = peer_get(m, p->sender);
	if (peer == NULL)
		return;
	if (link != NULL) {
		peer->link = link;
		peer->direct = true;
	}
	peer->last_seen = bc_now_ms();

	/* A fresh initiation supersedes our own when their ID sorts lower. */
	if (p->payload_len == BC_KEY_LEN && peer->hs != NULL &&
	    peer->hs_initiator &&
	    memcmp(p->sender, m->id.peer_id, BC_PEER_ID_LEN) < 0) {
		bc_noise_hs_free(peer->hs);
		peer->hs = NULL;
	}

	if (peer->hs == NULL) {
		if (p->payload_len != BC_KEY_LEN)
			return;
		if (bc_noise_hs_new(&peer->hs, false, m->id.noise_priv) < 0)
			return;
		peer->hs_initiator = false;
	}

	n = bc_noise_hs_read(peer->hs, p->payload, p->payload_len, payload);
	if (n < 0) {
		mlog(m, "handshake read failed: %ld", n);
		bc_noise_hs_free(peer->hs);
		peer->hs = NULL;
		return;
	}

	if (!bc_noise_hs_done(peer->hs)) {
		if (send_handshake(m, peer) < 0)
			return;
	}

	if (!bc_noise_hs_done(peer->hs))
		return;

	r = bc_noise_hs_split(peer->hs, &peer->sess);
	bc_noise_hs_free(peer->hs);
	peer->hs = NULL;
	if (r < 0)
		return;

	mlog(m, "noise session up with %s", peer->nick);
	flush_pending(m, peer);
}

static void
handle_encrypted(struct bc_mesh *m, const struct bc_packet *p)
{
	struct peer *peer = peer_find(m, p->sender);
	autofree uint8_t *plain = NULL;
	long n;

	if (peer == NULL || !peer->sess.established)
		return;

	plain = malloc(p->payload_len);
	if (plain == NULL)
		return;

	n = bc_noise_decrypt(&peer->sess, p->payload, p->payload_len, plain);
	if (n < 0)
		return;

	handle_noise_payload(m, peer, plain, (size_t)n);
}

static void dispatch(struct bc_mesh *m, const struct bc_packet *p, void *link);

static void
handle_fragment(struct bc_mesh *m, const struct bc_packet *p, void *link)
{
	struct frag_asm *slot = NULL, *free_slot = NULL;
	uint64_t sender = 0, id = 0;
	uint16_t index, total;
	size_t i, chunk;
	int64_t now = bc_now_ms();

	if (p->payload_len < 13)
		return;

	for (i = 0; i < BC_PEER_ID_LEN; i++)
		sender = (sender << 8) | p->sender[i];
	for (i = 0; i < 8; i++)
		id = (id << 8) | p->payload[i];

	index = (uint16_t)((p->payload[8] << 8) | p->payload[9]);
	total = (uint16_t)((p->payload[10] << 8) | p->payload[11]);
	if (total == 0 || index >= total || total > FRAG_MAX_PARTS) {
		mlog(m, "fragment %u/%u out of range", index, total);
		return;
	}

	for (i = 0; i < FRAG_SLOTS; i++) {
		struct frag_asm *f = &m->frags[i];

		if (f->used && now - f->started > 30000) {
			size_t j;

			for (j = 0; j < FRAG_MAX_PARTS; j++)
				free(f->parts[j]);
			memset(f, 0, sizeof(*f));
		}
		if (f->used && f->sender == sender && f->id == id)
			slot = f;
		else if (!f->used && free_slot == NULL)
			free_slot = f;
	}

	if (slot == NULL) {
		if (free_slot == NULL)
			return;
		slot = free_slot;
		memset(slot, 0, sizeof(*slot));
		slot->used = true;
		slot->sender = sender;
		slot->id = id;
		slot->total = total;
		slot->type = p->payload[12];
		slot->started = now;
	}

	if (slot->parts[index] != NULL)
		return;

	chunk = p->payload_len - 13;
	slot->parts[index] = malloc(chunk > 0 ? chunk : 1);
	if (slot->parts[index] == NULL)
		return;
	memcpy(slot->parts[index], p->payload + 13, chunk);
	slot->part_len[index] = chunk;
	slot->size += chunk;
	slot->got++;

	if (slot->got < slot->total || slot->size > MAX_FRAME)
		return;

	{
		autofree uint8_t *frame = malloc(slot->size);
		struct bc_packet inner;

		if (frame != NULL) {
			size_t off = 0;

			for (i = 0; i < slot->total; i++) {
				memcpy(frame + off, slot->parts[i],
				       slot->part_len[i]);
				off += slot->part_len[i];
			}
			if (bc_packet_decode(frame, off, &inner) == 0) {
				dispatch(m, &inner, link);
				bc_packet_free(&inner);
			}
		}
	}

	for (i = 0; i < FRAG_MAX_PARTS; i++)
		free(slot->parts[i]);
	memset(slot, 0, sizeof(*slot));
}

/*
 * Flood control, following the upstream relay controller. The point of the
 * caps and the jitter is that duplicate suppression usually wins the race, so
 * one copy crosses each hop instead of one per link.
 */
struct relay_decision {
	bool relay;
	uint8_t ttl;
	int delay_ms;
};

static int
jitter(int lo, int hi)
{
	return lo + (int)bc_rand_below((uint32_t)(hi - lo + 1));
}

static struct relay_decision
relay_decide(const struct bc_mesh *m, const struct bc_packet *p, bool for_me)
{
	struct relay_decision d = {0};
	size_t degree = m->link_count;
	bool directed = p->has_recipient && !bc_is_broadcast(p->recipient);
	uint8_t cap = p->ttl < DEFAULT_TTL ? p->ttl : DEFAULT_TTL;
	uint8_t limit;

	/* Sync requests are link-local however much TTL a peer puts on them. */
	if (p->type == BC_MSG_REQUEST_SYNC || cap <= 1 || for_me)
		return d;

	d.relay = true;

	/* Session traffic keeps full depth: losing it costs a conversation. */
	if (p->type == BC_MSG_NOISE_HANDSHAKE ||
	    (directed && (p->type == BC_MSG_NOISE_ENCRYPTED ||
	                  p->type == BC_MSG_FRAGMENT))) {
		d.ttl = (uint8_t)(cap - 1);
		d.delay_ms = p->type == BC_MSG_NOISE_HANDSHAKE ? jitter(10, 35)
		                                               : jitter(20, 60);
		return d;
	}

	if (p->type == BC_MSG_FRAGMENT || p->type == BC_MSG_VOICE_FRAME) {
		uint8_t fcap = degree >= HIGH_DEGREE ? FRAGMENT_TTL_CAP_DENSE
		                                     : FRAGMENT_TTL_CAP;

		limit = cap < fcap ? cap : fcap;
		if (limit <= 1) {
			d.relay = false;
			return d;
		}
		d.ttl = (uint8_t)(limit - 1);
		d.delay_ms = jitter(8, 25);
		return d;
	}

	if (degree >= HIGH_DEGREE) {
		limit = cap < DENSE_TTL_CAP ? cap : DENSE_TTL_CAP;
		if (limit < 2)
			limit = 2;
	} else if (degree <= 2) {
		limit = cap; /* every hop counts in a thin chain */
	} else {
		uint8_t preferred = p->type == BC_MSG_ANNOUNCE ? 7 : 6;

		limit = cap < preferred ? cap : preferred;
		if (limit < 2)
			limit = 2;
	}
	d.ttl = (uint8_t)(limit - 1);

	/* Sparse graphs relay fast; dense ones wait longer to lose the race. */
	if (degree <= 2)
		d.delay_ms = jitter(10, 40);
	else if (degree <= 5)
		d.delay_ms = jitter(60, 150);
	else if (degree <= 9)
		d.delay_ms = jitter(80, 180);
	else
		d.delay_ms = jitter(100, 220);
	return d;
}

/*
 * Broadcasts go to a deterministic slice of the links rather than all of
 * them. Presence, fragments and sync must not be thinned: dropping one loses
 * a peer or a piece of a message, not a redundant copy.
 */
static bool
subset_relay(const struct bc_packet *p)
{
	if (p->has_recipient && !bc_is_broadcast(p->recipient))
		return false;
	return p->type != BC_MSG_FRAGMENT && p->type != BC_MSG_ANNOUNCE &&
	       p->type != BC_MSG_REQUEST_SYNC;
}

static void
schedule_relay(struct bc_mesh *m, const struct bc_packet *p,
               const uint8_t key[BC_HASH_LEN], void *ingress, bool for_me)
{
	struct relay_decision d = relay_decide(m, p, for_me);
	struct bc_packet copy = *p;
	struct relay_entry *slot = NULL;
	autofree uint8_t *frame = NULL;
	bool pad;
	size_t len, i;

	if (!d.relay)
		return;

	copy.ttl = d.ttl;
	pad = p->type == BC_MSG_NOISE_ENCRYPTED ||
	      p->type == BC_MSG_NOISE_HANDSHAKE;
	if (bc_packet_encode(&copy, pad, &frame, &len) < 0)
		return;

	for (i = 0; i < RELAY_SLOTS; i++) {
		if (!m->relays[i].used) {
			slot = &m->relays[i];
			break;
		}
	}
	if (slot == NULL)
		return;

	slot->used = true;
	slot->frame = frame;
	frame = NULL; /* steal from autofree */
	slot->len = len;
	slot->except = ingress;
	slot->subset = subset_relay(p);
	frag_meta_of(&slot->meta, &copy);
	slot->due = bc_now_ms() + d.delay_ms;
	memcpy(slot->key, key, BC_HASH_LEN);

	mlog(m, "relay type 0x%02x ttl %u->%u in %d ms%s", p->type, p->ttl,
	     d.ttl, d.delay_ms, slot->subset ? " subset" : "");
}

static void
cancel_relay(struct bc_mesh *m, const uint8_t key[BC_HASH_LEN])
{
	size_t i;

	for (i = 0; i < RELAY_SLOTS; i++) {
		struct relay_entry *e = &m->relays[i];

		if (!e->used || memcmp(e->key, key, BC_HASH_LEN) != 0)
			continue;
		free(e->frame);
		memset(e, 0, sizeof(*e));
	}
}

static void
dispatch(struct bc_mesh *m, const struct bc_packet *p, void *link)
{
	switch (p->type) {
	case BC_MSG_ANNOUNCE:
		handle_announce(m, p, link);
		break;
	case BC_MSG_MESSAGE:
		handle_message(m, p);
		break;
	case BC_MSG_LEAVE:
		handle_leave(m, p);
		break;
	case BC_MSG_NOISE_HANDSHAKE:
		handle_handshake(m, p, link);
		break;
	case BC_MSG_NOISE_ENCRYPTED:
		handle_encrypted(m, p);
		break;
	case BC_MSG_FRAGMENT:
		handle_fragment(m, p, link);
		break;
	default:
		break;
	}
}

void
bc_mesh_recv(struct bc_mesh *m, void *link, const uint8_t *frame, size_t len)
{
	struct bc_packet p;
	uint8_t key[BC_HASH_LEN];
	bool for_me, broadcast;

	if (m == NULL || frame == NULL)
		return;
	if (bc_packet_decode(frame, len, &p) < 0)
		return;

	if (memcmp(p.sender, m->id.peer_id, BC_PEER_ID_LEN) == 0) {
		bc_packet_free(&p);
		return;
	}

	packet_key(&p, key);
	if (seen_check_add(m, key)) {
		cancel_relay(m, key);
		bc_packet_free(&p);
		return;
	}

	broadcast = !p.has_recipient || bc_is_broadcast(p.recipient);
	for_me = p.has_recipient &&
	         memcmp(p.recipient, m->id.peer_id, BC_PEER_ID_LEN) == 0;

	if (broadcast || for_me)
		dispatch(m, &p, link);

	schedule_relay(m, &p, key, link, for_me);

	bc_packet_free(&p);
}

void
bc_mesh_link_up(struct bc_mesh *m, void *link)
{
	if (m == NULL ||
	    m->link_count >= sizeof(m->links) / sizeof(m->links[0]))
		return;
	/*
	 * Clear the MTU as the slot is taken and again as it is vacated:
	 * link_down swaps the last entry down, so a recycled slot would
	 * otherwise inherit a dead peer's frame size.
	 */
	m->link_mtu[m->link_count] = 0;
	m->links[m->link_count++] = link;
	m->next_announce = 0; /* announce into the new link right away */
}

void
bc_mesh_set_link_mtu(struct bc_mesh *m, const void *link, size_t max_frame)
{
	size_t i;

	if (m == NULL || link == NULL)
		return;

	for (i = 0; i < m->link_count; i++)
		if (m->links[i] == link)
			m->link_mtu[i] = max_frame;
}

void
bc_mesh_link_rssi(struct bc_mesh *m, const void *link, int rssi)
{
	struct peer *p;

	if (m == NULL || link == NULL)
		return;

	for (p = m->peers; p != NULL; p = p->next)
		if (p->link == link) {
			p->rssi = rssi;
			p->rssi_at = bc_now_ms();
		}
}

void
bc_mesh_link_down(struct bc_mesh *m, const void *link)
{
	struct peer *p, *next;
	size_t i;

	if (m == NULL)
		return;

	for (i = 0; i < m->link_count; i++) {
		if (m->links[i] != link)
			continue;
		m->links[i] = m->links[m->link_count - 1];
		m->link_mtu[i] = m->link_mtu[m->link_count - 1];
		m->link_mtu[m->link_count - 1] = 0;
		m->link_count--;
		break;
	}

	/*
	 * A dropped radio link is not a departure. Links flap constantly, and
	 * a peer stays reachable for as long as its last announce is fresh,
	 * so peers are kept here and retired by the staleness sweep or by an
	 * explicit leave.
	 */
	for (p = m->peers; p != NULL; p = next) {
		next = p->next;
		if (p->link != link)
			continue;
		p->direct = false;
		p->link = NULL;
	}
}

/* Links per subset relay: two or fewer means all of them, else ~log2 + 1. */
static size_t
subset_size(size_t degree)
{
	size_t value, bits = 0;

	if (degree <= 2)
		return degree;

	for (value = degree - 1; value > 0; value >>= 1)
		bits++;
	return bits + 1 < degree ? bits + 1 : degree;
}

/*
 * Score each link by a digest of the packet key and the link, then take the
 * lowest few. Every node scores the same packet differently because the links
 * differ, so the slices overlap and the mesh stays covered.
 */
static void
relay_emit(struct bc_mesh *m, const struct relay_entry *e)
{
	uint8_t scores[64][8]; /* digest prefix is enough to order links */
	size_t degree = m->link_count;
	size_t want, i, j, sent = 0;

	if (!e->subset || degree <= 2 || degree > 64) {
		send_all(m, e->except, &e->meta, e->frame, e->len);
		return;
	}

	want = subset_size(degree);
	for (i = 0; i < degree; i++) {
		uint8_t seed[BC_HASH_LEN + sizeof(void *)];

		memcpy(seed, e->key, BC_HASH_LEN);
		memcpy(seed + BC_HASH_LEN, &m->links[i], sizeof(void *));
		{
			uint8_t digest[BC_HASH_LEN];

			bc_sha256(seed, sizeof(seed), digest);
			memcpy(scores[i], digest, sizeof(scores[i]));
		}
	}

	while (sent < want) {
		size_t best = degree;

		for (j = 0; j < degree; j++) {
			if (scores[j][0] == 0xff && scores[j][1] == 0xff)
				continue; /* already taken */
			if (m->links[j] == e->except)
				continue;
			if (best == degree || memcmp(scores[j], scores[best],
			                             sizeof(scores[j])) < 0)
				best = j;
		}
		if (best == degree)
			break;

		send_one(m, m->links[best], &e->meta, e->frame, e->len);
		scores[best][0] = 0xff;
		scores[best][1] = 0xff;
		sent++;
	}
}

int
bc_mesh_timeout(struct bc_mesh *m)
{
	int64_t now = bc_now_ms();
	int64_t next;
	size_t i;

	if (m == NULL)
		return -1;

	next = m->next_announce;
	if (m->next_sweep < next)
		next = m->next_sweep;
	for (i = 0; i < RELAY_SLOTS; i++)
		if (m->relays[i].used && m->relays[i].due < next)
			next = m->relays[i].due;

	if (next <= now)
		return 0;
	if (next - now > 1000)
		return 1000;
	return (int)(next - now);
}

void
bc_mesh_tick(struct bc_mesh *m)
{
	int64_t now = bc_now_ms();
	struct peer *p, *next;
	size_t i;

	if (m == NULL)
		return;

	for (i = 0; i < RELAY_SLOTS; i++) {
		struct relay_entry *e = &m->relays[i];

		if (!e->used || e->due > now)
			continue;
		relay_emit(m, e);
		free(e->frame);
		memset(e, 0, sizeof(*e));
	}

	if (now >= m->next_announce) {
		bc_mesh_announce(m);
		if (m->link_count == 0)
			m->next_announce = now + ANNOUNCE_ALONE_MS;
		else
			m->next_announce = now + ANNOUNCE_LINKED_MS +
			                   bc_rand_below(ANNOUNCE_LINKED_MS);
	}

	if (now >= m->next_sweep) {
		m->next_sweep = now + 5000;
		for (p = m->peers; p != NULL; p = next) {
			next = p->next;
			if (now - p->last_seen < PEER_STALE_MS)
				continue;
			if (p->announced)
				report_peer(m, p, false);
			peer_drop(m, p);
		}
	}
}

size_t
bc_mesh_peers(struct bc_mesh *m, struct bc_peer_info *out, size_t max)
{
	struct peer *p;
	size_t n = 0;

	if (m == NULL || out == NULL)
		return 0;

	for (p = m->peers; p != NULL && n < max; p = p->next) {
		if (!p->announced)
			continue;
		peer_id_hex(p->id, out[n].peer_id);
		snprintf(out[n].nickname, sizeof(out[n].nickname), "%s",
		         p->nick);
		out[n].direct = p->direct;
		out[n].encrypted = p->sess.established;
		out[n].rssi = p->rssi;
		out[n].rssi_age_ms = p->rssi_at ? bc_now_ms() - p->rssi_at : 0;
		out[n].last_seen_ms = p->last_seen;
		n++;
	}
	return n;
}

const char *
bc_mesh_nickname(const struct bc_mesh *m)
{
	return m->nickname;
}

void
bc_mesh_set_nickname(struct bc_mesh *m, const char *nickname)
{
	if (m == NULL || nickname == NULL)
		return;
	snprintf(m->nickname, sizeof(m->nickname), "%s", nickname);
	m->next_announce = 0;
}

bool
bc_mesh_resolve_peer(struct bc_mesh *m, const char *needle,
                     char out[BC_PEER_ID_LEN * 2 + 1])
{
	struct peer *p;
	size_t len;

	if (m == NULL || needle == NULL || needle[0] == '\0')
		return false;
	len = strlen(needle);

	for (p = m->peers; p != NULL; p = p->next) {
		char hex[BC_PEER_ID_LEN * 2 + 1];

		peer_id_hex(p->id, hex);
		if (strncmp(hex, needle, len) == 0 ||
		    strncmp(p->nick, needle, len) == 0) {
			memcpy(out, hex, sizeof(hex));
			return true;
		}
	}
	return false;
}

int
bc_mesh_new(struct bc_mesh **ret, const struct bc_identity *id,
            const char *nickname, const struct bc_mesh_ops *ops, void *ud)
{
	struct bc_mesh *m;

	ASSERT_RETURN(ret != NULL && id != NULL && ops != NULL, -EINVAL);

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return -ENOMEM;

	m->id = *id;
	m->ops = *ops;
	m->ud = ud;
	snprintf(m->nickname, sizeof(m->nickname), "%s",
	         nickname != NULL ? nickname : "anon");

	*ret = m;
	return 0;
}

void
bc_mesh_free(struct bc_mesh *m)
{
	size_t i, j;

	if (m == NULL)
		return;

	while (m->peers != NULL)
		peer_drop(m, m->peers);

	for (i = 0; i < RELAY_SLOTS; i++)
		free(m->relays[i].frame);
	for (i = 0; i < FRAG_SLOTS; i++)
		for (j = 0; j < FRAG_MAX_PARTS; j++)
			free(m->frags[i].parts[j]);

	free(m);
}
