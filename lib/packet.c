// SPDX-License-Identifier: ISC
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "lib/internal.h"

#define V1_HEADER 14
#define V2_HEADER 16

#define FLAG_RECIPIENT 0x01
#define FLAG_SIGNATURE 0x02
#define FLAG_COMPRESSED 0x04
#define FLAG_ROUTE 0x08
#define FLAG_RSR 0x10

bool
bc_is_broadcast(const uint8_t id[BC_PEER_ID_LEN])
{
	size_t i;

	for (i = 0; i < BC_PEER_ID_LEN; i++)
		if (id[i] != 0xff)
			return false;
	return true;
}

void
bc_hex_encode(const uint8_t *in, size_t len, char *out)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2] = hex[in[i] >> 4];
		out[i * 2 + 1] = hex[in[i] & 0x0f];
	}
	out[len * 2] = '\0';
}

static int
hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int
bc_hex_decode(const char *in, uint8_t *out, size_t outlen)
{
	size_t i;

	for (i = 0; i < outlen; i++) {
		int hi = hex_nibble(in[i * 2]);
		int lo = hi < 0 ? -1 : hex_nibble(in[i * 2 + 1]);

		if (lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

/* A growable output buffer used only while encoding. */
struct buf {
	uint8_t *p;
	size_t len;
	size_t cap;
	bool oom;
};

static void
buf_put(struct buf *b, const void *data, size_t len)
{
	if (b->oom)
		return;
	if (b->len + len > b->cap) {
		size_t cap = b->cap ? b->cap * 2 : 256;
		uint8_t *n;

		while (cap < b->len + len)
			cap *= 2;
		n = realloc(b->p, cap);
		if (n == NULL) {
			b->oom = true;
			return;
		}
		b->p = n;
		b->cap = cap;
	}
	memcpy(b->p + b->len, data, len);
	b->len += len;
}

static void
buf_u8(struct buf *b, uint8_t v)
{
	buf_put(b, &v, 1);
}

static void
buf_be16(struct buf *b, uint16_t v)
{
	uint8_t t[2] = {(uint8_t)(v >> 8), (uint8_t)v};

	buf_put(b, t, sizeof(t));
}

static void
buf_be32(struct buf *b, uint32_t v)
{
	uint8_t t[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16),
	                (uint8_t)(v >> 8), (uint8_t)v};

	buf_put(b, t, sizeof(t));
}

static void
buf_be64(struct buf *b, uint64_t v)
{
	int i;

	for (i = 56; i >= 0; i -= 8)
		buf_u8(b, (uint8_t)((v >> i) & 0xff));
}

static size_t
optimal_block(size_t len)
{
	static const size_t blocks[] = {256, 512, 1024, 2048};
	size_t total = len + 16;
	size_t i;

	for (i = 0; i < sizeof(blocks) / sizeof(blocks[0]); i++)
		if (total <= blocks[i])
			return blocks[i];
	return len;
}

/* PKCS#7-style: every pad byte holds the pad length, so it must fit a byte. */
static void
pad_buf(struct buf *b)
{
	size_t target = optimal_block(b->len);
	size_t need;
	uint8_t byte;

	if (b->len >= target)
		return;
	need = target - b->len;
	if (need > 255)
		return;
	byte = (uint8_t)need;
	while (need-- > 0)
		buf_u8(b, byte);
}

/* padlen == len unpads to nothing. Upstream allows it, so this does too. */
static size_t
unpad_len(const uint8_t *buf, size_t len)
{
	size_t padlen, i;

	if (len == 0)
		return len;
	padlen = buf[len - 1];
	if (padlen == 0 || padlen > len)
		return len;
	for (i = len - padlen; i < len; i++)
		if (buf[i] != buf[len - 1])
			return len;
	return len - padlen;
}

int
bc_packet_encode(const struct bc_packet *p, bool pad, uint8_t **out,
                 size_t *outlen)
{
	struct buf b = {0};
	autofree uint8_t *comp = NULL;
	const uint8_t *payload = p->payload;
	size_t payload_len = p->payload_len;
	size_t orig_len = 0;
	size_t lenfield;
	bool compressed = false;
	bool has_route;
	uint8_t flags = 0;

	ASSERT_RETURN(p != NULL && out != NULL && outlen != NULL, -EINVAL);
	ASSERT_RETURN(p->version == 1 || p->version == 2, -EINVAL);

	lenfield = p->version == 2 ? 4 : 2;
	has_route = p->version >= 2 && p->route_len > 0;

	if (bc_should_compress(payload, payload_len)) {
		size_t clen = 0;

		if (bc_deflate(payload, payload_len, &comp, &clen) == 0 &&
		    clen < payload_len) {
			orig_len = payload_len;
			payload = comp;
			payload_len = clen;
			compressed = true;
		}
	}

	if (p->version == 1 &&
	    payload_len + (compressed ? lenfield : 0) > 0xffff)
		return -EMSGSIZE;

	if (p->has_recipient)
		flags |= FLAG_RECIPIENT;
	if (p->has_sig)
		flags |= FLAG_SIGNATURE;
	if (compressed)
		flags |= FLAG_COMPRESSED;
	if (has_route)
		flags |= FLAG_ROUTE;
	if (p->is_rsr)
		flags |= FLAG_RSR;

	buf_u8(&b, p->version);
	buf_u8(&b, p->type);
	buf_u8(&b, p->ttl);
	buf_be64(&b, p->timestamp);
	buf_u8(&b, flags);

	if (p->version == 2)
		buf_be32(&b,
		         (uint32_t)(payload_len + (compressed ? lenfield : 0)));
	else
		buf_be16(&b,
		         (uint16_t)(payload_len + (compressed ? lenfield : 0)));

	buf_put(&b, p->sender, BC_PEER_ID_LEN);
	if (p->has_recipient)
		buf_put(&b, p->recipient, BC_PEER_ID_LEN);

	if (has_route) {
		uint8_t i;

		buf_u8(&b, p->route_len);
		for (i = 0; i < p->route_len; i++)
			buf_put(&b, p->route[i], BC_PEER_ID_LEN);
	}

	if (compressed) {
		if (p->version == 2)
			buf_be32(&b, (uint32_t)orig_len);
		else
			buf_be16(&b, (uint16_t)orig_len);
	}

	buf_put(&b, payload, payload_len);

	if (p->has_sig)
		buf_put(&b, p->sig, BC_SIG_LEN);

	if (pad)
		pad_buf(&b);

	if (b.oom) {
		free(b.p);
		return -ENOMEM;
	}

	*out = b.p;
	*outlen = b.len;
	return 0;
}

/* A bounds-checked cursor over one inbound frame. */
struct cur {
	const uint8_t *p;
	size_t len;
	size_t off;
	bool bad;
};

static const uint8_t *
cur_take(struct cur *c, size_t n)
{
	const uint8_t *at;

	if (c->bad || c->off + n > c->len) {
		c->bad = true;
		return NULL;
	}
	at = c->p + c->off;
	c->off += n;
	return at;
}

static uint8_t
cur_u8(struct cur *c)
{
	const uint8_t *at = cur_take(c, 1);

	return at ? *at : 0;
}

static uint16_t
cur_be16(struct cur *c)
{
	const uint8_t *at = cur_take(c, 2);

	return at ? (uint16_t)((at[0] << 8) | at[1]) : 0;
}

static uint32_t
cur_be32(struct cur *c)
{
	const uint8_t *at = cur_take(c, 4);

	if (at == NULL)
		return 0;
	return ((uint32_t)at[0] << 24) | ((uint32_t)at[1] << 16) |
	       ((uint32_t)at[2] << 8) | at[3];
}

static uint64_t
cur_be64(struct cur *c)
{
	const uint8_t *at = cur_take(c, 8);
	uint64_t v = 0;
	int i;

	if (at == NULL)
		return 0;
	for (i = 0; i < 8; i++)
		v = (v << 8) | at[i];
	return v;
}

static int
decode_core(const uint8_t *buf, size_t len, struct bc_packet *out)
{
	struct cur c = {.p = buf, .len = len};
	autofree uint8_t *payload = NULL;
	size_t lenfield, payload_len;
	uint8_t flags;
	bool compressed, has_route;

	memset(out, 0, sizeof(*out));

	if (len < V1_HEADER + BC_PEER_ID_LEN)
		return -EBADMSG;

	out->version = cur_u8(&c);
	if (out->version != 1 && out->version != 2)
		return -EBADMSG;
	lenfield = out->version == 2 ? 4 : 2;
	if (len < (out->version == 2 ? V2_HEADER : V1_HEADER) + BC_PEER_ID_LEN)
		return -EBADMSG;

	out->type = cur_u8(&c);
	out->ttl = cur_u8(&c);
	out->timestamp = cur_be64(&c);
	flags = cur_u8(&c);

	out->has_recipient = (flags & FLAG_RECIPIENT) != 0;
	out->has_sig = (flags & FLAG_SIGNATURE) != 0;
	out->is_rsr = (flags & FLAG_RSR) != 0;
	compressed = (flags & FLAG_COMPRESSED) != 0;
	has_route = out->version >= 2 && (flags & FLAG_ROUTE) != 0;

	payload_len = out->version == 2 ? cur_be32(&c) : cur_be16(&c);
	if (payload_len > BC_MAX_PAYLOAD)
		return -EBADMSG;

	{
		const uint8_t *at = cur_take(&c, BC_PEER_ID_LEN);

		if (at == NULL)
			return -EBADMSG;
		memcpy(out->sender, at, BC_PEER_ID_LEN);
	}

	if (out->has_recipient) {
		const uint8_t *at = cur_take(&c, BC_PEER_ID_LEN);

		if (at == NULL)
			return -EBADMSG;
		memcpy(out->recipient, at, BC_PEER_ID_LEN);
	}

	if (has_route) {
		uint8_t count = cur_u8(&c);
		uint8_t i;

		if (count > BC_MAX_ROUTE_HOPS)
			return -EBADMSG;
		for (i = 0; i < count; i++) {
			const uint8_t *at = cur_take(&c, BC_PEER_ID_LEN);

			if (at == NULL)
				return -EBADMSG;
			memcpy(out->route[i], at, BC_PEER_ID_LEN);
		}
		out->route_len = count;
	}

	if (compressed) {
		size_t original, csize;
		const uint8_t *at;

		if (payload_len < lenfield)
			return -EBADMSG;
		original = out->version == 2 ? cur_be32(&c) : cur_be16(&c);
		csize = payload_len - lenfield;
		if (original == 0 || original > BC_MAX_PAYLOAD || csize == 0)
			return -EBADMSG;
		/* A wild ratio means a decompression bomb. */
		if (original / csize > 50000)
			return -EBADMSG;
		at = cur_take(&c, csize);
		if (at == NULL)
			return -EBADMSG;
		if (bc_inflate(at, csize, original, &payload) < 0)
			return -EBADMSG;
		payload_len = original;
	} else {
		const uint8_t *at = cur_take(&c, payload_len);

		if (at == NULL)
			return -EBADMSG;
		payload = malloc(payload_len > 0 ? payload_len : 1);
		if (payload == NULL)
			return -ENOMEM;
		memcpy(payload, at, payload_len);
	}

	if (out->has_sig) {
		const uint8_t *at = cur_take(&c, BC_SIG_LEN);

		if (at == NULL)
			return -EBADMSG;
		memcpy(out->sig, at, BC_SIG_LEN);
	}

	if (c.bad)
		return -EBADMSG;

	out->payload = payload;
	payload = NULL; /* steal from autofree */
	out->payload_len = payload_len;
	return 0;
}

int
bc_packet_decode(const uint8_t *buf, size_t len, struct bc_packet *out)
{
	size_t unpadded;

	ASSERT_RETURN(buf != NULL && out != NULL, -EINVAL);

	if (decode_core(buf, len, out) == 0)
		return 0;

	unpadded = unpad_len(buf, len);
	if (unpadded == len)
		return -EBADMSG;
	return decode_core(buf, unpadded, out);
}

int
bc_packet_signing_data(const struct bc_packet *p, uint8_t **out, size_t *outlen)
{
	struct bc_packet copy;

	ASSERT_RETURN(p != NULL, -EINVAL);

	copy = *p;
	copy.ttl = 0;
	copy.has_sig = false;
	copy.is_rsr = false;
	return bc_packet_encode(&copy, true, out, outlen);
}

void
bc_packet_free(struct bc_packet *p)
{
	if (p == NULL)
		return;
	free(p->payload);
	p->payload = NULL;
	p->payload_len = 0;
}
