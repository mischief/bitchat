// SPDX-License-Identifier: ISC
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/internal.h"

#define TLV_NICKNAME 0x01
#define TLV_NOISE_PUB 0x02
#define TLV_SIGN_PUB 0x03
#define TLV_NEIGHBORS 0x04

struct wbuf {
	uint8_t *p;
	size_t len;
	size_t cap;
	bool oom;
};

static void
wput(struct wbuf *b, const void *data, size_t len)
{
	if (b->oom || len == 0)
		return;
	if (b->len + len > b->cap) {
		size_t cap = b->cap ? b->cap * 2 : 128;
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
wu8(struct wbuf *b, uint8_t v)
{
	wput(b, &v, 1);
}

static void
wtlv(struct wbuf *b, uint8_t type, const void *val, size_t len)
{
	if (len > 255)
		return;
	wu8(b, type);
	wu8(b, (uint8_t)len);
	wput(b, val, len);
}

static int
wfinish(struct wbuf *b, uint8_t **out, size_t *outlen)
{
	if (b->oom) {
		free(b->p);
		return -ENOMEM;
	}
	*out = b->p;
	*outlen = b->len;
	return 0;
}

int
bc_announce_encode(const struct bc_announce *a, uint8_t **out, size_t *outlen)
{
	struct wbuf b = {0};

	ASSERT_RETURN(a != NULL && out != NULL && outlen != NULL, -EINVAL);

	wtlv(&b, TLV_NICKNAME, a->nickname, strlen(a->nickname));
	wtlv(&b, TLV_NOISE_PUB, a->noise_pub, BC_KEY_LEN);
	wtlv(&b, TLV_SIGN_PUB, a->sign_pub, BC_KEY_LEN);
	if (a->neighbor_count > 0)
		wtlv(&b, TLV_NEIGHBORS, a->neighbors,
		     (size_t)a->neighbor_count * BC_PEER_ID_LEN);

	return wfinish(&b, out, outlen);
}

int
bc_announce_decode(const uint8_t *in, size_t len, struct bc_announce *out)
{
	size_t off = 0;
	bool have_nick = false, have_noise = false, have_sign = false;

	ASSERT_RETURN(in != NULL && out != NULL, -EINVAL);

	memset(out, 0, sizeof(*out));

	while (off + 2 <= len) {
		uint8_t type = in[off];
		size_t vlen = in[off + 1];
		const uint8_t *val = in + off + 2;

		if (off + 2 + vlen > len)
			return -EBADMSG;
		off += 2 + vlen;

		switch (type) {
		case TLV_NICKNAME:
			if (!bc_utf8_valid((const char *)val, vlen))
				return -EBADMSG;
			if (vlen >= sizeof(out->nickname)) {
				memcpy(out->nickname, val,
				       sizeof(out->nickname) - 1);
				out->nickname[sizeof(out->nickname) - 1] = '\0';
				vlen = bc_utf8_truncate(
				    out->nickname, sizeof(out->nickname) - 1);
			} else {
				memcpy(out->nickname, val, vlen);
			}
			out->nickname[vlen] = '\0';
			have_nick = true;
			break;
		case TLV_NOISE_PUB:
			if (vlen != BC_KEY_LEN)
				return -EBADMSG;
			memcpy(out->noise_pub, val, BC_KEY_LEN);
			have_noise = true;
			break;
		case TLV_SIGN_PUB:
			if (vlen != BC_KEY_LEN)
				return -EBADMSG;
			memcpy(out->sign_pub, val, BC_KEY_LEN);
			have_sign = true;
			break;
		case TLV_NEIGHBORS:
			if (vlen == 0 || vlen % BC_PEER_ID_LEN != 0)
				break;
			out->neighbor_count = (uint8_t)(vlen / BC_PEER_ID_LEN);
			if (out->neighbor_count > BC_MAX_NEIGHBORS)
				out->neighbor_count = BC_MAX_NEIGHBORS;
			memcpy(out->neighbors, val,
			       (size_t)out->neighbor_count * BC_PEER_ID_LEN);
			break;
		default:
			break; /* unknown TLV: skip, stay forward compatible */
		}
	}

	if (!have_nick || !have_noise || !have_sign)
		return -EBADMSG;
	return 0;
}

/* Rejects overlong forms, surrogates and anything past U+10FFFF. */
bool
bc_utf8_valid(const char *s, size_t len)
{
	const uint8_t *p = (const uint8_t *)s;
	size_t i = 0;

	if (s == NULL)
		return false;

	while (i < len) {
		uint8_t c = p[i];
		size_t need;
		uint32_t cp;
		size_t j;

		if (c < 0x80) {
			i++;
			continue;
		}
		if (c >= 0xc2 && c <= 0xdf) {
			need = 1;
			cp = c & 0x1fu;
		} else if (c >= 0xe0 && c <= 0xef) {
			need = 2;
			cp = c & 0x0fu;
		} else if (c >= 0xf0 && c <= 0xf4) {
			need = 3;
			cp = c & 0x07u;
		} else {
			return false;
		}

		if (i + need >= len)
			return false;

		for (j = 1; j <= need; j++) {
			uint8_t cc = p[i + j];

			if ((cc & 0xc0) != 0x80)
				return false;
			cp = (cp << 6) | (cc & 0x3fu);
		}

		if (need == 2 && cp < 0x800)
			return false;
		if (need == 3 && cp < 0x10000)
			return false;
		if (cp > 0x10ffff)
			return false;
		if (cp >= 0xd800 && cp <= 0xdfff)
			return false;

		i += need + 1;
	}
	return true;
}

size_t
bc_utf8_truncate(const char *s, size_t max)
{
	size_t len;

	if (s == NULL)
		return 0;

	len = strlen(s);
	if (len <= max)
		return len;

	/* Step back off the continuation bytes of a split sequence. */
	len = max;
	while (len > 0 && ((uint8_t)s[len] & 0xc0) == 0x80)
		len--;
	return len;
}

bool
bc_mentions(const char *text, const char *nick)
{
	size_t nicklen;
	const char *at;

	if (text == NULL || nick == NULL || nick[0] == '\0')
		return false;
	nicklen = strlen(nick);

	for (at = strchr(text, '@'); at != NULL; at = strchr(at + 1, '@')) {
		char next;

		if (strncmp(at + 1, nick, nicklen) != 0)
			continue;
		next = at[1 + nicklen];
		if (next == '\0' || next == '#' ||
		    !(isalnum((unsigned char)next) || next == '_'))
			return true;
	}
	return false;
}

void
bc_uuid(char buf[40])
{
	uint8_t r[16];
	char hex[33];

	if (bc_random(r, sizeof(r)) < 0)
		memset(r, 0, sizeof(r));
	r[6] = (uint8_t)((r[6] & 0x0f) | 0x40);
	r[8] = (uint8_t)((r[8] & 0x3f) | 0x80);
	bc_hex_encode(r, sizeof(r), hex);
	snprintf(buf, 40, "%.8s-%.4s-%.4s-%.4s-%.12s", hex, hex + 8, hex + 12,
	         hex + 16, hex + 20);
}

/* TLV 0x00 is the message ID, 0x01 the text. Both cap at 255 bytes. */
#define PM_TLV_ID 0x00
#define PM_TLV_CONTENT 0x01

int
bc_private_message_encode(const char *id, const char *content, uint8_t **out,
                          size_t *outlen)
{
	struct wbuf b = {0};

	ASSERT_RETURN(id != NULL && content != NULL, -EINVAL);
	ASSERT_RETURN(out != NULL && outlen != NULL, -EINVAL);

	if (strlen(id) > 255 || strlen(content) > 255)
		return -EMSGSIZE;

	wtlv(&b, PM_TLV_ID, id, strlen(id));
	wtlv(&b, PM_TLV_CONTENT, content, strlen(content));

	return wfinish(&b, out, outlen);
}

int
bc_private_message_decode(const uint8_t *in, size_t len,
                          struct bc_private_message *out)
{
	size_t off = 0;
	bool have_id = false, have_content = false;

	ASSERT_RETURN(in != NULL && out != NULL, -EINVAL);

	memset(out, 0, sizeof(*out));

	while (off + 2 <= len) {
		uint8_t type = in[off];
		size_t vlen = in[off + 1];
		const uint8_t *val = in + off + 2;
		char *dst;
		size_t cap;

		if (off + 2 + vlen > len)
			return -EBADMSG;
		off += 2 + vlen;

		switch (type) {
		case PM_TLV_ID:
			dst = out->id;
			cap = sizeof(out->id);
			have_id = true;
			break;
		case PM_TLV_CONTENT:
			dst = out->content;
			cap = sizeof(out->content);
			have_content = true;
			break;
		default:
			return -EBADMSG; /* upstream rejects unknown types */
		}

		if (!bc_utf8_valid((const char *)val, vlen))
			return -EBADMSG;
		if (vlen >= cap)
			return -EMSGSIZE;
		memcpy(dst, val, vlen);
		dst[vlen] = '\0';
	}

	if (!have_id || !have_content)
		return -EBADMSG;
	return 0;
}
