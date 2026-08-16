// SPDX-License-Identifier: ISC
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "lib/internal.h"

#define PROTOCOL_NAME "Noise_XX_25519_ChaChaPoly_SHA256"

struct bc_noise_hs {
	uint8_t h[BC_HASH_LEN];
	uint8_t ck[BC_HASH_LEN];
	uint8_t k[BC_KEY_LEN];
	bool has_k;
	uint64_t n;

	uint8_t s_priv[BC_KEY_LEN], s_pub[BC_KEY_LEN];
	uint8_t e_priv[BC_KEY_LEN], e_pub[BC_KEY_LEN];
	uint8_t rs[BC_KEY_LEN], re[BC_KEY_LEN];
	bool have_rs, have_re;

	bool initiator;
	int step; /* handshake messages processed so far */
};

/*
 * h = SHA-256(h || data). Streamed: a skipped mix would leave the transcript
 * one input short and desynchronise every later key without any visible error.
 */
static void
mix_hash(struct bc_noise_hs *hs, const uint8_t *data, size_t len)
{
	bc_sha256_two(hs->h, BC_HASH_LEN, data, len, hs->h);
}

static void
mix_key(struct bc_noise_hs *hs, const uint8_t *ikm, size_t len)
{
	uint8_t ck[BC_HASH_LEN], k[BC_HASH_LEN];

	bc_hkdf(hs->ck, ikm, len, ck, k, NULL);
	memcpy(hs->ck, ck, BC_HASH_LEN);
	memcpy(hs->k, k, BC_KEY_LEN);
	hs->has_k = true;
	hs->n = 0;
}

static long
encrypt_and_hash(struct bc_noise_hs *hs, const uint8_t *in, size_t len,
                 uint8_t *out)
{
	long r;

	if (!hs->has_k) {
		memcpy(out, in, len);
		mix_hash(hs, out, len);
		return (long)len;
	}
	r = bc_aead_seal(hs->k, hs->n++, hs->h, BC_HASH_LEN, in, len, out);
	if (r < 0)
		return r;
	mix_hash(hs, out, (size_t)r);
	return r;
}

static long
decrypt_and_hash(struct bc_noise_hs *hs, const uint8_t *in, size_t len,
                 uint8_t *out)
{
	long r;

	if (!hs->has_k) {
		memcpy(out, in, len);
		mix_hash(hs, in, len);
		return (long)len;
	}
	r = bc_aead_open(hs->k, hs->n++, hs->h, BC_HASH_LEN, in, len, out);
	if (r < 0)
		return r;
	mix_hash(hs, in, len);
	return r;
}

static int
dh_mix(struct bc_noise_hs *hs, const uint8_t priv[BC_KEY_LEN],
       const uint8_t pub[BC_KEY_LEN])
{
	uint8_t shared[BC_KEY_LEN];
	int r;

	r = bc_x25519_dh(priv, pub, shared);
	if (r < 0)
		return r;
	mix_key(hs, shared, sizeof(shared));
	OPENSSL_cleanse(shared, sizeof(shared));
	return 0;
}

int
bc_noise_hs_new(struct bc_noise_hs **ret, bool initiator,
                const uint8_t static_priv[BC_KEY_LEN])
{
	struct bc_noise_hs *hs;
	const char *name = PROTOCOL_NAME;
	size_t namelen = strlen(name);
	int r;

	ASSERT_RETURN(ret != NULL && static_priv != NULL, -EINVAL);

	hs = calloc(1, sizeof(*hs));
	if (hs == NULL)
		return -ENOMEM;

	if (namelen <= BC_HASH_LEN)
		memcpy(hs->h, name, namelen);
	else
		bc_sha256((const uint8_t *)name, namelen, hs->h);
	memcpy(hs->ck, hs->h, BC_HASH_LEN);

	hs->initiator = initiator;
	memcpy(hs->s_priv, static_priv, BC_KEY_LEN);
	r = bc_x25519_pub(hs->s_priv, hs->s_pub);
	if (r < 0) {
		free(hs);
		return r;
	}
	r = bc_x25519_keygen(hs->e_priv, hs->e_pub);
	if (r < 0) {
		free(hs);
		return r;
	}

	mix_hash(hs, NULL, 0); /* empty prologue */
	*ret = hs;
	return 0;
}

void
bc_noise_hs_free(struct bc_noise_hs *hs)
{
	if (hs == NULL)
		return;
	OPENSSL_cleanse(hs, sizeof(*hs));
	free(hs);
}

bool
bc_noise_hs_done(const struct bc_noise_hs *hs)
{
	return hs != NULL && hs->step >= 3;
}

void
bc_noise_hs_hash(const struct bc_noise_hs *hs, uint8_t out[BC_HASH_LEN])
{
	memcpy(out, hs->h, BC_HASH_LEN);
}

/* XX: -> e | <- e, ee, s, es | -> s, se */
long
bc_noise_hs_write(struct bc_noise_hs *hs, const uint8_t *payload, size_t len,
                  uint8_t *out)
{
	size_t off = 0;
	long r;

	ASSERT_RETURN(hs != NULL && out != NULL, -EINVAL);

	switch (hs->step) {
	case 0:
		if (!hs->initiator)
			return -EPROTO;
		memcpy(out, hs->e_pub, BC_KEY_LEN);
		mix_hash(hs, hs->e_pub, BC_KEY_LEN);
		off = BC_KEY_LEN;
		break;
	case 1:
		if (hs->initiator)
			return -EPROTO;
		memcpy(out, hs->e_pub, BC_KEY_LEN);
		mix_hash(hs, hs->e_pub, BC_KEY_LEN);
		off = BC_KEY_LEN;
		if (dh_mix(hs, hs->e_priv, hs->re) < 0)
			return -EIO;
		r = encrypt_and_hash(hs, hs->s_pub, BC_KEY_LEN, out + off);
		if (r < 0)
			return r;
		off += (size_t)r;
		if (dh_mix(hs, hs->s_priv, hs->re) < 0)
			return -EIO;
		break;
	case 2:
		if (!hs->initiator)
			return -EPROTO;
		r = encrypt_and_hash(hs, hs->s_pub, BC_KEY_LEN, out);
		if (r < 0)
			return r;
		off = (size_t)r;
		if (dh_mix(hs, hs->s_priv, hs->re) < 0)
			return -EIO;
		break;
	default:
		return -EPROTO;
	}

	r = encrypt_and_hash(hs, payload, len, out + off);
	if (r < 0)
		return r;
	off += (size_t)r;
	hs->step++;
	return (long)off;
}

long
bc_noise_hs_read(struct bc_noise_hs *hs, const uint8_t *in, size_t len,
                 uint8_t *payload_out)
{
	size_t off = 0;
	long r;

	ASSERT_RETURN(hs != NULL && in != NULL, -EINVAL);

	switch (hs->step) {
	case 0:
		if (hs->initiator || len < BC_KEY_LEN)
			return -EPROTO;
		memcpy(hs->re, in, BC_KEY_LEN);
		hs->have_re = true;
		mix_hash(hs, hs->re, BC_KEY_LEN);
		off = BC_KEY_LEN;
		break;
	case 1: {
		uint8_t rs[BC_KEY_LEN + BC_AEAD_TAG_LEN];

		if (!hs->initiator || len < BC_KEY_LEN * 2 + BC_AEAD_TAG_LEN)
			return -EPROTO;
		memcpy(hs->re, in, BC_KEY_LEN);
		hs->have_re = true;
		mix_hash(hs, hs->re, BC_KEY_LEN);
		off = BC_KEY_LEN;
		if (dh_mix(hs, hs->e_priv, hs->re) < 0)
			return -EIO;
		r = decrypt_and_hash(hs, in + off, BC_KEY_LEN + BC_AEAD_TAG_LEN,
		                     rs);
		if (r != BC_KEY_LEN)
			return -EBADMSG;
		memcpy(hs->rs, rs, BC_KEY_LEN);
		hs->have_rs = true;
		off += BC_KEY_LEN + BC_AEAD_TAG_LEN;
		if (dh_mix(hs, hs->e_priv, hs->rs) < 0)
			return -EIO;
		break;
	}
	case 2: {
		uint8_t rs[BC_KEY_LEN + BC_AEAD_TAG_LEN];

		if (hs->initiator || len < BC_KEY_LEN + BC_AEAD_TAG_LEN)
			return -EPROTO;
		r = decrypt_and_hash(hs, in, BC_KEY_LEN + BC_AEAD_TAG_LEN, rs);
		if (r != BC_KEY_LEN)
			return -EBADMSG;
		memcpy(hs->rs, rs, BC_KEY_LEN);
		hs->have_rs = true;
		off = BC_KEY_LEN + BC_AEAD_TAG_LEN;
		if (dh_mix(hs, hs->e_priv, hs->rs) < 0)
			return -EIO;
		break;
	}
	default:
		return -EPROTO;
	}

	{
		uint8_t scratch[512];

		if (len - off > sizeof(scratch) && payload_out == NULL)
			return -EMSGSIZE;
		r = decrypt_and_hash(hs, in + off, len - off,
		                     payload_out ? payload_out : scratch);
		if (r < 0)
			return r;
	}
	hs->step++;
	return r;
}

int
bc_noise_hs_split(struct bc_noise_hs *hs, struct bc_noise_session *out)
{
	uint8_t k1[BC_HASH_LEN], k2[BC_HASH_LEN];

	ASSERT_RETURN(hs != NULL && out != NULL, -EINVAL);
	if (hs->step < 3)
		return -EAGAIN;

	bc_hkdf(hs->ck, NULL, 0, k1, k2, NULL);

	memset(out, 0, sizeof(*out));
	if (hs->initiator) {
		memcpy(out->send_key, k1, BC_KEY_LEN);
		memcpy(out->recv_key, k2, BC_KEY_LEN);
	} else {
		memcpy(out->send_key, k2, BC_KEY_LEN);
		memcpy(out->recv_key, k1, BC_KEY_LEN);
	}
	memcpy(out->remote_static, hs->rs, BC_KEY_LEN);
	memcpy(out->handshake_hash, hs->h, BC_HASH_LEN);
	out->established = true;

	OPENSSL_cleanse(k1, sizeof(k1));
	OPENSSL_cleanse(k2, sizeof(k2));
	return 0;
}

/* Has this nonce already been accepted, or fallen out of the window? */
static bool
replay_ok(const struct bc_noise_session *s, uint64_t nonce)
{
	uint64_t window = BC_REPLAY_WINDOW_BYTES * 8;
	size_t offset, byte, bit;

	if (s->highest_recv >= window && nonce <= s->highest_recv - window)
		return false;
	if (nonce > s->highest_recv)
		return true;

	offset = (size_t)(s->highest_recv - nonce);
	byte = offset / 8;
	bit = offset % 8;
	return (s->replay_window[byte] & (1u << bit)) == 0;
}

static void
replay_mark(struct bc_noise_session *s, uint64_t nonce)
{
	size_t offset, byte, bit;

	if (nonce > s->highest_recv) {
		uint64_t shift = nonce - s->highest_recv;

		if (shift >= BC_REPLAY_WINDOW_BYTES * 8) {
			memset(s->replay_window, 0, sizeof(s->replay_window));
		} else {
			size_t i;

			for (i = BC_REPLAY_WINDOW_BYTES; i-- > 0;) {
				uint8_t v = 0;

				if (i >= shift / 8) {
					size_t src = i - (size_t)(shift / 8);

					v = (uint8_t)(s->replay_window[src] >>
					              (shift % 8));
					if (src > 0 && shift % 8 != 0)
						v |= (uint8_t)(s->replay_window
						                   [src - 1]
						               << (8 -
						                   shift % 8));
				}
				s->replay_window[i] = v;
			}
		}
		s->highest_recv = nonce;
		s->replay_window[0] |= 1;
		return;
	}

	offset = (size_t)(s->highest_recv - nonce);
	byte = offset / 8;
	bit = offset % 8;
	s->replay_window[byte] |= (uint8_t)(1u << bit);
}

long
bc_noise_encrypt(struct bc_noise_session *s, const uint8_t *in, size_t len,
                 uint8_t *out)
{
	uint64_t nonce;
	long r;
	int i;

	ASSERT_RETURN(s != NULL && s->established, -EINVAL);

	/* The wire nonce is four bytes wide; rekey before it wraps. */
	if (s->send_nonce >= 0xfffffffeULL)
		return -EOVERFLOW;

	nonce = s->send_nonce++;
	for (i = 0; i < BC_NOISE_NONCE_LEN; i++)
		out[i] = (uint8_t)((nonce >> ((3 - i) * 8)) & 0xff);

	r = bc_aead_seal(s->send_key, nonce, NULL, 0, in, len,
	                 out + BC_NOISE_NONCE_LEN);
	if (r < 0)
		return r;
	return r + BC_NOISE_NONCE_LEN;
}

long
bc_noise_decrypt(struct bc_noise_session *s, const uint8_t *in, size_t len,
                 uint8_t *out)
{
	uint64_t nonce = 0;
	long r;
	int i;

	ASSERT_RETURN(s != NULL && s->established, -EINVAL);

	if (len < BC_NOISE_OVERHEAD)
		return -EBADMSG;

	for (i = 0; i < BC_NOISE_NONCE_LEN; i++)
		nonce = (nonce << 8) | in[i];

	if (!replay_ok(s, nonce))
		return -EBADMSG;

	r = bc_aead_open(s->recv_key, nonce, NULL, 0, in + BC_NOISE_NONCE_LEN,
	                 len - BC_NOISE_NONCE_LEN, out);
	if (r < 0)
		return r;

	replay_mark(s, nonce);
	return r;
}
