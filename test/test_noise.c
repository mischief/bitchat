// SPDX-License-Identifier: ISC
#include <assert.h>
#include <string.h>

#include "bitchat/crypto.h"
#include "bitchat/noise.h"

static void
test_primitives(void)
{
	uint8_t priv[32], pub[32], priv2[32], pub2[32];
	uint8_t s1[32], s2[32];
	uint8_t sig[64];
	uint8_t plain[16], cipher[64], back[64];
	const char *msg = "grug sign rock";
	long n;

	assert(bc_x25519_keygen(priv, pub) == 0);
	assert(bc_x25519_keygen(priv2, pub2) == 0);
	assert(bc_x25519_dh(priv, pub2, s1) == 0);
	assert(bc_x25519_dh(priv2, pub, s2) == 0);
	assert(memcmp(s1, s2, sizeof(s1)) == 0);

	assert(bc_ed25519_keygen(priv, pub) == 0);
	assert(bc_ed25519_sign(priv, (const uint8_t *)msg, strlen(msg), sig) ==
	       0);
	assert(bc_ed25519_verify(pub, (const uint8_t *)msg, strlen(msg), sig) ==
	       0);
	sig[0] ^= 0xff;
	assert(bc_ed25519_verify(pub, (const uint8_t *)msg, strlen(msg), sig) <
	       0);

	memset(plain, 0x5a, sizeof(plain));
	memset(s1, 0x11, sizeof(s1));
	n = bc_aead_seal(s1, 3, NULL, 0, plain, sizeof(plain), cipher);
	assert(n == (long)sizeof(plain) + BC_AEAD_TAG_LEN);
	assert(bc_aead_open(s1, 4, NULL, 0, cipher, (size_t)n, back) < 0);
	assert(bc_aead_open(s1, 3, NULL, 0, cipher, (size_t)n, back) ==
	       (long)sizeof(plain));
	assert(memcmp(plain, back, sizeof(plain)) == 0);
}

/*
 * The protocol name is exactly 32 bytes, so it becomes the initial h verbatim.
 * After the empty prologue is mixed in, h is its SHA-256 -- a value computed
 * outside this implementation, which pins the transcript to the specification.
 */
static void
test_initial_hash(void)
{
	struct bc_noise_hs *hs = NULL;
	uint8_t priv[32], pub[32];
	uint8_t h[32], want[32];
	const char *name = "Noise_XX_25519_ChaChaPoly_SHA256";

	assert(strlen(name) == 32);
	assert(bc_x25519_keygen(priv, pub) == 0);
	assert(bc_noise_hs_new(&hs, true, priv) == 0);

	bc_noise_hs_hash(hs, h);
	bc_sha256((const uint8_t *)name, 32, want);
	assert(memcmp(h, want, sizeof(h)) == 0);

	bc_noise_hs_free(hs);
}

/* Drive a full XX handshake between two peers, then talk both ways. */
static void
test_handshake(void)
{
	uint8_t apriv[32], apub[32], bpriv[32], bpub[32];
	struct bc_noise_hs *ini = NULL, *res = NULL;
	struct bc_noise_session sa, sb;
	static uint8_t m1[256], m2[256], m3[256], payload[256];
	static uint8_t cipher[256], plain[256];
	long n1, n2, n3, n;

	assert(bc_x25519_keygen(apriv, apub) == 0);
	assert(bc_x25519_keygen(bpriv, bpub) == 0);

	assert(bc_noise_hs_new(&ini, true, apriv) == 0);
	assert(bc_noise_hs_new(&res, false, bpriv) == 0);

	n1 = bc_noise_hs_write(ini, NULL, 0, m1);
	assert(n1 == 32);
	assert(bc_noise_hs_read(res, m1, (size_t)n1, payload) == 0);

	n2 = bc_noise_hs_write(res, NULL, 0, m2);
	assert(n2 == 96);
	assert(bc_noise_hs_read(ini, m2, (size_t)n2, payload) == 0);

	n3 = bc_noise_hs_write(ini, NULL, 0, m3);
	assert(n3 == 64);
	assert(bc_noise_hs_read(res, m3, (size_t)n3, payload) == 0);

	assert(bc_noise_hs_done(ini) && bc_noise_hs_done(res));
	assert(bc_noise_hs_split(ini, &sa) == 0);
	assert(bc_noise_hs_split(res, &sb) == 0);

	/* Each side learned the other's static key and the same hash. */
	assert(memcmp(sa.remote_static, bpub, 32) == 0);
	assert(memcmp(sb.remote_static, apub, 32) == 0);
	assert(memcmp(sa.handshake_hash, sb.handshake_hash, 32) == 0);

	/* Wire framing: <nonce[4] big endian><ciphertext><tag[16]>. */
	n = bc_noise_encrypt(&sa, (const uint8_t *)"ping", 4, cipher);
	assert(n == 4 + BC_NOISE_OVERHEAD);
	assert(cipher[0] == 0 && cipher[1] == 0 && cipher[2] == 0 &&
	       cipher[3] == 0);
	assert(bc_noise_decrypt(&sb, cipher, (size_t)n, plain) == 4);
	assert(memcmp(plain, "ping", 4) == 0);

	n = bc_noise_encrypt(&sb, (const uint8_t *)"pong", 4, cipher);
	assert(bc_noise_decrypt(&sa, cipher, (size_t)n, plain) == 4);
	assert(memcmp(plain, "pong", 4) == 0);

	bc_noise_hs_free(ini);
	bc_noise_hs_free(res);
}

/* Out-of-order frames are readable; a repeat of one is not. */
static void
test_replay_window(void)
{
	static uint8_t frames[4][64];
	struct bc_noise_session send = {0}, recv = {0};
	uint8_t plain[64];
	long lens[4];
	int i;

	memset(send.send_key, 0x42, BC_KEY_LEN);
	memcpy(recv.recv_key, send.send_key, BC_KEY_LEN);
	send.established = recv.established = true;

	for (i = 0; i < 4; i++) {
		uint8_t body[2] = {(uint8_t)i, 0};

		lens[i] =
		    bc_noise_encrypt(&send, body, sizeof(body), frames[i]);
		assert(lens[i] > 0);
		assert(frames[i][3] == (uint8_t)i); /* counter on the wire */
	}

	assert(bc_noise_decrypt(&recv, frames[3], (size_t)lens[3], plain) == 2);
	assert(plain[0] == 3);
	assert(bc_noise_decrypt(&recv, frames[1], (size_t)lens[1], plain) == 2);
	assert(plain[0] == 1);
	assert(bc_noise_decrypt(&recv, frames[1], (size_t)lens[1], plain) < 0);
	assert(bc_noise_decrypt(&recv, frames[0], (size_t)lens[0], plain) == 2);

	/* A truncated frame carries no room for a nonce and a tag. */
	assert(bc_noise_decrypt(&recv, frames[2], 8, plain) < 0);
}

int
main(void)
{
	test_primitives();
	test_initial_hash();
	test_handshake();
	test_replay_window();
	return 0;
}
