// SPDX-License-Identifier: ISC
#include <errno.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "lib/internal.h"

int
bc_random(void *buf, size_t len)
{
	if (RAND_bytes(buf, (int)len) != 1)
		return -EIO;
	return 0;
}

void
bc_sha256(const uint8_t *in, size_t len, uint8_t out[BC_HASH_LEN])
{
	SHA256(in, len, out);
}

/* SHA-256 over two buffers, without joining them first. */
void
bc_sha256_two(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
              uint8_t out[BC_HASH_LEN])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int outlen = BC_HASH_LEN;

	if (ctx == NULL)
		return;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    (alen == 0 || EVP_DigestUpdate(ctx, a, alen) == 1) &&
	    (blen == 0 || EVP_DigestUpdate(ctx, b, blen) == 1))
		EVP_DigestFinal_ex(ctx, out, &outlen);
	EVP_MD_CTX_free(ctx);
}

void
bc_hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *in, size_t len,
               uint8_t out[BC_HASH_LEN])
{
	unsigned int outlen = BC_HASH_LEN;

	HMAC(EVP_sha256(), key, (int)keylen, in, len, out, &outlen);
}

/*
 * Noise HKDF. temp = HMAC(ck, ikm); each output is HMAC(temp, prev || i).
 */
void
bc_hkdf(const uint8_t ck[BC_HASH_LEN], const uint8_t *ikm, size_t ikmlen,
        uint8_t *o1, uint8_t *o2, uint8_t *o3)
{
	uint8_t temp[BC_HASH_LEN];
	uint8_t buf[BC_HASH_LEN + 1];
	uint8_t out1[BC_HASH_LEN], out2[BC_HASH_LEN];

	bc_hmac_sha256(ck, BC_HASH_LEN, ikm, ikmlen, temp);

	buf[0] = 1;
	bc_hmac_sha256(temp, BC_HASH_LEN, buf, 1, out1);
	if (o1 != NULL)
		memcpy(o1, out1, BC_HASH_LEN);

	memcpy(buf, out1, BC_HASH_LEN);
	buf[BC_HASH_LEN] = 2;
	bc_hmac_sha256(temp, BC_HASH_LEN, buf, sizeof(buf), out2);
	if (o2 != NULL)
		memcpy(o2, out2, BC_HASH_LEN);

	if (o3 != NULL) {
		memcpy(buf, out2, BC_HASH_LEN);
		buf[BC_HASH_LEN] = 3;
		bc_hmac_sha256(temp, BC_HASH_LEN, buf, sizeof(buf), o3);
	}

	OPENSSL_cleanse(temp, sizeof(temp));
	OPENSSL_cleanse(out1, sizeof(out1));
	OPENSSL_cleanse(out2, sizeof(out2));
}

static int
raw_keygen(int type, uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN])
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key = NULL;
	size_t len;
	int r = -EIO;

	ctx = EVP_PKEY_CTX_new_id(type, NULL);
	if (ctx == NULL)
		return -ENOMEM;
	if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <= 0)
		goto out;

	len = BC_KEY_LEN;
	if (EVP_PKEY_get_raw_private_key(key, priv, &len) <= 0)
		goto out;
	len = BC_KEY_LEN;
	if (EVP_PKEY_get_raw_public_key(key, pub, &len) <= 0)
		goto out;
	r = 0;
out:
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);
	return r;
}

static int
raw_pub(int type, const uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN])
{
	EVP_PKEY *key;
	size_t len = BC_KEY_LEN;
	int r = -EIO;

	key = EVP_PKEY_new_raw_private_key(type, NULL, priv, BC_KEY_LEN);
	if (key == NULL)
		return -EINVAL;
	if (EVP_PKEY_get_raw_public_key(key, pub, &len) > 0)
		r = 0;
	EVP_PKEY_free(key);
	return r;
}

int
bc_x25519_keygen(uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN])
{
	return raw_keygen(EVP_PKEY_X25519, priv, pub);
}

int
bc_x25519_pub(const uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN])
{
	return raw_pub(EVP_PKEY_X25519, priv, pub);
}

int
bc_x25519_dh(const uint8_t priv[BC_KEY_LEN], const uint8_t peer[BC_KEY_LEN],
             uint8_t out[BC_KEY_LEN])
{
	EVP_PKEY *mine = NULL, *theirs = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	size_t len = BC_KEY_LEN;
	int r = -EIO;

	mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv,
	                                    BC_KEY_LEN);
	theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer,
	                                     BC_KEY_LEN);
	if (mine == NULL || theirs == NULL) {
		r = -EINVAL;
		goto out;
	}

	ctx = EVP_PKEY_CTX_new(mine, NULL);
	if (ctx == NULL) {
		r = -ENOMEM;
		goto out;
	}
	if (EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(ctx, theirs) <= 0 ||
	    EVP_PKEY_derive(ctx, out, &len) <= 0)
		goto out;
	r = 0;
out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(theirs);
	EVP_PKEY_free(mine);
	return r;
}

int
bc_ed25519_keygen(uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN])
{
	return raw_keygen(EVP_PKEY_ED25519, priv, pub);
}

int
bc_ed25519_pub(const uint8_t priv[BC_KEY_LEN], uint8_t pub[BC_KEY_LEN])
{
	return raw_pub(EVP_PKEY_ED25519, priv, pub);
}

int
bc_ed25519_sign(const uint8_t priv[BC_KEY_LEN], const uint8_t *msg, size_t len,
                uint8_t sig[64])
{
	EVP_PKEY *key;
	EVP_MD_CTX *ctx = NULL;
	size_t siglen = 64;
	int r = -EIO;

	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv,
	                                   BC_KEY_LEN);
	if (key == NULL)
		return -EINVAL;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		r = -ENOMEM;
		goto out;
	}
	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) <= 0)
		goto out;
	if (EVP_DigestSign(ctx, sig, &siglen, msg, len) <= 0)
		goto out;
	r = 0;
out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return r;
}

int
bc_ed25519_verify(const uint8_t pub[BC_KEY_LEN], const uint8_t *msg, size_t len,
                  const uint8_t sig[64])
{
	EVP_PKEY *key;
	EVP_MD_CTX *ctx = NULL;
	int r = -EBADMSG;

	key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub,
	                                  BC_KEY_LEN);
	if (key == NULL)
		return -EINVAL;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		r = -ENOMEM;
		goto out;
	}
	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) <= 0)
		goto out;
	if (EVP_DigestVerify(ctx, sig, 64, msg, len) == 1)
		r = 0;
out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return r;
}

/* Noise nonce: four zero bytes then the counter, little endian. */
static void
aead_nonce(uint64_t counter, uint8_t nonce[12])
{
	size_t i;

	memset(nonce, 0, 4);
	for (i = 0; i < 8; i++)
		nonce[4 + i] = (uint8_t)((counter >> (i * 8)) & 0xff);
}

long
bc_aead_seal(const uint8_t key[BC_KEY_LEN], uint64_t counter, const uint8_t *ad,
             size_t adlen, const uint8_t *in, size_t len, uint8_t *out)
{
	EVP_CIPHER_CTX *ctx;
	uint8_t nonce[12];
	int outl = 0;
	long r = -EIO;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return -ENOMEM;

	aead_nonce(counter, nonce);
	if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key,
	                       nonce) != 1)
		goto out;
	if (adlen > 0 &&
	    EVP_EncryptUpdate(ctx, NULL, &outl, ad, (int)adlen) != 1)
		goto out;
	if (len > 0 && EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) != 1)
		goto out;
	if (EVP_EncryptFinal_ex(ctx, out + outl, &outl) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, BC_AEAD_TAG_LEN,
	                        out + len) != 1)
		goto out;
	r = (long)(len + BC_AEAD_TAG_LEN);
out:
	EVP_CIPHER_CTX_free(ctx);
	return r;
}

long
bc_aead_open(const uint8_t key[BC_KEY_LEN], uint64_t counter, const uint8_t *ad,
             size_t adlen, const uint8_t *in, size_t len, uint8_t *out)
{
	EVP_CIPHER_CTX *ctx;
	uint8_t nonce[12];
	uint8_t tag[BC_AEAD_TAG_LEN];
	size_t body;
	int outl = 0;
	long r = -EBADMSG;

	if (len < BC_AEAD_TAG_LEN)
		return -EBADMSG;
	body = len - BC_AEAD_TAG_LEN;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return -ENOMEM;

	aead_nonce(counter, nonce);
	memcpy(tag, in + body, BC_AEAD_TAG_LEN);

	if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key,
	                       nonce) != 1)
		goto out;
	if (adlen > 0 &&
	    EVP_DecryptUpdate(ctx, NULL, &outl, ad, (int)adlen) != 1)
		goto out;
	if (body > 0 && EVP_DecryptUpdate(ctx, out, &outl, in, (int)body) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, BC_AEAD_TAG_LEN,
	                        tag) != 1)
		goto out;
	if (EVP_DecryptFinal_ex(ctx, out + outl, &outl) != 1)
		goto out;
	r = (long)body;
out:
	EVP_CIPHER_CTX_free(ctx);
	return r;
}
