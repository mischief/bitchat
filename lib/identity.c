// SPDX-License-Identifier: ISC
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "lib/internal.h"

void
bc_identity_derive(struct bc_identity *id)
{
	bc_sha256(id->noise_pub, BC_KEY_LEN, id->fingerprint);
	memcpy(id->peer_id, id->fingerprint, BC_PEER_ID_LEN);
}

int
bc_identity_default_path(char *buf, size_t len)
{
	const char *cfg = getenv("XDG_CONFIG_HOME");
	const char *home = getenv("HOME");
	int n;

	if (cfg != NULL && cfg[0] != '\0')
		n = snprintf(buf, len, "%s/bitchat/identity", cfg);
	else if (home != NULL && home[0] != '\0')
		n = snprintf(buf, len, "%s/.config/bitchat/identity", home);
	else
		return -ENOENT;

	if (n < 0 || (size_t)n >= len)
		return -ENAMETOOLONG;
	return 0;
}

static int
mkdir_parents(const char *path)
{
	autofree char *copy = strdup(path);
	char *slash;

	if (copy == NULL)
		return -ENOMEM;

	for (slash = copy + 1; *slash != '\0'; slash++) {
		if (*slash != '/')
			continue;
		*slash = '\0';
		if (mkdir(copy, 0700) < 0 && errno != EEXIST)
			return -errno;
		*slash = '/';
	}
	return 0;
}

static int
identity_save(const struct bc_identity *id, const char *path)
{
	autoclose int fd = -1;
	uint8_t blob[BC_KEY_LEN * 2];
	ssize_t w;
	int r;

	r = mkdir_parents(path);
	if (r < 0)
		return r;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;

	memcpy(blob, id->noise_priv, BC_KEY_LEN);
	memcpy(blob + BC_KEY_LEN, id->sign_priv, BC_KEY_LEN);

	w = write(fd, blob, sizeof(blob));
	OPENSSL_cleanse(blob, sizeof(blob));
	if (w != (ssize_t)sizeof(blob))
		return -EIO;
	return 0;
}

int
bc_identity_load(struct bc_identity *id, const char *path)
{
	autoclose int fd = -1;
	uint8_t blob[BC_KEY_LEN * 2];
	ssize_t n;
	int r;

	ASSERT_RETURN(id != NULL && path != NULL, -EINVAL);

	memset(id, 0, sizeof(*id));

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			return -errno;

		r = bc_x25519_keygen(id->noise_priv, id->noise_pub);
		if (r < 0)
			return r;
		r = bc_ed25519_keygen(id->sign_priv, id->sign_pub);
		if (r < 0)
			return r;
		bc_identity_derive(id);
		return identity_save(id, path);
	}

	n = read(fd, blob, sizeof(blob));
	if (n != (ssize_t)sizeof(blob))
		return -EBADMSG;

	memcpy(id->noise_priv, blob, BC_KEY_LEN);
	memcpy(id->sign_priv, blob + BC_KEY_LEN, BC_KEY_LEN);
	OPENSSL_cleanse(blob, sizeof(blob));

	r = bc_x25519_pub(id->noise_priv, id->noise_pub);
	if (r < 0)
		return r;
	r = bc_ed25519_pub(id->sign_priv, id->sign_pub);
	if (r < 0)
		return r;

	bc_identity_derive(id);
	return 0;
}
