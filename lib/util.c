// SPDX-License-Identifier: ISC
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <zlib.h>

#include "lib/internal.h"

int64_t
bc_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint32_t
bc_rand_below(uint32_t n)
{
	uint32_t v;

	if (n == 0)
		return 0;
	if (bc_random(&v, sizeof(v)) < 0)
		return 0;
	return v % n;
}

/*
 * Upstream compresses a payload of 100 bytes or more whose distinct byte
 * count, over a 256-byte yardstick, stays under 90%. Signatures cover the
 * encoded frame, so this rule has to match byte for byte or verification
 * fails on the peer.
 */
bool
bc_should_compress(const uint8_t *data, size_t len)
{
	bool seen[256] = {false};
	size_t unique = 0, sample, i;

	if (len < 100)
		return false;

	for (i = 0; i < len; i++) {
		if (seen[data[i]])
			continue;
		seen[data[i]] = true;
		unique++;
	}

	sample = len < 256 ? len : 256;
	return (double)unique / (double)sample < 0.9;
}

/* windowBits -15 selects a raw deflate stream, with no zlib wrapper. */
int
bc_deflate(const uint8_t *in, size_t len, uint8_t **out, size_t *outlen)
{
	z_stream z = {0};
	uLong bound;
	uint8_t *buf;
	int r;

	if (deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8,
	                 Z_DEFAULT_STRATEGY) != Z_OK)
		return -ENOMEM;

	bound = deflateBound(&z, (uLong)len);
	buf = malloc(bound);
	if (buf == NULL) {
		deflateEnd(&z);
		return -ENOMEM;
	}

	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)len;
	z.next_out = buf;
	z.avail_out = (uInt)bound;

	r = deflate(&z, Z_FINISH);
	if (r != Z_STREAM_END) {
		deflateEnd(&z);
		free(buf);
		return -EIO;
	}
	*outlen = z.total_out;
	deflateEnd(&z);
	*out = buf;
	return 0;
}

int
bc_inflate(const uint8_t *in, size_t len, size_t original, uint8_t **out)
{
	z_stream z = {0};
	uint8_t *buf;
	int r;

	buf = malloc(original);
	if (buf == NULL)
		return -ENOMEM;

	if (inflateInit2(&z, -15) != Z_OK) {
		free(buf);
		return -ENOMEM;
	}

	z.next_in = (Bytef *)(uintptr_t)in;
	z.avail_in = (uInt)len;
	z.next_out = buf;
	z.avail_out = (uInt)original;

	r = inflate(&z, Z_FINISH);
	inflateEnd(&z);
	if (r != Z_STREAM_END || z.total_out != original) {
		free(buf);
		return -EBADMSG;
	}
	*out = buf;
	return 0;
}
