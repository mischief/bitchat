// SPDX-License-Identifier: ISC
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bitchat/packet.h"
#include "bitchat/tlv.h"

static void
test_roundtrip(void)
{
	struct bc_packet p = {0}, out;
	uint8_t *frame = NULL;
	size_t len;

	p.version = 1;
	p.type = BC_MSG_MESSAGE;
	p.ttl = 7;
	p.timestamp = 1750000000000ULL;
	memset(p.sender, 0xab, sizeof(p.sender));
	p.payload = (uint8_t *)"hello mesh";
	p.payload_len = 10;

	assert(bc_packet_encode(&p, false, &frame, &len) == 0);
	assert(len == 14 + 8 + 10);
	assert(bc_packet_decode(frame, len, &out) == 0);
	assert(out.type == BC_MSG_MESSAGE);
	assert(out.ttl == 7);
	assert(out.timestamp == p.timestamp);
	assert(out.payload_len == 10);
	assert(memcmp(out.payload, "hello mesh", 10) == 0);
	assert(!out.has_recipient && !out.has_sig);

	bc_packet_free(&out);
	free(frame);
}

static void
test_padded_directed(void)
{
	struct bc_packet p = {0}, out;
	uint8_t *frame = NULL;
	size_t len;

	p.version = 1;
	p.type = BC_MSG_NOISE_ENCRYPTED;
	p.ttl = 3;
	p.timestamp = 42;
	memset(p.sender, 0x11, sizeof(p.sender));
	memset(p.recipient, 0x22, sizeof(p.recipient));
	p.has_recipient = true;
	p.has_sig = true;
	memset(p.sig, 0x33, sizeof(p.sig));
	p.payload = (uint8_t *)"secret";
	p.payload_len = 6;

	assert(bc_packet_encode(&p, true, &frame, &len) == 0);
	assert(len == 256); /* padded to the first bucket */
	assert(bc_packet_decode(frame, len, &out) == 0);
	assert(out.has_recipient && out.has_sig);
	assert(out.payload_len == 6);
	assert(memcmp(out.payload, "secret", 6) == 0);
	assert(out.sig[0] == 0x33);

	bc_packet_free(&out);
	free(frame);
}

/* A payload over the threshold is deflated, and inflates back unchanged. */
static void
test_compression(void)
{
	static uint8_t body[2048];
	struct bc_packet p = {0}, out;
	uint8_t *frame = NULL;
	size_t len, i;

	for (i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)('a' + (i % 4));

	p.version = 2;
	p.type = BC_MSG_MESSAGE;
	p.ttl = 5;
	p.timestamp = 7;
	p.payload = body;
	p.payload_len = sizeof(body);

	assert(bc_packet_encode(&p, false, &frame, &len) == 0);
	assert(len < sizeof(body));
	assert(bc_packet_decode(frame, len, &out) == 0);
	assert(out.payload_len == sizeof(body));
	assert(memcmp(out.payload, body, sizeof(body)) == 0);

	bc_packet_free(&out);
	free(frame);
}

/*
 * Signature checks re-encode a received packet, so the compression decision
 * must be reproducible. Upstream compresses at 100 bytes and up, and only
 * when the payload has enough repetition.
 */
static void
test_compression_boundary(void)
{
	static uint8_t body[200];
	struct bc_packet p = {0}, out;
	uint8_t *frame = NULL, *again = NULL;
	size_t len, relen, i;

	memset(body, 'a', sizeof(body));

	p.version = 1;
	p.type = BC_MSG_MESSAGE;
	p.ttl = 7;
	p.timestamp = 11;
	p.payload = body;

	/* 99 bytes stays raw; 100 bytes of the same filler compresses. */
	p.payload_len = 99;
	assert(bc_packet_encode(&p, false, &frame, &len) == 0);
	assert(len == 14 + 8 + 99);
	free(frame);
	frame = NULL;

	p.payload_len = 100;
	assert(bc_packet_encode(&p, false, &frame, &len) == 0);
	assert(len < 14 + 8 + 100);
	free(frame);
	frame = NULL;

	/* High-entropy payloads are left alone whatever their size. */
	for (i = 0; i < sizeof(body); i++)
		body[i] = (uint8_t)i;
	p.payload_len = sizeof(body);
	assert(bc_packet_encode(&p, false, &frame, &len) == 0);
	assert(len == 14 + 8 + sizeof(body));

	/* Decoding and re-encoding must reproduce the bytes byte for byte. */
	assert(bc_packet_decode(frame, len, &out) == 0);
	assert(bc_packet_encode(&out, false, &again, &relen) == 0);
	assert(relen == len && memcmp(again, frame, len) == 0);

	bc_packet_free(&out);
	free(again);
	free(frame);
}

static void
test_route(void)
{
	struct bc_packet p = {0}, out;
	uint8_t *frame = NULL;
	size_t len;

	p.version = 2;
	p.type = BC_MSG_MESSAGE;
	p.ttl = 4;
	p.timestamp = 9;
	p.route_len = 2;
	memset(p.route[0], 0xa1, BC_PEER_ID_LEN);
	memset(p.route[1], 0xa2, BC_PEER_ID_LEN);
	p.payload = (uint8_t *)"x";
	p.payload_len = 1;

	assert(bc_packet_encode(&p, false, &frame, &len) == 0);
	assert(bc_packet_decode(frame, len, &out) == 0);
	assert(out.route_len == 2);
	assert(out.route[1][0] == 0xa2);

	bc_packet_free(&out);
	free(frame);
}

static void
test_bad_input(void)
{
	struct bc_packet out;
	uint8_t junk[64];

	memset(junk, 0, sizeof(junk));
	assert(bc_packet_decode(junk, sizeof(junk), &out) < 0);
	assert(bc_packet_decode(junk, 3, &out) < 0);

	junk[0] = 1;
	junk[13] = 0xff; /* payload length far beyond the frame */
	assert(bc_packet_decode(junk, sizeof(junk), &out) < 0);
}

static void
test_announce_tlv(void)
{
	struct bc_announce a = {0}, out;
	uint8_t *buf = NULL;
	size_t len;

	snprintf(a.nickname, sizeof(a.nickname), "caveman");
	memset(a.noise_pub, 0x01, sizeof(a.noise_pub));
	memset(a.sign_pub, 0x02, sizeof(a.sign_pub));
	a.neighbor_count = 2;
	memset(a.neighbors[0], 0x03, BC_PEER_ID_LEN);
	memset(a.neighbors[1], 0x04, BC_PEER_ID_LEN);

	assert(bc_announce_encode(&a, &buf, &len) == 0);
	assert(bc_announce_decode(buf, len, &out) == 0);
	assert(strcmp(out.nickname, "caveman") == 0);
	assert(out.noise_pub[0] == 0x01 && out.sign_pub[0] == 0x02);
	assert(out.neighbor_count == 2 && out.neighbors[1][0] == 0x04);

	free(buf);
}

static void
test_private_message_tlv(void)
{
	struct bc_private_message out;
	uint8_t *buf = NULL;
	char id[40];
	size_t len;

	bc_uuid(id);
	assert(bc_private_message_encode(id, "rock good", &buf, &len) == 0);
	/* TLV 0x00 id, TLV 0x01 content, both length-prefixed. */
	assert(len == 2 + strlen(id) + 2 + 9);
	assert(buf[0] == 0x00 && buf[1] == (uint8_t)strlen(id));

	assert(bc_private_message_decode(buf, len, &out) == 0);
	assert(strcmp(out.id, id) == 0);
	assert(strcmp(out.content, "rock good") == 0);

	/* An unknown TLV type is a parse failure, as upstream treats it. */
	buf[0] = 0x7f;
	assert(bc_private_message_decode(buf, len, &out) < 0);

	free(buf);
}

static void
test_utf8(void)
{
	static struct bc_announce a, out;
	uint8_t *buf = NULL;
	size_t len;

	assert(bc_utf8_valid("plain ascii", 11));
	assert(bc_utf8_valid("caf\xc3\xa9", 5));
	assert(bc_utf8_valid("\xf0\x9f\xa6\xb4", 4));  /* bone emoji */
	assert(!bc_utf8_valid("\xc3", 1));             /* truncated */
	assert(!bc_utf8_valid("\xc0\xaf", 2));         /* overlong */
	assert(!bc_utf8_valid("\xed\xa0\x80", 3));     /* surrogate */
	assert(!bc_utf8_valid("\xf5\x80\x80\x80", 4)); /* past U+10FFFF */

	/* Truncation lands on a character boundary, never inside one. */
	assert(bc_utf8_truncate("caf\xc3\xa9", 4) == 3);
	assert(bc_utf8_truncate("caf\xc3\xa9", 5) == 5);
	assert(bc_utf8_truncate("abc", 10) == 3);

	/* A nickname that is not UTF-8 makes the whole announce invalid. */
	snprintf(a.nickname, sizeof(a.nickname), "caf\xc3\xa9");
	assert(bc_announce_encode(&a, &buf, &len) == 0);
	assert(bc_announce_decode(buf, len, &out) == 0);
	assert(strcmp(out.nickname, "caf\xc3\xa9") == 0);
	buf[3] = 0xff;
	assert(bc_announce_decode(buf, len, &out) < 0);
	free(buf);
}

static void
test_mentions(void)
{
	/* A bare name, and the #abcd suffix upstream allows. */
	assert(bc_mentions("hey @grug look", "grug"));
	assert(bc_mentions("@grug", "grug"));
	assert(bc_mentions("@grug#1a2b are you there", "grug"));
	assert(bc_mentions("cc @grug, @thog", "thog"));

	/* A longer name that merely starts with ours is not a mention. */
	assert(!bc_mentions("@grugly", "grug"));
	assert(!bc_mentions("@grug_bot", "grug"));
	assert(!bc_mentions("mail grug@example.org", "grug"));
	assert(!bc_mentions("no names here", "grug"));
	assert(!bc_mentions("@grug", ""));
}

static void
test_hex(void)
{
	uint8_t in[4] = {0xde, 0xad, 0xbe, 0xef};
	uint8_t back[4];
	char hex[9];

	bc_hex_encode(in, sizeof(in), hex);
	assert(strcmp(hex, "deadbeef") == 0);
	assert(bc_hex_decode(hex, back, sizeof(back)) == 0);
	assert(memcmp(in, back, sizeof(in)) == 0);
	assert(bc_hex_decode("zz", back, 1) < 0);
}

int
main(void)
{
	test_roundtrip();
	test_padded_directed();
	test_compression();
	test_compression_boundary();
	test_route();
	test_bad_input();
	test_announce_tlv();
	test_private_message_tlv();
	test_utf8();
	test_mentions();
	test_hex();
	return 0;
}
