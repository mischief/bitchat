#ifndef BC_EMOJI_H
#define BC_EMOJI_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Vendored from clm. Generated at build time from emoji_data.tsv by
 * gen_emoji.lua. The layout is relocation-free: name_off indexes into
 * bc_emoji_names, one NUL-separated blob. See gen_emoji.lua for cp_packed.
 */
struct bc_emoji_entry {
	uint16_t name_off;
	uint16_t cp_packed;
};

extern const unsigned char bc_emoji_names[];
extern const struct bc_emoji_entry bc_emoji_table[]; /* sorted by name */
extern const size_t bc_emoji_table_len;

/* Look up a shortcode by name (not including the surrounding colons;
 * namelen bytes, need not be NUL-terminated). On a match, encodes the
 * UTF-8 glyph into out (must be at least 5 bytes: up to 4 bytes plus a
 * NUL) and returns the encoded length (1-4). Returns 0 if unknown. */
size_t bc_emoji_lookup(const char *name, size_t namelen, char out[5]);

/* i must be < bc_emoji_table_len; "" on violation in release builds, not
 * NULL, so it stays safe to strlen/strncmp. */
static inline const char *
bc_emoji_entry_name(size_t i)
{
	assert(i < bc_emoji_table_len);
	if (i >= bc_emoji_table_len)
		return "";
	return (const char *)bc_emoji_names + bc_emoji_table[i].name_off;
}

#endif
