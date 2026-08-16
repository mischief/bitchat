// SPDX-License-Identifier: ISC
#include <assert.h>
#include <string.h>

#include "emoji.h"

int
main(void)
{
	char glyph[5];

	assert(bc_emoji_lookup("bone", 4, glyph) == 4);
	assert(strcmp(glyph, "\xf0\x9f\xa6\xb4") == 0);

	assert(bc_emoji_lookup("fire", 4, glyph) == 4);
	assert(bc_emoji_lookup("+1", 2, glyph) == 4);

	/* Unknown names leave the caller with nothing to insert. */
	assert(bc_emoji_lookup("notanemojiname", 14, glyph) == 0);
	assert(bc_emoji_lookup("", 0, glyph) == 0);

	return 0;
}
