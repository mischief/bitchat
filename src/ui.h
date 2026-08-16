// SPDX-License-Identifier: ISC
/* Terminal chat window: a scrollback pane, a status bar and an input line. */
#ifndef BITCHAT_UI_H
#define BITCHAT_UI_H

#include <stdbool.h>
#include <stddef.h>

struct ui;

enum ui_kind {
	UI_PUBLIC,
	UI_MENTION, /* a message that names you */
	UI_PRIVATE,
	UI_SYSTEM,
	UI_SELF,
	UI_DEBUG, /* transport chatter, shown only with /debug */
};

/*
 * Completion candidates for @names and /msg. The callback fills out with
 * pointers that stay valid until it is called again.
 */
typedef size_t (*ui_names_fn)(void *ud, const char *out[], size_t max);

int ui_new(struct ui **ret);
void ui_set_names(struct ui *u, ui_names_fn fn, void *ud);

/* Ring the terminal bell. */
void ui_alert(struct ui *u);

void ui_free(struct ui *u);

void ui_printf(struct ui *u, enum ui_kind kind, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void ui_status(struct ui *u, const char *nick, const char *peer_id,
               size_t links, size_t peers);
void ui_draw(struct ui *u);

/*
 * Read what is pending on the terminal. Returns a completed input line, or
 * NULL when the line is still being typed. The buffer is reused per call.
 */
const char *ui_input(struct ui *u);

#endif
