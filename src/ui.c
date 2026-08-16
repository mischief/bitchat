// SPDX-License-Identifier: ISC
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>
#include <curses.h>
#include <locale.h>

#ifdef HAVE_EMOJI
#include "emoji.h"
#endif

#include "src/ui.h"
#include "banned.h"

#define SCROLLBACK 500
#define LINE_MAX_LEN 512
#define INPUT_MAX 1024
#define MAX_CANDIDATES 64

struct line {
	enum ui_kind kind;
	char text[LINE_MAX_LEN];
};

struct ui {
	struct line lines[SCROLLBACK];
	size_t count;
	size_t first;

	char status[256];
	char input[INPUT_MAX];
	size_t input_len;
	char ready[INPUT_MAX]; /* the line handed to the caller */
	ui_names_fn names;
	void *names_ud;
	bool dirty;
};

static const char *const commands[] = {
    "/who", "/msg", "/nick", "/id", "/debug", "/help", "/quit",
};

static void
init_colors(void)
{
	if (!has_colors())
		return;
	start_color();
	use_default_colors();
	init_pair(1, COLOR_CYAN, -1);    /* public */
	init_pair(2, COLOR_MAGENTA, -1); /* private */
	init_pair(3, COLOR_YELLOW, -1);  /* system */
	init_pair(4, COLOR_GREEN, -1);   /* own messages */
	init_pair(5, COLOR_BLACK, COLOR_WHITE);
	init_pair(6, COLOR_BLUE, -1); /* transport chatter */
	init_pair(7, COLOR_RED, -1);  /* messages naming you */
}

int
ui_new(struct ui **ret)
{
	struct ui *u;

	if (ret == NULL)
		return -1;

	u = calloc(1, sizeof(*u));
	if (u == NULL)
		return -1;

	/* Wide output needs the locale set before curses starts. */
	setlocale(LC_ALL, "");

	if (initscr() == NULL) {
		free(u);
		return -1;
	}

	cbreak();
	noecho();
	nonl();
	keypad(stdscr, TRUE);
	nodelay(stdscr, TRUE);
	curs_set(1);
	init_colors();

	u->dirty = true;
	*ret = u;
	return 0;
}

void
ui_alert(struct ui *u)
{
	if (u != NULL)
		beep();
}

void
ui_set_names(struct ui *u, ui_names_fn fn, void *ud)
{
	if (u == NULL)
		return;
	u->names = fn;
	u->names_ud = ud;
}

void
ui_free(struct ui *u)
{
	if (u == NULL)
		return;
	endwin();
	free(u);
}

static struct line *
push_line(struct ui *u)
{
	struct line *l;

	if (u->count < SCROLLBACK) {
		l = &u->lines[(u->first + u->count) % SCROLLBACK];
		u->count++;
	} else {
		l = &u->lines[u->first];
		u->first = (u->first + 1) % SCROLLBACK;
	}
	return l;
}

/*
 * Message text comes from the mesh, so it must never reach the terminal as
 * control bytes: an escape sequence from a peer could repaint the screen or
 * drive the emulator. UTF-8 sequences pass through untouched.
 */
static void
sanitize(char *s)
{
	unsigned char *p = (unsigned char *)s;

	for (; *p != '\0'; p++)
		if (*p < 0x20 || *p == 0x7f)
			*p = '?';
}

void
ui_printf(struct ui *u, enum ui_kind kind, const char *fmt, ...)
{
	struct line *l;
	va_list ap;

	if (u == NULL)
		return;

	l = push_line(u);
	l->kind = kind;
	va_start(ap, fmt);
	vsnprintf(l->text, sizeof(l->text), fmt, ap);
	va_end(ap);
	sanitize(l->text);
	u->dirty = true;
}

void
ui_status(struct ui *u, const char *nick, const char *peer_id, size_t links,
          size_t peers)
{
	if (u == NULL)
		return;
	snprintf(u->status, sizeof(u->status),
	         " bitchat  %s  id %.8s  links %zu  peers %zu ", nick, peer_id,
	         links, peers);
	u->dirty = true;
}

static int
color_of(enum ui_kind kind)
{
	switch (kind) {
	case UI_PUBLIC:
		return 1;
	case UI_MENTION:
		return 7;
	case UI_PRIVATE:
		return 2;
	case UI_SYSTEM:
		return 3;
	case UI_SELF:
		return 4;
	case UI_DEBUG:
		return 6;
	}
	return 1;
}

void
ui_draw(struct ui *u)
{
	int rows, cols, pane, i;
	size_t start;

	if (u == NULL || !u->dirty)
		return;

	getmaxyx(stdscr, rows, cols);
	pane = rows - 2;
	if (pane < 1)
		pane = 1;

	erase();

	start = u->count > (size_t)pane ? u->count - (size_t)pane : 0;
	for (i = 0; start + (size_t)i < u->count && i < pane; i++) {
		struct line *l =
		    &u->lines[(u->first + start + (size_t)i) % SCROLLBACK];
		int pair = color_of(l->kind);

		attron(COLOR_PAIR(pair));
		mvaddnstr(i, 0, l->text, cols);
		attroff(COLOR_PAIR(pair));
	}

	attron(COLOR_PAIR(5));
	mvhline(rows - 2, 0, ' ', cols);
	mvaddnstr(rows - 2, 0, u->status, cols);
	attroff(COLOR_PAIR(5));

	mvaddnstr(rows - 1, 0, "> ", 2);
	mvaddnstr(rows - 1, 2, u->input, cols - 3);
	move(rows - 1, (int)u->input_len + 2);

	refresh();
	u->dirty = false;
}

/*
 * A ':' was just typed at the end of the input. If it closes a ":shortcode:"
 * run, swap the whole span for the glyph, the way chat clients do. Silently
 * does nothing when the name is unknown or malformed.
 */
static void
expand_emoji(struct ui *u)
{
#ifdef HAVE_EMOJI
	size_t close = u->input_len - 1; /* the ':' just typed */
	size_t i = close, namestart, namelen, span, glyphlen;
	char glyph[5];

	while (i > 0) {
		char c = u->input[--i];

		if (c == ':')
			break;
		if (!(isalnum((unsigned char)c) || c == '_' || c == '+' ||
		      c == '-'))
			return;
		if (close - i > 64) /* no shortcode is this long */
			return;
	}
	if (u->input[i] != ':')
		return;

	namestart = i + 1;
	namelen = close - namestart;
	if (namelen == 0)
		return;

	glyphlen = bc_emoji_lookup(u->input + namestart, namelen, glyph);
	if (glyphlen == 0)
		return;

	span = close - i + 1; /* ":name:", both colons included */
	memcpy(u->input + i, glyph, glyphlen);
	u->input_len = u->input_len - span + glyphlen;
	u->input[u->input_len] = '\0';
#else
	(void)u;
#endif
}

static void
append(struct ui *u, const char *s, size_t len)
{
	if (u->input_len + len >= sizeof(u->input))
		return;
	memcpy(u->input + u->input_len, s, len);
	u->input_len += len;
	u->input[u->input_len] = '\0';
}

#ifdef HAVE_EMOJI
/* Start of the ":prefix" run ending at the cursor, or -1 if there is none. */
static long
shortcode_start(const struct ui *u)
{
	size_t i = u->input_len;

	while (i > 0) {
		char c = u->input[i - 1];

		if (c == ':')
			return (long)i;
		if (!(isalnum((unsigned char)c) || c == '_' || c == '+' ||
		      c == '-'))
			return -1;
		if (u->input_len - i > 64)
			return -1;
		i--;
	}
	return -1;
}

#endif

/* Extend the input to what every candidate agrees on; list when ambiguous. */
static void
apply_completion(struct ui *u, const char **cand, size_t n, size_t prefixlen,
                 const char *suffix)
{
	char list[LINE_MAX_LEN];
	size_t common, listlen = 0, i;

	if (n == 0)
		return;

	common = strlen(cand[0]);
	for (i = 1; i < n; i++) {
		size_t j;

		for (j = 0; j < common && cand[i][j] == cand[0][j]; j++)
			;
		common = j;
	}

	if (common > prefixlen)
		append(u, cand[0] + prefixlen, common - prefixlen);

	if (n == 1) {
		append(u, suffix, strlen(suffix));
		if (suffix[0] == ':')
			expand_emoji(u);
		return;
	}

	for (i = 0; i < n; i++) {
		int w;

		if (listlen + strlen(cand[i]) + 2 >= sizeof(list))
			break;
		w = snprintf(list + listlen, sizeof(list) - listlen, "%s%s",
		             listlen ? " " : "", cand[i]);
		if (w > 0)
			listlen += (size_t)w;
	}
	ui_printf(u, UI_SYSTEM, "* %zu matches: %s", n, list);
}

/* Start of the word under the cursor. */
static size_t
word_start(const struct ui *u)
{
	size_t i = u->input_len;

	while (i > 0 && u->input[i - 1] != ' ')
		i--;
	return i;
}

static bool
complete_names(struct ui *u, size_t start, const char *suffix)
{
	const char *names[MAX_CANDIDATES];
	const char *cand[MAX_CANDIDATES];
	const char *prefix = u->input + start;
	size_t prefixlen = u->input_len - start;
	size_t n, i, matches = 0;

	if (u->names == NULL)
		return false;

	n = u->names(u->names_ud, names, MAX_CANDIDATES);
	for (i = 0; i < n && matches < MAX_CANDIDATES; i++)
		if (strncmp(names[i], prefix, prefixlen) == 0)
			cand[matches++] = names[i];

	if (matches == 0)
		return false;
	apply_completion(u, cand, matches, prefixlen, suffix);
	return true;
}

static bool
complete_commands(struct ui *u)
{
	const char *cand[MAX_CANDIDATES];
	size_t i, matches = 0;

	for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
		if (strncmp(commands[i], u->input, u->input_len) == 0)
			cand[matches++] = commands[i];

	if (matches == 0)
		return false;
	apply_completion(u, cand, matches, u->input_len, " ");
	return true;
}

static bool
complete_emoji(struct ui *u)
{
#ifdef HAVE_EMOJI
	const char *cand[MAX_CANDIDATES];
	long start = shortcode_start(u);
	const char *prefix;
	size_t prefixlen, i, matches = 0;

	if (start < 0)
		return false;

	prefix = u->input + start;
	prefixlen = u->input_len - (size_t)start;

	for (i = 0; i < bc_emoji_table_len && matches < MAX_CANDIDATES; i++) {
		const char *name = bc_emoji_entry_name(i);

		if (strncmp(name, prefix, prefixlen) == 0)
			cand[matches++] = name;
	}

	if (matches == 0)
		return false;
	apply_completion(u, cand, matches, prefixlen, ":");
	return true;
#else
	(void)u;
	return false;
#endif
}

/*
 * Tab completes, in order: a command at the start of the line, an @name, the
 * peer argument of /msg, or an emoji shortcode.
 */
static void
complete(struct ui *u)
{
	size_t start = word_start(u);

	if (start == 0 && u->input[0] == '/') {
		complete_commands(u);
		return;
	}

	if (u->input[start] == '@') {
		complete_names(u, start + 1, " ");
		return;
	}

	if (strncmp(u->input, "/msg ", 5) == 0 && start == 5) {
		complete_names(u, start, " ");
		return;
	}

	complete_emoji(u);
}

const char *
ui_input(struct ui *u)
{
	int ch;

	if (u == NULL)
		return NULL;

	while ((ch = getch()) != ERR) {
		u->dirty = true;

		switch (ch) {
		case '\r':
		case '\n':
		case KEY_ENTER:
			if (u->input_len == 0)
				break;
			u->input[u->input_len] = '\0';
			memcpy(u->ready, u->input, u->input_len + 1);
			u->input_len = 0;
			u->input[0] = '\0';
			return u->ready;
		case KEY_BACKSPACE:
		case 127:
		case 8:
			/* Erase a whole character, not one UTF-8 byte. */
			while (u->input_len > 0) {
				unsigned char c =
				    (unsigned char)u->input[--u->input_len];

				u->input[u->input_len] = '\0';
				if ((c & 0xc0) != 0x80)
					break;
			}
			break;
		case 21: /* ctrl-u */
			u->input_len = 0;
			u->input[0] = '\0';
			break;
		case '\t':
			complete(u);
			break;
		case KEY_RESIZE:
			break;
		default:
			/* Bytes above 0x7f are UTF-8 pieces; keep them. */
			if (ch < 32 || ch == 127 || ch > 255)
				break;
			if (u->input_len + 1 >= sizeof(u->input))
				break;
			u->input[u->input_len++] = (char)ch;
			u->input[u->input_len] = '\0';
			if (ch == ':')
				expand_emoji(u);
			break;
		}
	}
	return NULL;
}
