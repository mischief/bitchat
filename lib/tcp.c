// SPDX-License-Identifier: ISC
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bitchat/tcp.h"

#include "lib/internal.h"

#define MAX_LINKS 16
#define FRAME_MAX 4096
#define RECONNECT_MS 2000

struct link {
	struct bc_tcp *t;
	int fd;
	bool connecting;
	bool up;

	/* Set for links we dial, so they can be rebuilt when they drop. */
	char host[64];
	uint16_t port;
	int64_t retry_at;

	uint8_t in[FRAME_MAX];
	size_t in_len;
	uint8_t out[FRAME_MAX * 2];
	size_t out_len;

	struct link *next;
};

struct bc_tcp {
	int listen_fd;
	uint16_t port;
	struct bc_tcp_ops ops;
	void *ud;
	struct link *links;
	size_t link_count;
};

static void tlog(struct bc_tcp *t, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void
tlog(struct bc_tcp *t, const char *fmt, ...)
{
	char line[256];
	va_list ap;

	if (t->ops.on_log == NULL)
		return;
	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	t->ops.on_log(t->ud, line);
}

static int
set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;
	return 0;
}

static struct link *
link_new(struct bc_tcp *t, int fd)
{
	struct link *l;

	if (t->link_count >= MAX_LINKS)
		return NULL;

	l = calloc(1, sizeof(*l));
	if (l == NULL)
		return NULL;

	l->t = t;
	l->fd = fd;
	l->next = t->links;
	t->links = l;
	t->link_count++;
	return l;
}

static void
link_up(struct link *l)
{
	if (l->up)
		return;
	l->up = true;
	if (l->t->ops.on_link_up != NULL)
		l->t->ops.on_link_up(l->t->ud, l);
	if (l->t->ops.on_mtu != NULL)
		l->t->ops.on_mtu(l->t->ud, l, FRAME_MAX - 2);
}

/* A dialled link is kept for a later retry; an accepted one is discarded. */
static void
link_drop(struct bc_tcp *t, struct link *l)
{
	if (l->up && t->ops.on_link_down != NULL)
		t->ops.on_link_down(t->ud, l);
	l->up = false;

	if (l->fd >= 0)
		close(l->fd);
	l->fd = -1;
	l->in_len = 0;
	l->out_len = 0;
	l->connecting = false;

	if (l->host[0] != '\0') {
		l->retry_at = bc_now_ms() + RECONNECT_MS;
		return;
	}

	{
		struct link **pp;

		for (pp = &t->links; *pp != NULL; pp = &(*pp)->next) {
			if (*pp != l)
				continue;
			*pp = l->next;
			break;
		}
	}
	t->link_count--;
	free(l);
}

static int
dial(struct link *l)
{
	struct addrinfo hints = {.ai_family = AF_UNSPEC,
	                         .ai_socktype = SOCK_STREAM};
	struct addrinfo *res = NULL;
	char service[8];
	int fd, r;

	snprintf(service, sizeof(service), "%u", l->port);
	if (getaddrinfo(l->host, service, &hints, &res) != 0)
		return -EHOSTUNREACH;

	fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC,
	            res->ai_protocol);
	if (fd < 0) {
		freeaddrinfo(res);
		return -errno;
	}

	if (set_nonblock(fd) < 0) {
		close(fd);
		freeaddrinfo(res);
		return -EIO;
	}

	r = connect(fd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	if (r < 0 && errno != EINPROGRESS) {
		r = -errno;
		close(fd);
		return r;
	}

	l->fd = fd;
	l->connecting = true;
	return 0;
}

int
bc_tcp_connect(struct bc_tcp *t, const char *host, uint16_t port)
{
	struct link *l;
	int r;

	ASSERT_RETURN(t != NULL && host != NULL, -EINVAL);

	l = link_new(t, -1);
	if (l == NULL)
		return -ENOSPC;

	snprintf(l->host, sizeof(l->host), "%s", host);
	l->port = port;

	r = dial(l);
	if (r < 0)
		l->retry_at = bc_now_ms() + RECONNECT_MS;
	return 0;
}

int
bc_tcp_new(struct bc_tcp **ret, uint16_t port, const struct bc_tcp_ops *ops,
           void *ud)
{
	struct sockaddr_in addr = {0};
	socklen_t len = sizeof(addr);
	struct bc_tcp *t;
	int fd = -1, one = 1;

	ASSERT_RETURN(ret != NULL && ops != NULL, -EINVAL);

	t = calloc(1, sizeof(*t));
	if (t == NULL)
		return -ENOMEM;

	t->ops = *ops;
	t->ud = ud;
	t->listen_fd = -1;

	if (port == 0 && ops->on_link_up == NULL) {
		*ret = t;
		return 0;
	}

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		free(t);
		return -errno;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(fd, 8) < 0 || set_nonblock(fd) < 0 ||
	    getsockname(fd, (struct sockaddr *)&addr, &len) < 0) {
		int r = -errno;

		close(fd);
		free(t);
		return r;
	}

	t->listen_fd = fd;
	t->port = ntohs(addr.sin_port);
	*ret = t;
	return 0;
}

void
bc_tcp_free(struct bc_tcp *t)
{
	if (t == NULL)
		return;

	while (t->links != NULL) {
		struct link *l = t->links;

		t->links = l->next;
		if (l->fd >= 0)
			close(l->fd);
		free(l);
	}
	if (t->listen_fd >= 0)
		close(t->listen_fd);
	free(t);
}

uint16_t
bc_tcp_port(const struct bc_tcp *t)
{
	return t != NULL ? t->port : 0;
}

size_t
bc_tcp_pollfds(struct bc_tcp *t, struct pollfd *fds, size_t max)
{
	struct link *l;
	size_t n = 0;

	if (t == NULL || fds == NULL)
		return 0;

	if (t->listen_fd >= 0 && n < max) {
		fds[n].fd = t->listen_fd;
		fds[n].events = POLLIN;
		fds[n].revents = 0;
		n++;
	}

	for (l = t->links; l != NULL && n < max; l = l->next) {
		if (l->fd < 0)
			continue;
		fds[n].fd = l->fd;
		fds[n].events =
		    l->connecting
		        ? (short)POLLOUT
		        : (short)(POLLIN | (l->out_len ? POLLOUT : 0));
		fds[n].revents = 0;
		n++;
	}
	return n;
}

static void
flush_out(struct bc_tcp *t, struct link *l)
{
	while (l->out_len > 0) {
		ssize_t w = send(l->fd, l->out, l->out_len, MSG_NOSIGNAL);

		if (w < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			link_drop(t, l);
			return;
		}
		memmove(l->out, l->out + w, l->out_len - (size_t)w);
		l->out_len -= (size_t)w;
	}
}

static void
read_frames(struct bc_tcp *t, struct link *l)
{
	for (;;) {
		ssize_t r;
		size_t off = 0;

		r = recv(l->fd, l->in + l->in_len, sizeof(l->in) - l->in_len,
		         0);
		if (r == 0) {
			link_drop(t, l);
			return;
		}
		if (r < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			link_drop(t, l);
			return;
		}
		l->in_len += (size_t)r;

		while (l->in_len - off >= 2) {
			size_t len = ((size_t)l->in[off] << 8) | l->in[off + 1];

			if (len == 0 || len > FRAME_MAX - 2) {
				link_drop(t, l);
				return;
			}
			if (l->in_len - off < len + 2)
				break;
			if (t->ops.on_frame != NULL)
				t->ops.on_frame(t->ud, l, l->in + off + 2, len);
			off += len + 2;
		}

		if (off > 0) {
			memmove(l->in, l->in + off, l->in_len - off);
			l->in_len -= off;
		}
		if (l->in_len == sizeof(l->in)) {
			link_drop(t, l); /* a frame that can never complete */
			return;
		}
	}
}

static void
finish_connect(struct bc_tcp *t, struct link *l)
{
	int err = 0, one = 1;
	socklen_t len = sizeof(err);

	if (getsockopt(l->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 ||
	    err != 0) {
		link_drop(t, l);
		return;
	}

	setsockopt(l->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	l->connecting = false;
	link_up(l);
}

static void
accept_link(struct bc_tcp *t)
{
	struct link *l;
	int fd, one = 1;

	fd = accept(t->listen_fd, NULL, NULL);
	if (fd < 0)
		return;

	if (set_nonblock(fd) < 0) {
		close(fd);
		return;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	l = link_new(t, fd);
	if (l == NULL) {
		close(fd);
		return;
	}
	tlog(t, "accepted a link");
	link_up(l);
}

void
bc_tcp_dispatch(struct bc_tcp *t, const struct pollfd *fds, size_t n)
{
	size_t i;

	if (t == NULL || fds == NULL)
		return;

	for (i = 0; i < n; i++) {
		struct link *l, *next;

		if (fds[i].revents == 0)
			continue;
		if (fds[i].fd == t->listen_fd) {
			accept_link(t);
			continue;
		}

		for (l = t->links; l != NULL; l = next) {
			next = l->next;
			if (l->fd != fds[i].fd)
				continue;
			if (l->connecting) {
				finish_connect(t, l);
				break;
			}
			if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
				link_drop(t, l);
				break;
			}
			if (fds[i].revents & POLLOUT)
				flush_out(t, l);
			if (fds[i].revents & POLLIN)
				read_frames(t, l);
			break;
		}
	}
}

int
bc_tcp_timeout(const struct bc_tcp *t)
{
	return t != NULL ? 500 : -1;
}

void
bc_tcp_tick(struct bc_tcp *t)
{
	struct link *l;
	int64_t now;

	if (t == NULL)
		return;
	now = bc_now_ms();

	for (l = t->links; l != NULL; l = l->next) {
		if (l->fd >= 0 || l->host[0] == '\0' || now < l->retry_at)
			continue;
		if (dial(l) < 0)
			l->retry_at = now + RECONNECT_MS;
	}
}

int
bc_tcp_send(struct bc_tcp *t, void *link, const uint8_t *frame, size_t len)
{
	struct link *l = link;

	ASSERT_RETURN(t != NULL && l != NULL && frame != NULL, -EINVAL);

	if (!l->up || l->fd < 0)
		return -ENOTCONN;
	if (len == 0 || len > FRAME_MAX - 2)
		return -EMSGSIZE;
	if (l->out_len + len + 2 > sizeof(l->out))
		return -ENOBUFS;

	l->out[l->out_len++] = (uint8_t)(len >> 8);
	l->out[l->out_len++] = (uint8_t)(len & 0xff);
	memcpy(l->out + l->out_len, frame, len);
	l->out_len += len;

	flush_out(t, l);
	return 0;
}

int
bc_tcp_broadcast(struct bc_tcp *t, const void *except, const uint8_t *frame,
                 size_t len)
{
	struct link *l, *next;
	int sent = 0;

	ASSERT_RETURN(t != NULL && frame != NULL, -EINVAL);

	for (l = t->links; l != NULL; l = next) {
		next = l->next;
		if (l == except || !l->up)
			continue;
		if (bc_tcp_send(t, l, frame, len) == 0)
			sent++;
	}
	return sent;
}

size_t
bc_tcp_link_count(const struct bc_tcp *t)
{
	struct link *l;
	size_t n = 0;

	if (t == NULL)
		return 0;
	for (l = t->links; l != NULL; l = l->next)
		if (l->up)
			n++;
	return n;
}
