// SPDX-License-Identifier: ISC
/* Cleanup attribute macros for automatic resource management. */
#ifndef TMPL_CLEANUP_H
#define TMPL_CLEANUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static inline void
autofree_fn(void *p)
{
	if (*(void **)p)
		free(*(void **)p);
}

static inline void
autoclose_fn(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}

static inline void
autoclosefile_fn(FILE **fp)
{
	if (*fp != NULL)
		fclose(*fp);
}

#define autofree __attribute__((cleanup(autofree_fn)))
#define autoclose __attribute__((cleanup(autoclose_fn)))
#define autoclosefile __attribute__((cleanup(autoclosefile_fn)))

#endif
