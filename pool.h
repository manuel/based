/* Simple "bump pointer" pool for event processing: all memory needed
   for handling a request is allocated from the pool.  When the
   request is served the pool is reset to a standard size.  This means
   that most requests can be served without a call to malloc.

   The pool maintains a current page, from which allocations are done,
   and a list of older pages.  When the pool is reset, all pages but
   one are freed.

   Data is aligned on an 8-byte boundary.  Pages have a default size,
   but if an allocation request exceeds that size, the pool will
   allocate a larger page. */

#ifndef POOL_H
#define POOL_H

#include <stdlib.h>
#include <string.h>

#include "list.h"

#define POOL_DEFAULT_PAGE_SIZE 4096
#define POOL_ALIGN 8

struct pool {
	void *cur_page;
	size_t cur_size;
	size_t cur_used;
	list_t old_pages;
	size_t default_page_size;
};

void
pool_init(struct pool *, size_t default_page_size);

void *
pool_malloc(struct pool *, size_t);

void *
pool_calloc(struct pool *, size_t);

char *
pool_strndup(struct pool *, const char *, size_t);

void
pool_reset(struct pool *);

#endif
