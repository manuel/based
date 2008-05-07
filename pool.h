#ifndef _POOL_H
#define _POOL_H

#include <stdlib.h>

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
palloc(struct pool *, size_t);

void
pool_bump(struct pool *);

#endif
