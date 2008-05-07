#include "pool.h"

void
pool_init(struct pool *pool, size_t default_page_size)
{
	pool->cur_page = NULL;
	pool->cur_size = 0;
	pool->cur_used = 0;
	list_init(&pool->old_pages, LISTCOUNT_T_MAX);
	pool->default_page_size = default_page_size;
}

static void *
pool_new_page(struct pool *pool, size_t size)
{
	size_t page_size = size > pool->default_page_size ? 
		size : pool->default_page_size;
	void *old_page = pool->cur_page;
	if (!(pool->cur_page = malloc(page_size)))
		return NULL;
	if (old_page) {
		lnode_t *lnode;
		if (!(lnode = lnode_create(old_page))) {
			free(pool->cur_page);
			return NULL;
		}
		list_append(&pool->old_pages, lnode);
	}
	pool->cur_size = page_size;
	pool->cur_used = size;		
	return pool->cur_page;
}

void *
palloc(struct pool *pool, size_t size)
{
	if (pool->cur_page != NULL) {
		size_t off = pool->cur_used +
			(POOL_ALIGN - (pool->cur_used % POOL_ALIGN));
		if ((off + size) <= pool->cur_size) {
			pool->cur_used = off + size;
			return pool->cur_page + off;
		}
	}
	return pool_new_page(pool, size);
}

static void
pool_free_page_callback(list_t *pages, lnode_t *lnode, void *context)
{
	free(lnode_get(lnode));
}

void
pool_bump(struct pool *pool)
{
	list_process(&pool->old_pages, NULL, pool_free_page_callback);
	list_destroy_nodes(&pool->old_pages);
	if (pool->cur_size > pool->default_page_size) {
		free(pool->cur_page);
  		pool->cur_page = NULL;
		pool->cur_size = 0;
		pool->cur_used = 0;
	}
}
