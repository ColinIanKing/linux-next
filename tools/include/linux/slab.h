/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TOOLS_SLAB_H
#define _TOOLS_SLAB_H

#include <linux/types.h>
#include <linux/gfp.h>

#define SLAB_PANIC 2
#define SLAB_RECLAIM_ACCOUNT    0x00020000UL            /* Objects are reclaimable */

#define kzalloc_node(size, flags, node) kmalloc(size, flags)

void *kmalloc(size_t size, gfp_t gfp);
void kfree(void *p);
void *kmalloc_array(size_t n, size_t size, gfp_t gfp);

bool slab_is_available(void);

enum slab_state {
	DOWN,
	PARTIAL,
	UP,
	FULL
};

struct kmem_cache_args {
	unsigned int align;
	unsigned int sheaf_capacity;
	void (*ctor)(void *);
};

static inline void *kzalloc(size_t size, gfp_t gfp)
{
	return kmalloc(size, gfp | __GFP_ZERO);
}

struct list_lru;

void *kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *, int flags);
static inline void *kmem_cache_alloc(struct kmem_cache *cachep, int flags)
{
	return kmem_cache_alloc_lru(cachep, NULL, flags);
}
void kmem_cache_free(struct kmem_cache *cachep, void *objp);


struct kmem_cache *
__kmem_cache_create_args(const char *name, unsigned int size,
		struct kmem_cache_args *args, unsigned int flags);

/* If NULL is passed for @args, use this variant with default arguments. */
static inline struct kmem_cache *
__kmem_cache_default_args(const char *name, unsigned int size,
		struct kmem_cache_args *args, unsigned int flags)
{
	struct kmem_cache_args kmem_default_args = {};

	return __kmem_cache_create_args(name, size, &kmem_default_args, flags);
}

static inline struct kmem_cache *
__kmem_cache_create(const char *name, unsigned int size, unsigned int align,
		unsigned int flags, void (*ctor)(void *))
{
	struct kmem_cache_args kmem_args = {
		.align	= align,
		.ctor	= ctor,
	};

	return __kmem_cache_create_args(name, size, &kmem_args, flags);
}

#define kmem_cache_create(__name, __object_size, __args, ...)           \
	_Generic((__args),                                              \
		struct kmem_cache_args *: __kmem_cache_create_args,	\
		void *: __kmem_cache_default_args,			\
		default: __kmem_cache_create)(__name, __object_size, __args, __VA_ARGS__)

void kmem_cache_free_bulk(struct kmem_cache *cachep, size_t size, void **list);
int kmem_cache_alloc_bulk(struct kmem_cache *cachep, gfp_t gfp, size_t size,
			  void **list);

#endif		/* _TOOLS_SLAB_H */
