#include <stdlib.h>

#include <msys/kmem.h>

void *
kmem_alloc(size_t size, km_flag_t flags)
{
    return (malloc(size));
}

void *
kmem_zalloc(size_t size, km_flag_t flags)
{
    return (calloc(1, size));
}

void
kmem_free(void *p, size_t size)
{
    free(p);
}
