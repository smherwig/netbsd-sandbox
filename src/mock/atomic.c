#include <msys/atomic.h>

void
atomic_dec_uint(volatile unsigned int *x)
{
    (*x)--;
}

unsigned int
atomic_dec_uint_nv(volatile unsigned int *x)
{
    (*x)--;
    return (*x);
}

void
atomic_inc_uint(volatile unsigned int *x)
{
    (*x)++;
}

unsigned int
atomic_inc_uint_nv(volatile unsigned int *x)
{
    (*x)++;
    return (*x);
}
