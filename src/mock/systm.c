#include <msys/systm.h>

/* Copies a NUL-terminated string, at most len bytes long,
 * from kernel-space address kfaddr to kernel-space address
 * kdaddr.  If the done argument is non-NULL, the number of
 * bytes acutally copied, including the terminating NUL, is
 * returned in *done.
 *
 * from sys/arch/usermode/usermode/copy.c
 */
int
copystr(const void *kfaddr, void *kdaddr, size_t len, size_t *done)
{
#define min(x,y) (((x) < (y)) ? (x) : (y))
	len = min(strnlen(kfaddr, len), len) + 1;
#undef min
	strncpy(kdaddr, kfaddr, len);
	if (done)
		*done = len;
	return 0;
}
