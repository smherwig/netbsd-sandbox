#ifndef _SANDBOX_VNODE_H_
#define _SANDBOX_VNODE_H_

#include <sys/types.h>
#include <sys/vnode.h>

int sandbox_vnode_to_path(struct vnode *vp, char *out, size_t outlen);

#endif /* !_SANDBOX_VNODE_H_ */
