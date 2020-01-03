/*	$NetBSD: vnode.h,v 1.249 2014/07/05 09:33:15 hannken Exp $	*/

/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vnode.h	8.17 (Berkeley) 5/20/95
 */

#ifndef _MSYS_VNODE_H_
#define	_MSYS_VNODE_H_

#include <msys/queue.h>

/*
 * Vnode types.  VNON means no type.
 */
enum vtype	{ VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD };

#define	VNODE_TYPES \
    "VNON", "VREG", "VDIR", "VBLK", "VCHR", "VLNK", "VSOCK", "VFIFO", "VBAD"

/*
 * Vnode tag types.
 * These are for the benefit of external programs only (e.g., pstat)
 * and should NEVER be inspected by the kernel.
 */
enum vtagtype	{
	VT_NON, VT_UFS, VT_NFS, VT_MFS, VT_MSDOSFS, VT_LFS, VT_LOFS,
	VT_FDESC, VT_PORTAL, VT_NULL, VT_UMAP, VT_KERNFS, VT_PROCFS,
	VT_AFS, VT_ISOFS, VT_UNION, VT_ADOSFS, VT_EXT2FS, VT_CODA,
	VT_FILECORE, VT_NTFS, VT_VFS, VT_OVERLAY, VT_SMBFS, VT_PTYFS,
	VT_TMPFS, VT_UDF, VT_SYSVBFS, VT_PUFFS, VT_HFS, VT_EFS, VT_ZFS,
	VT_RUMP, VT_NILFS, VT_V7FS, VT_CHFS
};

#define	VNODE_TAGS \
    "VT_NON", "VT_UFS", "VT_NFS", "VT_MFS", "VT_MSDOSFS", "VT_LFS", "VT_LOFS", \
    "VT_FDESC", "VT_PORTAL", "VT_NULL", "VT_UMAP", "VT_KERNFS", "VT_PROCFS", \
    "VT_AFS", "VT_ISOFS", "VT_UNION", "VT_ADOSFS", "VT_EXT2FS", "VT_CODA", \
    "VT_FILECORE", "VT_NTFS", "VT_VFS", "VT_OVERLAY", "VT_SMBFS", "VT_PTYFS", \
    "VT_TMPFS", "VT_UDF", "VT_SYSVBFS", "VT_PUFFS", "VT_HFS", "VT_EFS", \
    "VT_ZFS", "VT_RUMP", "VT_NILFS", "VT_V7FS", "VT_CHFS"

struct vnode;

struct vnode {
	int		v_iflag;		/* i: VI_* flags */
	int		v_vflag;		/* v: VV_* flags */
	int		v_uflag;		/* u: VU_* flags */
	int		v_numoutput;		/* i: # of pending writes */
	int		v_writecount;		/* i: ref count of writers */
	int		v_holdcnt;		/* i: page & buffer refs */
	int		v_synclist_slot;	/* s: synclist slot index */
};

typedef struct vnode vnode_t;

#endif /* !_MSYS_VNODE_H_ */
