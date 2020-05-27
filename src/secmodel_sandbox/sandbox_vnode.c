/*-
 * Copyright (c) 2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by 
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

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/unistd.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/extattr.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kauth.h>

#include <ufs/ufs/dir.h>    /* XXX only for DIRBLKSIZ */

#include "sandbox_vnode.h"
#include "sandbox_path.h"

#include "sandbox_log.h"


/* TODO: you can probably merge this file into sandbox_path.c */

#define SANDBOX_VNODE_PRINT(vp, msg) \
    SANDBOX_LOG_DEBUG("%s uc:%d wc:%d hc:%d LK:%d\n", \
            msg, \
            vp->v_usecount, \
            vp->v_writecount, \
            vp->v_holdcnt, \
            VOP_ISLOCKED(vp))

static ino_t
sandbox_vnode_getfileid(struct vnode *vp, kauth_cred_t cred)
{
    int error = 0;
    ino_t fileid = 0;
    struct vattr va;

    SANDBOX_VNODE_PRINT(vp, "vp");

    /* Pre-Conditions:
     *  - vp is locked
     */
    error = VOP_GETATTR(vp, &va, cred);
    /* Post-Conditions (both success and failure):
     *  - vp is locked
     *
     * VOP_GETATTR() should not change vp
     */
    if (error != 0) {
        SANDBOX_LOG_ERROR("VOP_GETATTR() failed (%d)\n", error);
        goto fail;
    }

    fileid = va.va_fileid; 
    
fail:
    SANDBOX_VNODE_PRINT(vp, "vp");
    return (fileid);
}

static int
sandbox_vnode_scandir(struct vnode *dvp, struct vnode *vp, kauth_cred_t cred,
        char *outname, size_t outnamelen)
{
    int error = 0;
    int eofflag = 0;
    struct iovec iov;
    struct uio uio;
    int len = 0;
    int reclen = 0;
    char dirbuf[UFS_DIRBLKSIZ] = { 0 };
    off_t off = 0;
    char *cpos = NULL;
    struct dirent *dp = NULL;
    ino_t fileid = 0;

    SANDBOX_VNODE_PRINT(dvp, "dvp");
    SANDBOX_VNODE_PRINT(vp, "vp");

    fileid = sandbox_vnode_getfileid(vp, cred);

    do {
        iov.iov_base = dirbuf;
        iov.iov_len = UFS_DIRBLKSIZ;
        uio.uio_iov = &iov;
        uio.uio_iovcnt = 1;
        uio.uio_offset = off;
        uio.uio_resid = UFS_DIRBLKSIZ;
        uio.uio_rw = UIO_READ;
        UIO_SETUP_SYSSPACE(&uio);
        eofflag = 0;

        /* Pre-Condition:
         *  - dvp should be locked
         */
        SANDBOX_VNODE_PRINT(dvp, "dvp");

        error = VOP_READDIR(dvp, &uio, cred, &eofflag, NULL, NULL);

        if (error != 0) {
            /* Error Post-Condition:
             *  - dvp is locked
             *  - error is nonzero 
             */
            SANDBOX_VNODE_PRINT(dvp, "dvp");
            SANDBOX_LOG_ERROR("VOP_READDIR() failed (%d)\n", error);
            goto fail;
        }
        SANDBOX_VNODE_PRINT(dvp, "dvp");

        /* Success Post-Condition:
         *  - dvp is locked
         *  - error is zero
         *
         *  VOP_READDIR() should not change dvp
         */
        off = uio.uio_offset;
        cpos = dirbuf;
        /* scan directory page looking for matching vnode */
        for (len = (UFS_DIRBLKSIZ - uio.uio_resid); len > 0; len -= reclen) {
            dp = (struct dirent *)cpos;
            reclen = dp->d_reclen;

            //SANDBOX_LOG_DEBUG("len=%d, reclen=%d\n", len, reclen);

            /* check for malformed directory */
            if (reclen < _DIRENT_MINSIZE(dp)) {
                SANDBOX_LOG_ERROR("reclen (%d) < _DIRENT_MINSIZE(dp)\n", reclen);
                error = EINVAL;
                goto fail;
            }

            if ((dp->d_type != DT_WHT) && (dp->d_fileno == fileid)) {
                /* TODO: check for overflow */
                memcpy(outname, dp->d_name, dp->d_namlen);
                SANDBOX_LOG_DEBUG("found '%s'\n", outname); 
                goto succeed;
            }
            cpos += reclen;
        }
    } while (!eofflag);

    error = ENOENT;

fail:
succeed:
    SANDBOX_VNODE_PRINT(dvp, "dvp");
    SANDBOX_VNODE_PRINT(vp, "vp");
    return (error);
}

/* this function is similar to sys/kern/vfs_getcwd.c::getcwd_common()
 * 
 * Caller made sure that lvp != rvp.
 *
 */

#define SANDBOX_VNODE_CN_DOTDOT_INIT(cn, cred) \
    do { \
        cn.cn_nameiop = LOOKUP; \
        cn.cn_flags = ISLASTCN | ISDOTDOT | RDONLY; \
        cn.cn_cred = cred; \
        cn.cn_nameptr = ".."; \
        cn.cn_namelen = 2; \
        cn.cn_consume = 0; \
    } while (0)

static int
sandbox_vnode_name(struct vnode *lvp, struct vnode *rvp, kauth_cred_t cred,
        struct sandbox_path_list *pathlist)
{
    int error = 0;
    bool locked_uvp = false;
    struct componentname cn;
    struct vnode *uvp = NULL;
    char pathcomp[256] = { 0 };
    struct sandbox_path *sp = NULL;

    if (lvp == rvp)
        goto succeed;

    SANDBOX_VNODE_CN_DOTDOT_INIT(cn, cred);

    SANDBOX_VNODE_PRINT(lvp, "lvp");

    /* get vnode of parent directory (uvp) */

    /* Pre-conditions:
     *  - lvp should be locked
     */

    error = VOP_LOOKUP(lvp, &uvp, &cn);
    if (error) {
        /* Error Post-Conditions:
         * - error is nonzero
         * - lvp is locked
         * - uvp is NULL
         */
        SANDBOX_LOG_ERROR("VOP_LOOKUP() failed (%d)\n", error);
        SANDBOX_VNODE_PRINT(lvp, "lvp");
        error = 1;
        goto fail;
    }
    
    /* Success Post-conditions:
     *
     * If the pathname component is found:
     *  - error is 0
     *  - lvp is locked
     *  - lvp unchanged
     *  - uvp is unlocked
     *  - uvp->v_usecount is incremented
     */
    SANDBOX_VNODE_PRINT(lvp, "lvp");
    SANDBOX_VNODE_PRINT(uvp, "uvp");

    /* To prevent deadlock, when acquiring locks on multiple vnodes, the lock
     * of the parent directory must be acquired before the lock on the child
     * directory 
     *              -- VNODEOPS(9) manpage
     *
     * The following code snippet is very similar to one in
     * sys/fs/union/union_vnops.c::union_lookup()
     */
    VOP_UNLOCK(lvp);
    error = vn_lock(uvp, LK_SHARED | LK_RETRY);
    vn_lock(lvp, LK_SHARED | LK_RETRY);     /* are we reacquiring the correct type of lock? */
    if (error != 0) {
        SANDBOX_LOG_ERROR("vn_lock(uvp) failed (%d)\n", error);
        /* vrele() must be called on an unlocked vnode */
        vrele(uvp);
        goto fail;
    }
    locked_uvp = true;

    /* scan uvp looking for lvp, and return lvp's path component */
    error = sandbox_vnode_scandir(uvp, lvp, cred, pathcomp, sizeof(pathcomp) - 1);
    if (error != 0) {
        SANDBOX_LOG_ERROR("sandbox_vnode_scandir() failed (%d)\n", error);
        goto fail;
    }

    sp = sandbox_path_create(pathcomp, false);
    SIMPLEQ_INSERT_HEAD(pathlist, sp, path_next);

    error = sandbox_vnode_name(uvp, rvp, cred, pathlist);


fail:
succeed:
    if (locked_uvp) {
        /* vrele() must be called on an unlocked vnode */
        VOP_UNLOCK(uvp);
        vrele(uvp); /* matches increment from VOP_LOOKUP() */
    }

    if (lvp != NULL)
        SANDBOX_VNODE_PRINT(lvp, "lvp");
    if (uvp != NULL)
        SANDBOX_VNODE_PRINT(uvp, "uvp");
    return (error);
}

int
sandbox_vnode_to_path(struct vnode *vp, char *outpath, size_t outpathlen)
{
    int error = 0;
    char basename[256] = { 0 };
    char *bp = NULL;
    struct vnode *dvp = NULL;
    bool locked_dvp = false;
    struct vnode *rvp = NULL;
    kauth_cred_t cred = NULL;
    struct sandbox_path_list pathlist;
    struct sandbox_path *sp = NULL;
    struct sandbox_path *tmp = NULL;

    SIMPLEQ_INIT(&pathlist);

    bp = &basename[256];
    *(--bp) = '\0';

    cred = kauth_cred_alloc();

    rvp = curlwp->l_proc->p_cwdi->cwdi_rdir; 
    if (rvp == NULL) {
        /* TODO: I think rootvnode is global variable declared in sys/vnode.h
         * that we could set rvp to * in case cwdi_rdir is NULL.
         */
        if (rootvnode != NULL) {
             rvp = rootvnode;
        } else {
            SANDBOX_LOG_ERROR("cannot get root directory\n");
            error = 1;
            goto fail;
        }
    }
    vref(rvp);

    SANDBOX_VNODE_PRINT(vp, "vp");

    /* bp will point to vp's filename (as recorded in the dvp directory record)
     */
    error = cache_revlookup(vp, &dvp, &bp, basename);
    if (error != 0) {
        SANDBOX_LOG_ERROR("cache_revlookup failed (%d)\n", error);
        SANDBOX_VNODE_PRINT(vp, "vp");
        error = 1;
        goto fail;
    }

    /* cache_revlookup() post-conditions:
     *   - vp is unchanged
     *   - dvp->v_usecount is incremeneted
     */
    SANDBOX_VNODE_PRINT(vp, "vp");
    SANDBOX_VNODE_PRINT(dvp, "dvp");
    SANDBOX_LOG_DEBUG("basename: '%s'\n", bp);

    /* using VOP_ISLOCKED (other than for debugging) is frowned upon */
    if (!VOP_ISLOCKED(dvp)) {
        /* XXX: I think we only need a LK_SHARED */
        vn_lock(dvp, LK_SHARED | LK_RETRY);
        locked_dvp = true;
    }
    
    /* retrieves the fullpath for dvp */
    error = sandbox_vnode_name(dvp, rvp, cred, &pathlist);
    if (error != 0) {
        SANDBOX_LOG_ERROR("sandbox_vnode_name() failed (%d)\n", error);
        error = 1;
        goto fail;
    }

    /* concatenate the path components in path list */
    SIMPLEQ_FOREACH_SAFE(sp, &pathlist, path_next, tmp) {
        /* TODO: check for buffer overrun */
        strcat(outpath, "/");
        strcat(outpath, sp->path);
        sandbox_path_destroy(sp);
    } 

    /* if bp is the rootdir don't end up with '//' */
    strcat(outpath, "/");
    if (strcmp(bp, "/") != 0)
        strcat(outpath, bp);
    
fail:
    SANDBOX_VNODE_PRINT(vp, "vp");
    if (dvp != NULL)
        SANDBOX_VNODE_PRINT(dvp, "dvp");

    if (locked_dvp) {
        /* vrele() must be called on an unlocked vnode */
        VOP_UNLOCK(dvp);
        vrele(dvp); /* matches increment from cache_revlookup() */
    }

    if (rvp != NULL)
        vrele(rvp); /* mathes vref() at start of function() */

    if (cred != NULL)
        kauth_cred_free(cred);

    return (error);
}
