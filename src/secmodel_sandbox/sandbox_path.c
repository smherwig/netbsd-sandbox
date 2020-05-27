/*-
 * Copyright (c) 2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Stephen Herwig.
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>  /**/
#include <sys/namei.h>  /**/
#include <sys/filedesc.h> /**/
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/vnode.h> /**/
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/uio.h>   /**/
#include <sys/kmem.h>   /**/
#include <sys/dirent.h>
#include <sys/kauth.h>
#include <sys/atomic.h>

#include <ufs/ufs/dir.h>    /* XXX only for DIRBLKSIZ */

#include "sandbox_path.h"

#include "sandbox_log.h"

struct sandbox_path *
sandbox_path_create(const char *path, bool resolve)
{
    int error = 0;
    struct sandbox_path *sp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(path != NULL);

    sp = kmem_zalloc(sizeof(*sp), KM_SLEEP);
    sp->refcnt = 1;
    /* TODO: check for overflow */
    memcpy(sp->path, path, strlen(path)); 

    if (resolve) {
        error = namei_simple_kernel(sp->path, NSM_FOLLOW_NOEMULROOT, &sp->vp);
        switch (error) {
        case 0:
            SANDBOX_LOG_DEBUG("success\n");
            vhold(sp->vp);
            break;
        case ENOENT:
            SANDBOX_LOG_DEBUG("'%s' does not exist\n", sp->path);
            sp->vp = NULL;
            break;
        default:
            SANDBOX_LOG_DEBUG("failed (%d)\n", error);
            sp->vp = NULL;
            break;
        }
    }

    SANDBOX_LOG_TRACE_EXIT;
    return(sp);
}

void
sandbox_path_hold(struct sandbox_path *sp)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(sp != NULL);
    KASSERT(sp->refcnt > 0);

    atomic_inc_uint(&sp->refcnt);

    SANDBOX_LOG_TRACE_EXIT;
}

void
sandbox_path_destroy(struct sandbox_path *sp)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(sp != NULL);
    KASSERT(sp->refcnt > 0);

    if (atomic_dec_uint_nv(&sp->refcnt) > 0)
        goto done;

    SANDBOX_LOG_DEBUG("destroying sandbox_path\n");
    if (sp->vp != NULL)
        holdrele(sp->vp);
    kmem_free(sp, sizeof(*sp));

done:
    SANDBOX_LOG_TRACE_EXIT;
    return;
}

int
sandbox_path_isequal(const struct sandbox_path *spa,
        const struct sandbox_path *spb)
{
    int result = 0;

    SANDBOX_LOG_TRACE_ENTER;

    if ((spa == NULL) && (spb == NULL)) {
        result = 1;
        goto done;
    }

    if ((spa == NULL) && (spb != NULL)) {
        result = 0;
        goto done;
    }

    if ((spa != NULL) && (spb == NULL)) {
        result = 0;
        goto done;
    }

    if (strcmp(spa->path, spb->path) == 0)
        result = 1;
    else
        result = 0;

done:
    SANDBOX_LOG_TRACE_EXIT;
    return (result);
}

void
sandbox_path_list_destroy(struct sandbox_path_list *list)
{
    struct sandbox_path *sp = NULL;
    struct sandbox_path *tmp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(list != NULL);

    SIMPLEQ_FOREACH_SAFE(sp, list, path_next, tmp) {
        sandbox_path_destroy(sp);
    }

    SANDBOX_LOG_TRACE_EXIT;
}

void 
sandbox_path_list_concat(struct sandbox_path_list *to, 
        struct sandbox_path_list *from)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(to != NULL);
    KASSERT(from != NULL);

    /* nodes get transfered from 'from' to 'to'; 'from' gets initialized back
     * to an empty list
     */
    SIMPLEQ_CONCAT(to, from);

    SANDBOX_LOG_TRACE_EXIT;
}

int
sandbox_path_list_isequal(const struct sandbox_path_list *a, 
        const struct sandbox_path_list *b)
{
    int equal = 1;
    struct sandbox_path *spa = NULL;
    struct sandbox_path *spb = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(a != NULL);
    KASSERT(b != NULL);

    spa = SIMPLEQ_FIRST(a);
    spb = SIMPLEQ_FIRST(b);

    while (1) {
        if (spa == NULL || spb == NULL)
            break;

        if (!sandbox_path_isequal(spa, spb)) {
            equal = 0;
            break;
        }

        spa = SIMPLEQ_NEXT(spa, path_next);
        spb = SIMPLEQ_NEXT(spb, path_next);
    }

    if (equal == 1)
        if ((spa == NULL && spb != NULL) || (spa != NULL && spb == NULL))
                equal = 0;

    SANDBOX_LOG_TRACE_EXIT;
    return (equal);
}

int
sandbox_path_list_containsvnode(const struct sandbox_path_list *list,
        const struct vnode *vp)
{
    int contains = 0;
    struct sandbox_path *sp = NULL;

    SANDBOX_LOG_TRACE_EXIT;

    KASSERT(list != NULL);

    if (vp == NULL)
        goto done;

    SIMPLEQ_FOREACH(sp, list, path_next) {
        if (sp->vp == vp) {
            SANDBOX_LOG_DEBUG("found match\n");
            contains = 1;
            break;
        }
    }

    if (!contains)
        SANDBOX_LOG_DEBUG("no match\n");

done:
    SANDBOX_LOG_TRACE_ENTER;
    return (contains);
}
