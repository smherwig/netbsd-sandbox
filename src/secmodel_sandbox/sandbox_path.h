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

#ifndef _SANDBOX_PATH_H_
#define _SANDBOX_PATH_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/vnode.h>

#define SANDBOX_PATH_MAXPATHLEN 256

struct sandbox_path {
    char path[SANDBOX_PATH_MAXPATHLEN];
    struct vnode *vp;
    u_int refcnt;
    SIMPLEQ_ENTRY(sandbox_path) path_next;
};

/* struct sandbox_path_list { }; */
SIMPLEQ_HEAD(sandbox_path_list, sandbox_path);

struct sandbox_path * sandbox_path_create(const char *path, bool resolve);
void sandbox_path_hold(struct sandbox_path *path);
void sandbox_path_destroy(struct sandbox_path *path);
int sandbox_path_isequal(const struct sandbox_path *a, 
        const struct sandbox_path *b);

void sandbox_path_list_concat(struct sandbox_path_list *to, 
        struct sandbox_path_list *from);

/* does not destroy head */
void sandbox_path_list_destroy(struct sandbox_path_list *list);
int sandbox_path_list_isequal(const struct sandbox_path_list *a, 
        const struct sandbox_path_list *b);

int sandbox_path_list_containsvnode(const struct sandbox_path_list *list,
        const struct vnode *vp);

#endif /* !_SANDBOX_PATH_H_ */
