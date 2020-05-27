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

#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#include <msys/cdefs.h>
#include <msys/types.h>
#include <msys/queue.h>

#include <msys/kauth.h>
#include <msys/lua.h>
#include <msys/proc.h>
#include <msys/vnode.h>

#include "sandbox_ruleset.h"

struct sandbox_list {
    SLIST_HEAD(, sandbox) head;
    SLIST_ENTRY(sandbox_list) sandbox_list_next;
    /* TODO: add a lock */
};

struct sandbox {
    klua_State  *K;
    struct sandbox_ruleset *ruleset;
    u_int refcnt;
    SLIST_ENTRY(sandbox) sandbox_next;
};

struct sandbox * sandbox_create(const char *script, int *error);
void sandbox_hold(struct sandbox *sandbox);
void sandbox_destroy(struct sandbox *sandbox);

struct sandbox_list * sandbox_list_create(void);

void sandbox_list_destroy(struct sandbox_list *sandbox_list);

int sandbox_list_evalsystem(struct sandbox_list *sandbox_list,
        kauth_cred_t cred, kauth_action_t action, enum kauth_system_req req,
        void *arg1, void *arg2, void *arg3);

int sandbox_list_evalprocess(struct sandbox_list *sandbox_list, 
        kauth_cred_t cred, kauth_action_t action, struct proc *p, void *arg1,
        void *arg2, void *arg3);

int sandbox_list_evalnetwork(struct sandbox_list *sandbox_list,
        kauth_cred_t cred, kauth_action_t action, enum kauth_network_req req,
        void *arg1, void *arg2, void *arg3);

int sandbox_list_evalmachdep(struct sandbox_list *sandbox_list,
        kauth_cred_t cred, kauth_action_t action, void *arg0, void *arg1,
        void *arg2, void *arg3);

int sandbox_list_evaldevice(struct sandbox_list *sandbox_list,
        kauth_cred_t cred, kauth_action_t action, void *arg0, void *arg1,
        void *arg2, void *arg3);

int sandbox_list_evalvnode(struct sandbox_list *sandbox_list,
        kauth_cred_t cred, kauth_action_t action, vnode_t *vp, vnode_t *dvp);

/* For MOCK purposes */
int sandbox_eval(struct sandbox *sandbox, kauth_cred_t cred,
        const struct sandbox_rule *rule, struct vnode *vp, const char *fmt, ...);

#endif /* ! _SANDBOX_H_ */
