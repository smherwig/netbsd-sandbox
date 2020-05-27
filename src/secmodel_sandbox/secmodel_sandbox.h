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

#ifndef _SECMODEL_SANDBOX_H_
#define _SECMODEL_SANDBOX_H_

#include <sys/queue.h>

#include <sys/kauth.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#include "sandbox.h"

#define SECMODEL_SANDBOX_ID   "edu.umd.cs.smherwig.secmodel.sandbox"
#define SECMODEL_SANDBOX_NAME "process sandbox"

extern kauth_key_t secmodel_sandbox_key;

void secmodel_sandbox_init(void);
void secmodel_sandbox_start(void);
int sysctl_security_sandbox_setup(struct sysctllog **clog);
void secmodel_sandbox_attachcurproc(struct sandbox_list *sandbox_list);
void secmodel_sandbox_stop(void);
void secmodel_sandbox_fini(void);

int secmodel_sandbox_system_cb(kauth_cred_t, kauth_action_t,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

int secmodel_sandbox_process_cb(kauth_cred_t, kauth_action_t,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

int secmodel_sandbox_network_cb(kauth_cred_t, kauth_action_t,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

int secmodel_sandbox_machdep_cb(kauth_cred_t, kauth_action_t,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

int secmodel_sandbox_device_cb(kauth_cred_t, kauth_action_t,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

int secmodel_sandbox_vnode_cb(kauth_cred_t, kauth_action_t,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

#endif /* !_SECMODEL_SANDBOX_H_ */
