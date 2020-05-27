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
#include <sys/cdefs.h>
#include <sys/module.h>

#include <sys/queue.h>

#include <sys/filedesc.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/lua.h>
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <secmodel/secmodel.h>

#include "sandbox.h"
#include "sandbox_device.h"
#include "sandbox_lua.h"
#include "secmodel_sandbox.h"

#include "sandbox_log.h"

MODULE(MODULE_CLASS_SECMODEL, secmodel_sandbox, "lua");

kauth_key_t secmodel_sandbox_key;

static secmodel_t secmodel_sandbox = NULL;
static kauth_listener_t l_system = NULL;
static kauth_listener_t l_process = NULL;
static kauth_listener_t l_network = NULL;
static kauth_listener_t l_machdep = NULL;
static kauth_listener_t l_device = NULL;
static kauth_listener_t l_vnode = NULL;
static kauth_listener_t l_cred = NULL;
static struct sysctllog *sandbox_sysctl_log = NULL;

#if 0
static LIST_HEAD(, sandbox) secmodel_sandbox_list = 
    LIST_HEAD_INITIALIZER(secmodel_sandbox_list);
static int secmodel_sandbox_n = 0;
#endif

/* 
 * FORWARD DECLARATIONS
 */

static int secmodel_sandbox_register(void);
static void secmodel_sandbox_deregister(void);
static int secmodel_sandbox_modinit(void);
static void secmodel_sandbox_modfini(void);
static int secmodel_sandbox_cred_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3);

/*
 * MODULE LOAD/UNLOAD HELPERS
 */

/* registers both the secmodel and the secmodel's key */
static int
secmodel_sandbox_register(void)
{
    int error = 0;

    SANDBOX_LOG_TRACE_ENTER;

    error = secmodel_register(&secmodel_sandbox,
        SECMODEL_SANDBOX_ID, SECMODEL_SANDBOX_NAME, NULL, NULL, NULL);
    if (error != 0) {
        SANDBOX_LOG_ERROR("secmodel_register() failed: error=%d\n", error);
        goto fail;
    }

    error = kauth_register_key(secmodel_sandbox, &secmodel_sandbox_key);
    if (error != 0) {
        SANDBOX_LOG_ERROR("kauth_register_key() failed: error=%d\n", error);  
        goto fail;
    }

    goto succeed;

fail:
    if (secmodel_sandbox != NULL) {
        (void)secmodel_deregister(secmodel_sandbox);
        secmodel_sandbox = NULL;
    }
succeed:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

/* deregisters both the secmodel and the secmodel's key */
static void
secmodel_sandbox_deregister(void)
{
    int error = 0;

    SANDBOX_LOG_TRACE_ENTER;

    if (secmodel_sandbox == NULL)
        goto done;

    error = kauth_deregister_key(secmodel_sandbox_key);
    if (error != 0) 
        SANDBOX_LOG_ERROR("kauth_deregister_key() failed; error=%d\n", error);

    error = secmodel_deregister(secmodel_sandbox);
    if (error != 0)
        SANDBOX_LOG_ERROR("secmodel_deregister() failed; error=%d\n", error);

    secmodel_sandbox = NULL;

done:
    SANDBOX_LOG_TRACE_EXIT;
    return;
}

static int
secmodel_sandbox_modinit(void)
{
    int error = 0;
    SANDBOX_LOG_TRACE_ENTER;

    error = secmodel_sandbox_register();
    if (error != 0)
        goto fail;
        
    secmodel_sandbox_start();
    error = sysctl_security_sandbox_setup(&sandbox_sysctl_log);
    if (error != 0)
        goto fail;
        
    error = sandbox_device_init();
    if (error != 0)
        goto fail;

    goto succeed;

fail:
    error = 1;
succeed:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

static void
secmodel_sandbox_modfini(void)
{
    SANDBOX_LOG_TRACE_ENTER;
 
    sandbox_device_fini();

    if (sandbox_sysctl_log != NULL) {
        sysctl_teardown(&sandbox_sysctl_log);
        sandbox_sysctl_log = NULL;
    }

    secmodel_sandbox_stop();
    secmodel_sandbox_deregister();

    SANDBOX_LOG_TRACE_EXIT;
}

/*
 * CREDENTIAL INHERITANCE
 */

static int 
secmodel_sandbox_cred_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    struct cwdinfo * cwdinfo = NULL;
    kauth_cred_t tocred;
    struct proc *parent = NULL;
    struct proc *child= NULL;
    struct sandbox_list *sandbox_list = NULL;

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list == NULL)
        goto done;

    switch (action) {
    case KAUTH_CRED_COPY:
        tocred = (kauth_cred_t)arg0;
        SANDBOX_LOG_INFO("KAUTH_CRED_COPY\n");
        sandbox_list_copy(sandbox_list, tocred);
        break;
    case KAUTH_CRED_FORK:
        /* see sys/kern/kern_auth.c::kauth_proc_fork */
        parent = (struct proc *)arg0;
        child = (struct proc *)arg1;
        SANDBOX_LOG_INFO("KAUTH_CRED_FORK (%ld -> %ld\n",
                (long)parent->p_pid, (long)child->p_pid);
        sandbox_list_fork(parent, child, cred);
        break;
    case KAUTH_CRED_CHROOT:
        //SANDBOX_LOG_DEBUG("KAUTH_CRED_CHROOT\n");
        cwdinfo = arg0;
        (void)cwdinfo;
        break;
    case KAUTH_CRED_FREE:
        SANDBOX_LOG_INFO("KAUTH_CRED_FREE\n");
        sandbox_list_destroy(sandbox_list);
        break;
    case KAUTH_CRED_INIT:
        SANDBOX_LOG_INFO("KAUTH_CRED_INIT\n");
        break;
    default:
        SANDBOX_LOG_WARN("unknown action %d for scope %s\n", action, KAUTH_SCOPE_CRED);
        goto done;
    }

done:
    /* required to return KAUTH_RESULT_ALLOW */
    return (KAUTH_RESULT_ALLOW);
}

/* 
 * SECMODEL INTERFACE
 */

void
secmodel_sandbox_init(void)
{

}

void
secmodel_sandbox_fini(void)
{
    int error = 0;

    SANDBOX_LOG_TRACE_ENTER;

    sandbox_device_fini();
    sysctl_teardown(&sandbox_sysctl_log);

    /* TODO: keep a list of all existing sandboxes and free them */

    error = kauth_deregister_key(secmodel_sandbox_key);
    if (error != 0) 
        SANDBOX_LOG_ERROR("kauth_deregister_key() failed; error=%d\n", error);

    error = secmodel_deregister(secmodel_sandbox);
    if (error != 0)
        SANDBOX_LOG_ERROR("secmodel_deregister() failed; error=%d\n", error);

    SANDBOX_LOG_TRACE_EXIT;
    return;
}

/* TODO: can replace with SYSCTL_SETUP */
int
sysctl_security_sandbox_setup(struct sysctllog **clog)
{
    int error = 0;
	const struct sysctlnode *rnode = NULL;

    SANDBOX_LOG_TRACE_ENTER;

	error = sysctl_createv(clog, 0, NULL, &rnode,
		       CTLFLAG_PERMANENT, CTLTYPE_NODE, "models", 
               NULL, NULL, 0, NULL, 0,
		       CTL_SECURITY, CTL_CREATE, CTL_EOL);
    if (error) {
        SANDBOX_LOG_ERROR("sysctl_createv('models') failed: error=%d\n", error);
        goto fail;
    }

	error = sysctl_createv(clog, 0, &rnode, &rnode,
		       CTLFLAG_PERMANENT, CTLTYPE_NODE, "sandbox", 
               NULL, NULL, 0, NULL, 0,
		       CTL_CREATE, CTL_EOL);
    if (error) {
        SANDBOX_LOG_ERROR("sysctl_createv('sandbox') failed: error=%d\n", error);
        goto fail;
    }

	error = sysctl_createv(clog, 0, &rnode, NULL,
		       CTLFLAG_PERMANENT, CTLTYPE_STRING, "name", 
               NULL, NULL, 0, __UNCONST(SECMODEL_SANDBOX_NAME), 0,
		       CTL_CREATE, CTL_EOL);
    if (error) {
        SANDBOX_LOG_ERROR("sysctl_createv('name') failed: error=%d\n", error);
        goto fail;
    }

    goto succeed;

fail:
    if (clog != NULL) {
        sysctl_teardown(clog);
        *clog = NULL;
    }
    error = 1;
succeed:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

void
secmodel_sandbox_start(void)
{
    SANDBOX_LOG_TRACE_ENTER;

    l_system = kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
            secmodel_sandbox_system_cb, NULL);
    l_process = kauth_listen_scope(KAUTH_SCOPE_PROCESS,
            secmodel_sandbox_process_cb, NULL);
    l_network = kauth_listen_scope(KAUTH_SCOPE_NETWORK,
            secmodel_sandbox_network_cb, NULL);
    l_machdep = kauth_listen_scope(KAUTH_SCOPE_MACHDEP,
            secmodel_sandbox_machdep_cb, NULL);
    l_device = kauth_listen_scope(KAUTH_SCOPE_DEVICE,
            secmodel_sandbox_device_cb, NULL);
    l_vnode = kauth_listen_scope(KAUTH_SCOPE_VNODE,
            secmodel_sandbox_vnode_cb, NULL);
    l_cred = kauth_listen_scope(KAUTH_SCOPE_CRED,
            secmodel_sandbox_cred_cb, NULL);

    SANDBOX_LOG_TRACE_EXIT;
}

void
secmodel_sandbox_stop(void)
{
    SANDBOX_LOG_TRACE_ENTER;

    /* XXX: kauth_unlisten_scope checks for a NULL argument */

    kauth_unlisten_scope(l_system);
    l_system = NULL;
    
    kauth_unlisten_scope(l_process);
    l_process = NULL;

    kauth_unlisten_scope(l_network);
    l_network = NULL;

    kauth_unlisten_scope(l_machdep);
    l_machdep = NULL;

    kauth_unlisten_scope(l_device);
    l_device = NULL;

    kauth_unlisten_scope(l_vnode);
    l_vnode = NULL;

    kauth_unlisten_scope(l_cred);
    l_cred = NULL;

    SANDBOX_LOG_TRACE_EXIT;
}

#if 0
void
secmodel_sandbox_addsandboxlist(struct sandbox_list *sandbox_list)
{
    SLIST_INSERT_HEAD(&secmodel_sandbox_lists, sandbox_list, sandbox_list_next);
}
#endif

int
secmodel_sandbox_system_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_list *sandbox_list = NULL;
    enum kauth_system_req req = (enum kauth_system_req)arg0;
    
    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list != NULL) {
        result = sandbox_list_evalsystem(sandbox_list, cred, action, req, arg1,
                arg2, arg3);
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);
    }

    return (result);
}

int
secmodel_sandbox_process_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_list *sandbox_list = NULL;
    struct proc *p = (struct proc *)arg0;

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list != NULL) {
        result = sandbox_list_evalprocess(sandbox_list, cred, action, p, arg1,
                arg2, arg3);
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);
    }

    return (result);
}

int
secmodel_sandbox_network_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_list *sandbox_list = NULL;
    enum kauth_network_req req = (enum kauth_network_req)arg0;

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list != NULL) {
        result = sandbox_list_evalnetwork(sandbox_list, cred, action, req, arg1,
                arg2, arg3);
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);
    }

    return (result);
}

int
secmodel_sandbox_machdep_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_list *sandbox_list = NULL;

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list != NULL) {
        result = sandbox_list_evalmachdep(sandbox_list, cred, action, arg0,
                arg1, arg2, arg3);
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);
    }

    return (result);
}

int
secmodel_sandbox_device_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_list *sandbox_list = NULL;

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list != NULL) {
        result = sandbox_list_evaldevice(sandbox_list, cred, action, arg0,
                arg1, arg2, arg3);
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);
    }

    return (result);
}

int
secmodel_sandbox_vnode_cb(kauth_cred_t cred, kauth_action_t action,
        void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_list *sandbox_list = NULL;
    vnode_t *vp = (vnode_t *) arg0;
    vnode_t *dvp = (vnode_t *)arg1;

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list != NULL) {
        result = sandbox_list_evalvnode(sandbox_list, cred, action, vp, dvp);
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);
    }

    return (result);
}

/*
 * ATTACH A SANDBOX (INTERFACE BETWEEN SANDBOX DEVICE AND SANDBOX SECMODEL)
 */

/* look at sys/kern/kern_prot.c::do_setresgid() as an example */
/* XXX: why do we have to alloc a new cred? */
void 
secmodel_sandbox_attachcurproc(struct sandbox_list *sandbox_list)
{
    kauth_cred_t cred;
    kauth_cred_t ncred;

    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_DEBUG("attaching sandbox to process\n");

    ncred = kauth_cred_alloc();

    proc_crmod_enter();
    cred = curlwp->l_proc->p_cred;
    kauth_cred_clone(cred, ncred);
    kauth_cred_setdata(ncred, secmodel_sandbox_key, sandbox_list);
    /* Broadcast our credentials to the process and other LWPs */
    proc_crmod_leave(ncred, cred, true);

    SANDBOX_LOG_TRACE_EXIT;
    return;
}

/*
 * MODULE ENTRY POINT
 */

static int
secmodel_sandbox_modcmd(modcmd_t cmd, void *arg __unused)
{
    int error = 0;

    SANDBOX_LOG_TRACE_ENTER;

    switch (cmd) {
    case MODULE_CMD_INIT:
        SANDBOX_LOG_INFO("loading sandbox module\n");
        error = secmodel_sandbox_modinit();
        if (error != 0)
            secmodel_sandbox_modfini();
        break;
    case MODULE_CMD_FINI:
        SANDBOX_LOG_INFO("unloading sandbox module\n");
        secmodel_sandbox_modfini();
        break;
    case MODULE_CMD_STAT:
        break;
    default:
        error = ENOTTY;
    }

    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}
