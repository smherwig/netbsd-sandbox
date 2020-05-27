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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/signalvar.h>

#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <sys/kmem.h>
#include <sys/kauth.h>
#include <sys/filedesc.h>
#include <sys/lua.h>
#include <sys/atomic.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "sandbox.h"
#include "sandbox_lua.h"
#include "sandbox_path.h"
#include "sandbox_rule.h"
#include "sandbox_ruleset.h"
#include "sandbox_spec.h"
#include "secmodel_sandbox.h"

#include "sandbox_log.h"

#define SANDBOX_ARRAY_SIZE(a) sizeof(a) / sizeof (char *)
#define SANDBOX_ARRAY_GET(a, i) ( (i) < (SANDBOX_ARRAY_SIZE(a)) ) ? a[(i)] : NULL
#define SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg) ((lua_Integer)  ((intptr_t)(arg))  )

int sandbox_nlists = 0;

static int sandbox_serial = 0;

/* sandbox_system_strmap[KAUTH_SYSTEM_ACCOUNTING] -> "accounting" */
static const char * sandbox_system_strmap[] = {
    NULL,
	"accounting",   /* = 1 */
	"chroot",
	"chsysflags",
	"cpu",
	"debug",
	"filehandle",
	"mknod",
	"mount",
	"pset",
	"reboot",
	"setidcore",
	"swapctl",
	"sysctl",
	"time",
	"module",
	"fs_reservedspace",
	"fs_quota",
	"semaphore",
	"sysvipc",
	"mqueue",
	"veriexec",
	"devmapper",
	"map_va_zero",
	"lfs",
	"fs_extattr",
	"fs_snapshot"
};

static const char * sandbox_system_req_strmap[] = {
    NULL,
	"chroot",   /* = 1 */
	"fchroot",
	"setstate",
	"ipkdb",
	"get",
	"new",
	"unmount",
	"update",
	"assign",
	"bind",
	"create",
	"destroy",
	"add",
	"delete",
	"desc",
	"modify",
	"prvt",
	"adjtime",
	"ntpadjtime",
	"rtcoffset",
	"system",
	"timecounters",
	"get",
	"manage",
	"nolimit",
	"onoff",
	"bypass",
	"shm_lock",
	"shm_unlock",
	"msgq_oversize",
	"access",
	"modify",
	"markv",
	"bmapv",
	"segclean",
	"segwait",
	"fcntl",
	"umap",
	"device",
};

static const char * sandbox_process_strmap[] = {
    NULL,
	"cansee",   /* = 1 */
	"corename",
	"fork",
	"kevent_filter",
	"ktrace",
	"nice",
	"procfs",
	"ptrace",
	"rlimit",
	"scheduler_getaffinity",
	"scheduler_setaffinity",
	"scheduler_getparam",
	"scheduler_setparam",
	"setid",
	"signal",
	"stopflag"
};

static const char * sandbox_process_req_strmap[] = {
    NULL,
	"args", /* = 1 */
	"entry",
	"env",
	"openfiles",
	"get",
	"set",
	"persistent",
	"ctl",
	"read",
	"rw",
	"write",
	"get",
	"set",
	"bypass",
};

static const char * sandbox_network_strmap[] = {
    NULL,
	"altq",    /* = 1 */
	"bind",
	"firewall",
	"interface",
	"forwsrcrt",
	"nfs",
	"route",
	"socket",
	"interface_ppp",
	"interface_slip",
	"interface_strip",
	"interface_tun",
	"interface_bridge",
	"ipsec",
	"interface_pvc",
	"ipv6",
	"smb"
};

static const char * sandbox_network_req_strmap[] = {
    NULL,
    /* KAUTH_REQ_NETWORK_ALTQ_ */
	"afmap",  /* = 1 */
	"blue",
	"cbq",
	"cdnr",
	"conf",
	"fifoq",
	"hfsc",
	"jobs",
	"priq",
	"red",
	"rio",
	"wfq",
    /* KAUTH_REQ_NETWORK_BIND_ */
	"port",
	"privport",
    /* KAUTH_REQ_NETWORK_FIREWALL_ */
	"fw",
	"nat",
    /* KAUTH_REQ_NETWORK_INTERFACE_ */
	"get",
	"getpriv",
	"set",
	"setpriv",
    /* KAUTH_REQ_NETWORK_NFS_ */
	"export",
	"svc",
    /* KAUTH_REQ_NETWORK_SOCKET_ */
	"open",
	"rawsock",
	"cansee",
	"drop",
	"setpriv",
    /* KAUTH_REQ_NETWORK_INTERFACE_PPP_ */
	"add",
    /* KAUTH_REQ_NETWORK_INTERFACE_SLIP_ */
	"add",
    /* KAUTH_REQ_NETWORK_INTERFACE_STRIP_ */
	"add",
    /* KAUTH_REQ_NETWORK_INTERFACE_TUN_ */
	"add",
    /* KAUTH_REQ_NETWORK_INTERFACE_IPV6_ */
	"hopbyhop",
    /* KAUTH_REQ_NETWORK_INTERFACE_BRIDGE_ */
	"getpriv",
	"setpriv",
    /* KAUTH_REQ_NETWORK_INTERFACE_IPSEC_ */
	"bypass",
    /* KAUTH_REQ_NETWORK_IPV6_ */
	"join_multicast",
    /* KAUTH_REQ_NETWORK_INTERFACE_IPVC_ */
	"add",
    /* KAUTH_REQ_NETWORK_SMB_ */
	"share_access",
	"share_create",
	"vc_access",
	"vc_create",
    /* KAUTH_REQ_NETWORK_INTERFACE_FIRMWARE */
	"interface_firmware",
};

static const char * sandbox_machdep_strmap[] = {
    NULL,
	"cacheflush",   /* = 1 */
	"cpu_ucode_apply",
	"ioperm_get",
	"ioperm_set",
	"iopl",
	"ldt_get",
	"ldt_set",
	"mtrr_get",
	"mtrr_set",
	"nvram",
	"unmanagedmem",
	"pxg",
};

static const char * sandbox_device_strmap[] = {
    NULL,
	"tty_open", /* = 1 */
	"tty_privset",
	"tty_sti",
	"rawio_spec",
	"rawio_passthru",
	"bluetooth_setpriv",
	"rnd_adddata",
	"rnd_adddata_estimate",
	"rnd_getpriv",
	"rnd_setpriv",
	"bluetooth_bcsp",
	"bluetooth_btuart",
	"gpio_pinset",
	"bluetooth_send",
	"bluetooth_recv",
	"tty_virtual",
	"wscons_keyboard_bell",
	"wscons_keyboard_keyrepeat",
};

static const char * sandbox_device_req_strmap[] = {
    NULL,
	"read",   /* = 1 */
	"write",
	"rw",
	"add",
	"add",
};

static const char *sandbox_vnode_strmap[] = {
    "read_data",            /* 1U << 0:        1 */
    "write_data",           /* 1U << 1:        2 */
    "execute",              /* 1U << 2:        4 */
    "delete",               /* 1U << 3:        8 */
    "append_data",          /* 1U << 4:       16 */
    "read_times",           /* 1U << 5:       32 */
    "write_times",          /* 1U << 6:       64 */
    "read_flags",           /* 1U << 7:      128 */
    "write_flags",          /* 1U << 8:      256 */
    "read_sysflags",        /* 1U << 9:      512 */
    "write_sysflags",       /* 1U << 10:    1024 */
    "rename",               /* 1U << 11:    2048 */
    "change_ownership",     /* 1U << 12:    4096 */
    "read_security",        /* 1U << 13:    8192 */
    "write_security",       /* 1U << 14:   16384 */
    "read_attributes",      /* 1U << 15:   32768 */
    "write_attributes",     /* 1U << 16:   65536 */
    "read_extattributes",   /* 1U << 17:  131072 */
    "write_extattributes",  /* 1U << 18:  262144 */
    "retain_suid",          /* 1U << 19:  524288 */
    "regain_sgid",          /* 1U << 20: 1048576 */
    "revoke",               /* 1U << 21: 2097152 */
    NULL
};

static int
sandbox_veval(struct sandbox *sandbox, kauth_cred_t cred,
        const struct sandbox_rule *rule, struct vnode *vp, const char *fmt, va_list ap)
{
    int result = KAUTH_RESULT_DEFER;
    int has_allow = 0;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *ref = NULL;
    va_list apsave;

    SANDBOX_LOG_DEBUG("searching for rule: %s.%s.%s\n", SANDBOX_RULE_SCOPE(rule),
        SANDBOX_RULE_ACTION(rule), SANDBOX_RULE_SUBACTION(rule));

    node = sandbox_ruleset_search(sandbox->ruleset, rule);
    SANDBOX_LOG_DEBUG("found rule '%s'\n", node->name);
    
    if (node->type & SANDBOX_RULETYPE_TRILEAN) {
        result = node->value;
        if (result == KAUTH_RESULT_DENY)
            goto done;

        if (result == KAUTH_RESULT_ALLOW)
            has_allow = 1;
    }

    if (node->type & SANDBOX_RULETYPE_BLACKLIST) {
        if (sandbox_path_list_containsvnode(&node->blacklist, vp)) {
            result = KAUTH_RESULT_DENY;
            goto done;
        } else {
            /* TODO: I'm not sure whether it makes sense to allow or defer 
             * in the case where the vnode is not on the blacklist.  For now,
             * I'm going to allow.
             */
            has_allow = 1;
        }
    }

    if (node->type & SANDBOX_RULETYPE_FUNCTION) {
        SIMPLEQ_FOREACH(ref, &node->funclist, ref_next) {
            va_copy(apsave, ap);
            result = sandbox_lua_veval(sandbox->K, ref->value, cred, rule, fmt, apsave);
            va_end(apsave);
            if (result == KAUTH_RESULT_DENY)
                goto done;

            if (result == KAUTH_RESULT_ALLOW)
                has_allow = 1;
        }
    }

    if (node->type & SANDBOX_RULETYPE_WHITELIST) {
        if (sandbox_path_list_containsvnode(&node->whitelist, vp)) {
            result = KAUTH_RESULT_ALLOW;
        } else {
            /* TODO: I'm not sure whether it makes sense to allow or defer 
             * in the case where the vnode is not on the whitelist.  For now,
             * I'm going to deny.
             */
            result = KAUTH_RESULT_DENY;
            goto done;
        }
    }

    /* if we made it here, there was not a deny.  If there was at least one
     * allow, then allow the operation; otherwiser, defer it.
     */
    result = has_allow ? KAUTH_RESULT_ALLOW : KAUTH_RESULT_DEFER;

done:
    if (result == KAUTH_RESULT_DENY && 
            (sandbox->flags & SANDBOX_ON_DENY_ABORT)) {
        sigexit(curlwp, SIGILL);
    }

    return (result);
}

static int
sandbox_list_eval(struct sandbox_list *sandbox_list, kauth_cred_t cred, 
        const struct sandbox_rule *rule, struct vnode *vp, const char *fmt, ...)
{
    int result = KAUTH_RESULT_DEFER;
    int has_allow = 0;
    struct sandbox *sandbox = NULL;
    va_list ap;

    if (fmt != NULL)
        va_start(ap, fmt);

    SLIST_FOREACH(sandbox, &sandbox_list->head, sandbox_next) {
        result = sandbox_veval(sandbox, cred, rule, vp, fmt, ap);
        if (result == KAUTH_RESULT_DENY)
            goto done;
        if (result == KAUTH_RESULT_ALLOW)
            has_allow = 1;
    }

    /* if we made it here, there was not a deny.  If there was at least one
     * allow, then allow the operation; otherwiser, defer it.
     */
    result = has_allow ? KAUTH_RESULT_ALLOW : KAUTH_RESULT_DEFER;

done:
    if (fmt != NULL)
        va_end(ap);
    return (result);
}

#define SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, rule) \
    sandbox_list_eval(sandbox_list, cred, rule, NULL, NULL)

#define SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, rule, proc) \
    sandbox_list_eval(sandbox_list, cred, rule, NULL, "p", proc)

#define SANDBOX_LIST_EVAL_VNODE(sandbox_list, cred, rule, vp) \
    sandbox_list_eval(sandbox_list, cred, rule, vp, "v", vp)

struct sandbox *
sandbox_create(const char *script, int flags, int *error)
{
    int result = 0;
    struct sandbox *sandbox = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_DEBUG("creating new sandbox\n");

    sandbox = kmem_zalloc(sizeof(*sandbox), KM_SLEEP);
    sandbox->refcnt = 1;
    sandbox->flags = flags;
    sandbox->ruleset = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    sandbox_lua_newstate(sandbox); /* sets sandbox->K */

    result = sandbox_lua_load(sandbox->K, script);
    if (result != 0) {
        sandbox_destroy(sandbox);
        sandbox = NULL;
    } 

    if (error != NULL)
        *error = result;

    SANDBOX_LOG_TRACE_EXIT;
    return (sandbox);
}

void
sandbox_hold(struct sandbox *sandbox)
{
    KASSERT(sandbox != NULL);
    KASSERT(sandbox->refcnt > 0);

    SANDBOX_LOG_DEBUG("holding sandbox %u -> %u\n", sandbox->refcnt, sandbox->refcnt + 1);
    atomic_inc_uint(&sandbox->refcnt);
}

void
sandbox_destroy(struct sandbox *sandbox)
{
    KASSERT(sandbox != NULL);
    KASSERT(sandbox->refcnt > 0);

    SANDBOX_LOG_DEBUG("sandbox refcnt %u -> %u\n", sandbox->refcnt, sandbox->refcnt - 1);

    if (atomic_dec_uint_nv(&sandbox->refcnt) > 0)
        return;

    SANDBOX_LOG_DEBUG("destroying sandbox\n");
    sandbox_ruleset_destroy(sandbox->ruleset);
    klua_close(sandbox->K);
    kmem_free(sandbox, sizeof(*sandbox));
}

int
sandbox_attach(const char *script, int flags)
{
    int error = 0;
    int is_new_list = 0;
    kauth_cred_t cred;
    struct sandbox_list *sandbox_list = NULL;
    struct sandbox *sandbox = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    cred = kauth_cred_get();

    sandbox_list = kauth_cred_getdata(cred, secmodel_sandbox_key);
    if (sandbox_list == NULL) {
        is_new_list = 1;
        sandbox_list = sandbox_list_create();
    }

    sandbox = sandbox_create(script, flags, &error);
    if (sandbox == NULL)
        goto fail;

    SLIST_INSERT_HEAD(&sandbox_list->head, sandbox, sandbox_next);

    if (is_new_list)
        secmodel_sandbox_attachcurproc(sandbox_list);
    else 
        kauth_cred_setdata(cred, secmodel_sandbox_key, sandbox_list);

fail:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

struct sandbox_list *
sandbox_list_create(void)
{
    struct sandbox_list *sandbox_list = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    sandbox_list = kmem_zalloc(sizeof(*sandbox_list), KM_SLEEP);
    SLIST_INIT(&sandbox_list->head);
    sandbox_list->serial = ++sandbox_serial;
    //secmodel_sandbox_addsandboxlist(sandbox_list);
    /* TODO: updating sandbox_nlists should be atomic */
    sandbox_nlists++;
    SANDBOX_LOG_INFO("creating sandbox_list %d\n", sandbox_list->serial);

    SANDBOX_LOG_TRACE_EXIT;
    return (sandbox_list);
}

/* cred is parent's cred; sandbox_list is parent's sandbox_list */
void
sandbox_list_fork(struct proc *parent, struct proc *child, kauth_cred_t cred) 
{
    kauth_cred_t childcred;
   
    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_DEBUG("fork (%lu -> %lu)\n", (unsigned long)parent->p_pid, (unsigned long)child->p_pid);

    /* see sys/kern/kauth_kauth.c::kauth_cred_dup()
     *
     * kauth_cred_dup() generates a KAUTH_CRED_COPY hook, 
     * which is where we create the child's own sandbox_list;
     */
    childcred = kauth_cred_dup(cred);
    child->p_cred = childcred;

    /* see sys/kern/kern_kauth.c::kauth_cred_fork()
     *
     * kauth_cred_fork() sets the childs cred to that of the parent, and
     * increments the refcnt on the cred.  Since we are giving the child a new
     * cred, we must decrement the parent cred's refcount by calling
     * kauth_cred_free().
     */
	mutex_enter(parent->p_lock);
	kauth_cred_free(parent->p_cred);
	mutex_exit(parent->p_lock);

    SANDBOX_LOG_TRACE_EXIT;
}

/* cred is the newly created credential; sandbox_list belongs to some other
 * credential.  
 *
 * We need to add a sandbox_list to cred and make it point to the
 * first entry in the old sandbox_list. We also need to up the refcount of all
 * sandbox's in the new list.
 */
void
sandbox_list_copy(const struct sandbox_list *sandbox_list, kauth_cred_t cred)
{
    struct sandbox_list *newlist = NULL;
    struct sandbox *sandbox = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_DEBUG("copying sandbox\n");

    /* TODO: lock the lists before operating on them */
    newlist = sandbox_list_create();

    /* this will remove the first item from sandbox_list, which is not what we
     * want:
     *      SLIST_INSERT_HEAD(&newlist->head, SLIST_FIRST(&sandbox_list->head), sandbox_next);
     *
     * instead we explicitly set slh_fist
     */
    newlist->head.slh_first = sandbox_list->head.slh_first;

    SLIST_FOREACH(sandbox, &newlist->head, sandbox_next) {
        sandbox_hold(sandbox);
    }
        
    kauth_cred_setdata(cred, secmodel_sandbox_key, newlist);

    SANDBOX_LOG_TRACE_EXIT;
}

void
sandbox_list_destroy(struct sandbox_list *sandbox_list) 
{
    struct sandbox *sandbox = NULL;
    struct sandbox *tmp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_INFO("destroying sandbox_list %d.  %d remaining\n", sandbox_list->serial,
            sandbox_nlists - 1);

    SLIST_FOREACH_SAFE(sandbox, &sandbox_list->head, sandbox_next, tmp) {
        sandbox_destroy(sandbox);
    }

    kmem_free(sandbox_list, sizeof(*sandbox_list));
    /* TODO: remove from secmodel_sandbox_lists? */

    /* TODO: decrementing sandbox_nlists must be atomic */
    sandbox_nlists--;

    SANDBOX_LOG_TRACE_EXIT;
}

int
sandbox_list_evalsystem(struct sandbox_list *sandbox_list, kauth_cred_t cred,
       kauth_action_t action, enum kauth_system_req req, void *arg1,
       void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_rule rule = {{ "system", NULL, NULL }};

    SANDBOX_RULE_ACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_system_strmap, action);
    SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_system_req_strmap, req);

    switch (action) {
    case KAUTH_SYSTEM_ACCOUNTING:
    case KAUTH_SYSTEM_CHROOT:
    case KAUTH_SYSTEM_FILEHANDLE:
    case KAUTH_SYSTEM_MKNOD:
    case KAUTH_SYSTEM_REBOOT:
    case KAUTH_SYSTEM_SETIDCORE:
    case KAUTH_SYSTEM_SWAPCTL:
    case KAUTH_SYSTEM_SYSCTL:
    case KAUTH_SYSTEM_DEBUG:
    case KAUTH_SYSTEM_FS_RESERVEDSPACE:
    case KAUTH_SYSTEM_DEVMAPPER:
    case KAUTH_SYSTEM_MAP_VA_ZERO:
    case KAUTH_SYSTEM_LFS:
        /* arg1=NULL, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_SYSTEM_CPU:
        switch (req) {
        case KAUTH_REQ_SYSTEM_CPU_SETSTATE:
            /* arg1=cpustate_t *, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_MOUNT:
        switch (req)  {
        case KAUTH_REQ_SYSTEM_MOUNT_GET:
            /* arg1=struct mount *mp, arg2=void *data, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_MOUNT_NEW:
            /* arg1=vnode_t *vp, arg2=int flags, arg3=void *data */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_MOUNT_UNMOUNT:
            /* arg1=struct mount *mp, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_MOUNT_UPDATE:
            /* arg1=struct mount *mp, arg2=int flags, arg3=void *data */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_MOUNT_UMAP:
            /* arg1=NULL, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_MOUNT_DEVICE:
            /* arg1=struct mount *mp, arg2=struct vnode *devvp, arg3=mode_t accessmode) */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_PSET:
        switch (req) {
        case KAUTH_REQ_SYSTEM_PSET_CREATE:
            /* arg1=NULL, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_PSET_ASSIGN:
        case KAUTH_REQ_SYSTEM_PSET_BIND:
        case KAUTH_REQ_SYSTEM_PSET_DESTROY:
            /* arg1=psetid_t psid, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_TIME:
        switch (req) {
        case KAUTH_REQ_SYSTEM_TIME_ADJTIME:
        case KAUTH_REQ_SYSTEM_TIME_NTPADJTIME:
            /* arg1=NULL, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_TIME_RTCOFFSET:
            /* arg1=int nrew_rtc_offset, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_TIME_SYSTEM:
            /* arg1=struct timespec *ts, arg2=struct timespec *delta, arg3=bool check_kauth */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_TIME_TIMECOUNTERS:
            /* arg1=char *name, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_MODULE:
        /* arg1=uintptr_t cmd, arg2=uintptr_t loadtype, arg3=NULL */
        result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "ii",
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1),
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg2));
        break;
    case KAUTH_SYSTEM_FS_QUOTA:
        switch (req) {
        case KAUTH_REQ_SYSTEM_FS_QUOTA_GET:
            /* arg1=struct mount *mp, arg2=uid_t id, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_FS_QUOTA_MANAGE:
            /* arg1=struct mount *mp, arg2=id_t kauth_id, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_FS_QUOTA_NOLIMIT:
            /* arg1=int i, arg2=vtype, arg3=NULL */
            result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "ii",
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1),
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg2));
            break;
        case KAUTH_REQ_SYSTEM_FS_QUOTA_ONOFF:
            /* arg1=struct mount *mp, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_SEMAPHORE:
        /* req=0 arg1=ksemt_t *ks, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_SYSTEM_SYSVIPC:
        switch (req) {
        case KAUTH_REQ_SYSTEM_SYSVIPC_BYPASS:
            /* arg1=struct ipc_perm *perm, arg2=int mode, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_SYSVIPC_SHM_LOCK:
        case KAUTH_REQ_SYSTEM_SYSVIPC_SHM_UNLOCK:
            /* arg1=NULL, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_SYSVIPC_MSGQ_OVERSIZE:
            /* arg1=int, arg2=int, arg3=NULL */
            result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "ii",
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1),
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg2));
            break;
        default:
            SANDBOX_LOG_ERROR("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_VERIEXEC:
        switch (req) {
        case KAUTH_REQ_SYSTEM_VERIEXEC_ACCESS:
            /* arg1=NULL, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_SYSTEM_VERIEXEC_MODIFY:
            /* arg1=u_long cmd, arg2=NULL, arg3=NULL */
            result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "i",
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1));
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_SYSTEM_FS_EXTATTR:
        /* req=0, arg1=struct mount *mp, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_SYSTEM_FS_SNAPSHOT:
        /* req=0, arg1=struct mount *mp, arg2=struct vnode *vmp, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    default:
        SANDBOX_LOG_WARN("unknown action (%u) for rule: %s\n", action,
                SANDBOX_RULE_SCOPE(&rule));
        break;
    }
    
    return (result);
} 

int
sandbox_list_evalprocess(struct sandbox_list *sandbox_list, kauth_cred_t cred,
       kauth_action_t action, struct proc *p, void *arg1, void *arg2, 
       void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_rule rule = {{ "process", NULL, NULL }};
    enum kauth_process_req req = 0;

    SANDBOX_RULE_ACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_process_strmap, action);

    switch (action) {
    case KAUTH_PROCESS_KEVENT_FILTER:
    case KAUTH_PROCESS_KTRACE:
    case KAUTH_PROCESS_SCHEDULER_GETAFFINITY:
    case KAUTH_PROCESS_SCHEDULER_SETAFFINITY:
    case KAUTH_PROCESS_SCHEDULER_GETPARAM:
    case KAUTH_PROCESS_SETID:
        /* arg1=NULL, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
        break;
    case KAUTH_PROCESS_CANSEE:
        /* arg1=req, arg2=NULL, arg3=NULL */
        req = (enum kauth_process_req)arg1;
        SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_process_req_strmap, req);
        result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
        break;
    case KAUTH_PROCESS_CORENAME:
        req = (enum kauth_process_req)arg1;
        switch (req) {
        case KAUTH_REQ_PROCESS_CORENAME_GET:
            /* arg1=req, arg2=NULL, arg3=NULL */
            SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_process_req_strmap, req);
            result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
            break;
        case KAUTH_REQ_PROCESS_CORENAME_SET:
            /* arg1=req, arg2=char *cnbuf, arg3=NULL */
            SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_process_req_strmap, req);
            result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_PROCESS_FORK:
    case KAUTH_PROCESS_NICE:
    case KAUTH_PROCESS_PTRACE:
    case KAUTH_PROCESS_SIGNAL:
    case KAUTH_PROCESS_STOPFLAG:
        /* arg1=int n, arg2=NULL, arg3=NULL */
        result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "pi", p,
                SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1));
        break;
    case KAUTH_PROCESS_PROCFS:
        /* arg1=struct pfsnode *pfs, arg2=req, arg3=NULL */
        SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_process_req_strmap, (unsigned long)arg2);
        result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
        break;
    case KAUTH_PROCESS_RLIMIT:
        /* arg1=req, arg2=struct rlimit *alimit, arg3=int which */
        SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_process_req_strmap, (unsigned long)arg1);
        result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
        break;
    case KAUTH_PROCESS_SCHEDULER_SETPARAM:
        /* arg1=struct lwp *t, arg2=int lpolicy, arg3=pri_t kpir */
        result = SANDBOX_LIST_EVAL_PROCESS(sandbox_list, cred, &rule, p);
        break;
    default:
        SANDBOX_LOG_WARN("unknown action (%u) for rule: %s\n", action,
                    SANDBOX_RULE_SCOPE(&rule));
        break;
    }

    return (result);
} 

int
sandbox_list_evalnetwork(struct sandbox_list *sandbox_list, kauth_cred_t cred,
       kauth_action_t action, enum kauth_network_req req, 
       void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_rule rule = { {"network", NULL, NULL } };

    SANDBOX_RULE_ACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_network_strmap, action);
    SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_network_req_strmap, req);

    switch (action) {
    case KAUTH_NETWORK_ALTQ:
    case KAUTH_NETWORK_FIREWALL:
    case KAUTH_NETWORK_FORWSRCRT:
    case KAUTH_NETWORK_NFS:
    case KAUTH_NETWORK_INTERFACE_PPP:
    case KAUTH_NETWORK_INTERFACE_SLIP:
    case KAUTH_NETWORK_INTERFACE_STRIP:
    case KAUTH_NETWORK_INTERFACE_TUN:
    case KAUTH_NETWORK_INTERFACE_PVC:
    case KAUTH_NETWORK_IPSEC:
    case KAUTH_NETWORK_IPV6:
        /* arg1=NULL, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_NETWORK_BIND:
        /* arg1=struct socket *, arg2=struct sockaddr *, arg3=NULL */
        result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "oa", 
                (struct socket *)arg1, (struct sockaddr *)arg2);
        break;
    case KAUTH_NETWORK_INTERFACE:
        switch (req) {
        case KAUTH_REQ_NETWORK_INTERFACE_GET:
        case KAUTH_REQ_NETWORK_INTERFACE_GETPRIV:
        case KAUTH_REQ_NETWORK_INTERFACE_SET:
        case KAUTH_REQ_NETWORK_INTERFACE_SETPRIV:
            /*  arg1=struct ifnet *, arg2=u_long cmd, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_NETWORK_INTERFACE_FIRMWARE:
            /* currently not used */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_NETWORK_ROUTE:
        /* req=0, arg1=struct rt_msghdr *, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_NETWORK_SOCKET:
        switch (req) {
        case KAUTH_REQ_NETWORK_SOCKET_RAWSOCK:
        case KAUTH_REQ_NETWORK_SOCKET_OPEN:
            /* arg1=int domain, arg2=int type, arg3=int protocol */
            result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "iii",
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1),
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg2),
                    SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg3));
            break;
        case KAUTH_REQ_NETWORK_SOCKET_CANSEE:
        case KAUTH_REQ_NETWORK_SOCKET_SETPRIV:
            /* arg1=struct socket *, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_NETWORK_SOCKET_DROP:
            /* arg1=struct socket *, arg2=struct tcpcb *, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    case KAUTH_NETWORK_SMB:
        switch (req) {
        case KAUTH_REQ_NETWORK_SMB_VC_CREATE:
            /* arg1=struct smb_vcspec *, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_NETWORK_SMB_VC_ACCESS:
            /* arg1=struct smb_vc *, arg2=mode_t, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_NETWORK_SMB_SHARE_CREATE:
            /* arg1=struct smb_sharespec*, arg2=NULL, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        case KAUTH_REQ_NETWORK_SMB_SHARE_ACCESS:
            /* arg1=struct smb_share *, arg2=mode_t, arg3=NULL */
            result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
            break;
        default:
            SANDBOX_LOG_WARN("unknown subaction (%u) for rule: %s.%s\n", req,
                    SANDBOX_RULE_SCOPE(&rule), SANDBOX_RULE_ACTION(&rule));
            break;
        }
        break;
    default:
        SANDBOX_LOG_WARN("unknown action (%u) for rule: %s\n", action,
                SANDBOX_RULE_SCOPE(&rule));
        break;
    }

    return (result);
} 

int
sandbox_list_evalmachdep(struct sandbox_list *sandbox_list, kauth_cred_t cred, 
        kauth_action_t action, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_rule rule = {{ "machdep", NULL, NULL }};

    SANDBOX_RULE_ACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_machdep_strmap, action);
    
    switch (action) {
    case KAUTH_MACHDEP_CACHEFLUSH:
    case KAUTH_MACHDEP_CPU_UCODE_APPLY:
    case KAUTH_MACHDEP_IOPERM_GET:
    case KAUTH_MACHDEP_IOPERM_SET:
    case KAUTH_MACHDEP_IOPL:
    case KAUTH_MACHDEP_LDT_GET:
    case KAUTH_MACHDEP_LDT_SET:
    case KAUTH_MACHDEP_MTRR_GET:
    case KAUTH_MACHDEP_MTRR_SET:
    case KAUTH_MACHDEP_NVRAM:
    case KAUTH_MACHDEP_UNMANAGEDMEM:
        /* arg0=NULL, arg1=NULL, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_MACHDEP_PXG:
        /* arg0=int start, arg1=NULL, arg2=NULL, arg3=NULL */
        result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "i",
                SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg0));
        break;
    default:
        SANDBOX_LOG_WARN("unknown action (%u) for rule: %s\n", action,
                SANDBOX_RULE_SCOPE(&rule));
        break;
    }

    return (result);
}

int
sandbox_list_evaldevice(struct sandbox_list *sandbox_list, kauth_cred_t cred,
        kauth_action_t action, void *arg0, void *arg1, void *arg2, void *arg3)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_rule rule = {.names = { "device", NULL, NULL }};

    SANDBOX_RULE_ACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_device_strmap, action);

    switch (action) {
    case KAUTH_DEVICE_TTY_OPEN:
    case KAUTH_DEVICE_TTY_PRIVSET:
    case KAUTH_DEVICE_TTY_STI:
    case KAUTH_DEVICE_TTY_VIRTUAL:
        /* arg0=struct tty *, arg1=NULL, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case  KAUTH_DEVICE_RAWIO_SPEC:
        /* arg0=req arg1=struct vnode * */
        SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_device_req_strmap, (enum kauth_device_req)arg0);
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_DEVICE_RAWIO_PASSTHRU:
        /* arg0=req, arg1=dev_t dev, arg2=void *data, arg3=NULL */
        SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_device_req_strmap, (enum kauth_device_req)arg0);
        /* TODO: have fmt include dev; data depends on dev, so that will take
         * more work to include
         */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_DEVICE_BLUETOOTH_SETPRIV:
        /* arg0 = struct hci_unit *, arg1= unsigned long cmd, arg2=struct btreq *, arg3=NULL */
        /* hci_unit is defined in sys/netbt/hci.h */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_DEVICE_RND_ADDDATA:
    case KAUTH_DEVICE_RND_ADDDATA_ESTIMATE:
    case KAUTH_DEVICE_RND_GETPRIV:
    case KAUTH_DEVICE_RND_SETPRIV:
    case KAUTH_DEVICE_GPIO_PINSET:
    case KAUTH_DEVICE_WSCONS_KEYBOARD_BELL:
    case KAUTH_DEVICE_WSCONS_KEYBOARD_KEYREPEAT:
        /* arg0 = NULL, arg1=NULL, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_DEVICE_BLUETOOTH_BCSP:
    case KAUTH_DEVICE_BLUETOOTH_BTUART:
        /* arg0=req, arg1=NULL, arg2=NULL, arg3=NULL */
        SANDBOX_RULE_SUBACTION(&rule) = SANDBOX_ARRAY_GET(sandbox_device_req_strmap, (enum kauth_device_req)arg0);
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_DEVICE_BLUETOOTH_SEND:
        /* arg0=struct hci_unit *, arg1=hci_cmd_hdr_t *, arg2=NULL, arg3=NULL */
        result = SANDBOX_LIST_EVAL_NOARGS(sandbox_list, cred, &rule);
        break;
    case KAUTH_DEVICE_BLUETOOTH_RECV:
        /* arg0=uint8_t type, arg1=uint16_t, arg2=NULL, arg3=NULL */
        result = sandbox_list_eval(sandbox_list, cred, &rule, NULL, "ii",
                SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg0),
                SANDBOX_CAST_PVOID_TO_LUA_INTEGER(arg1));
        break;
    default:
        SANDBOX_LOG_WARN("unknown action (%u) for rule: %s\n", action,
                SANDBOX_RULE_SCOPE(&rule));
        break;
    }

    return (result);
}

int
sandbox_list_evalvnode(struct sandbox_list *sandbox_list, kauth_cred_t cred,
        kauth_action_t action, vnode_t *vp, vnode_t *dvp)
{
    int result = KAUTH_RESULT_DEFER;
    struct sandbox_rule rule = {{ "vnode", NULL, NULL }};
    const char *action_name = NULL;
    size_t i = 0;

    /* NB: dvp is usually NULL, which is why we ignore it */
    if (action & KAUTH_VNODE_EXECUTE)
        goto done;

    action_name = sandbox_vnode_strmap[i];
    while (action_name != NULL) {
        /* TODO: loop through all actions */
        if (action & (1U << i)) {
            SANDBOX_RULE_ACTION(&rule) = action_name;
            break;
        }
        i++;
        action_name = sandbox_vnode_strmap[i];
    }

    if (SANDBOX_RULE_ACTION(&rule) != NULL)
        result = SANDBOX_LIST_EVAL_VNODE(sandbox_list, cred, &rule, vp);

done:
    return (result);
}
