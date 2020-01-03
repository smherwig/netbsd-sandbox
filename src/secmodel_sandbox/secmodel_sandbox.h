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
