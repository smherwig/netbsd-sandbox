#ifndef _SANDBOX_SPEC_H_
#define _SANDBOX_SPEC_H_

#include <sys/types.h>
#include <sys/ioctl.h>

#define SANDBOX_VERSION     1

/* 
 * sandbox_spec flags
 */
#define SANDBOX_ON_DENY_ABORT  (1 << 0)

struct sandbox_spec {
    char    *script;
    size_t  script_len;
    int     flags;
};

#define SANDBOX_IOC_VERSION  _IOR('S', 0, int)
#define SANDBOX_IOC_SETSPEC  _IOW('S', 1, struct sandbox_spec)
#define SANDBOX_IOC_NLISTS   _IOR('S', 2, int)

#endif /* !_SANDBOX_SPEC_H_ */
