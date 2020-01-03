#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#define SANDBOX_DEVICE "/dev/sandbox"

#define SANDBOX_ON_DENY_KILL  (1 << 0)

struct sandbox_spec {
    char *script;
    size_t script_len;
    int flags;
};
#define SANDBOX_IOC_VERSION  _IOR('S', 0, int)
#define SANDBOX_IOC_SETSPEC  _IOW('S', 1, struct sandbox_spec)
#define SANDBOX_IOC_NLISTS   _IOR('S', 2, int)

int sandbox(const char *script, int flags);
int sandbox_from_file(const char *path, int flags);

int sandbox_securechroot(const char *dirname);
int sanddbox_pledge(const char *promises, const char *paths[]);

#endif /* !_SANDBOX_H_ */
