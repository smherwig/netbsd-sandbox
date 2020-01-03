#include <sys/param.h>  /* MAXPATHLEN */
#include <sys/ioctl.h>  /* ioctl */
#include <sys/stat.h>   /* stat */

#include <fcntl.h>      /* open */
#include <stdarg.h>     /* va_start, va_end, va_end */
#include <stdbool.h>    /* false, true */
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>     /* calloc, realpath, free */
#include <string.h>     /* strdup, strlen, strtok_r */
#include <unistd.h>     /* chroot, close, read */

#include "sandbox.h"

struct sandbox_pledge_req {
    const char *promise;
    const char *rules;
};

/* FORWARD DECLARATIONS */
static char * sandbox_sprintf(const char *fmt, ...);
static int sandbox_readspec(const char *path, struct sandbox_spec *spec);
static int sandbox_setspec(struct sandbox_spec *spec);

/* TODO: 
 *
 * 1. list all the kauth requests that do not have a pledge counterpart or
 *    which are disallowed as soon as pledge() is called (that is, the syscalls
 *    are not in pledge_syscalls[]).
 *
 * 2. list all of the pledge categories (and OpenBSD syscalls) that do not have
 *    a kauth counterpart.
 *
 * Note that with (1) and (2), there might be fuzzy matches, especially with
 * ioctls and packet filters.
 *
 *
 * 1.
 *
 *  - system.accounting
 *      acct
 *
 *  - system.chroot[.*]
 *      chroot
 *      fchroot
 *
 *  - system.cpu[.*]
 *
 *  - system.debug[.*]
 *
 *  - system.filehandle
 *      fhopen
 *      fhstat
 *
 *  - system.mount[.*]
 *      mount
 *      umount
 *  
 *  - system.pset[.*]
 *      
 *  - system.reboot
 *      reboot
 *
 *  - system.setidcore
 *
 *  - system.time[.*]
 *      XXX: partial overlap with pledge; look into further
 *
 *  - system.module
 *
 *  - system.fs_reservedspace
 *
 *  - system.fs_quota.[*]
 *
 *  - system.semaphore
 *
 *  - system.sysvipc[.*]
 *
 *  - system.mqueue
 *
 *  - system.veriexec[.*]
 *
 *  - system.map_va_zero
 *
 *  - system.lfs[.*]
 *
 *  - system.fs_extattr
 *
 *  - sytem.fs_snapshot
 *
 * - process.cansee[.*]
 *      might factor into sysctls
 *
 * - process.corename[.*]
 *      might factor into sysctls
 *
 * - proces.kevent_filter
 *
 * - process.ktrace
 *
 * - process.ktrace.persistent
 *
 * - process.procfs[.*]
 *      might factor into systcls
 *
 * - process.ptrace
 *      ptrace
 *
 * - processs.scheduler_getaffinity
 *      sched_getaffinity_np
 *
 * - processs.scheduler_setaffinity
 *      sched_setaffinity_np
 *
 * - processs.scheduler_getparam
 *      sched_getparam
 *
 * - processs.scheduler_setparam
 *      sched_setparam
 *
 * - process.stopflag
 *      might factor into sysctls
 *
 * - network.altq[.*]
 *      might factor into ioctls
 *
 * - network.firewall[.*]
 *      might be similar to pledge's pf promise
 *
 * - network.interface[.*]
 *      might factor into ioctls
 *
 * - network.forwsrcrt 
 *      might factor into ioctls
 *
 * - network.nfs[.*]
 *
 * - network.route
 *      might be similar to pledge's route promise
 *
 * - network.socket.rawsock
 *
 * - network.socket.cansee
 *      might factor into sysctls
 *
 * - network.socetk.drop
 *      
 * - network.socket.setpriv
 *      might factor into setsockopt
 *
 * - network.interface_ppp[.*]  
 *      might factor into ioctls
 *
 * - network.interface_slip[.*]  
 *      might factor into ioctls
 *
 * - network.interface_strip[.*]  
 *      might factor into ioctls
 *
 * - network.interface_tun[.*]  
 *      might factor into ioctls
 *
 * - network.interface_bridge[.*]  
 *      might factor into ioctls
 *
 * - network.interface_pvc[.*]  
 *      might factor into ioctls
 *
 * - network.ipv6[.*]  
 *      might factor into ioctls or setsockopts, or the mcast promise
 *
 * - network.smb[.*]
 *
 * - machdep[.*]
 *      might factor into ioctls
 *
 * - device[.*]
 *      might intersect audio, bpf, diskalable, prot_Exec,
 *      tamp, viuminof, or vmm promises.
 *
 * 2.
 */
static struct sandbox_pledge_req sandbox_pledge_reqs[] = {
    /*
     *
     */
    {"audio",       NULL},

    /*
     *
     */
    {"bpf",         NULL},

    /*
     *
     */
    {"chown",       "sandbox.allow('vnode.change_ownership')"},

    /*
     *
     *
     */
    {"cpath",       NULL},

    /*
     *
     */
    {"disklabel",   NULL},

    /* socket:
     *  network.socket.open
     *
     * connect:
     *  does not explicitly trigger a kauth request
     *
     * bind:
     *  network.bind.port
     *  network.bind.privport
     *
     * getsockname:
     *  does not explicitly trigger a kauth request
     */
    {"dns",         
        "sandbox.on('network.socket.open', function() end)\n"
        "sandbox.on('network.bind', function() end)\n"
    },

    /* mkfifo:
     *  Does not trigger a kauth request
     *
     * mknod:
     *  system.mknod 
     */
    {"dpath", "sandbox.allow('system.mknod')"},

    {"drm",         NULL},

    /* execve:
     *  Does not trigger a kauth request
     */
    {"exec",        NULL},

    /* utimes()
     *  vnode.write_times
     *
     * futimes()
     *  ?
     *
     * utimensat()
     *  ?
     *
     * futimens()
     *  ?
     *
     * chmod()
     *  vnode.write_security
     *
     * fchmod()
     *  ?
     *
     * fchmodat()
     *  ?
     *
     * chflags()
     *  vnode.write_flags 
     *  vnode.write_sysflags?
     *
     * chflagsat()
     *  ?
     * fchflags()
     *  ?
     */
    {"fattr",
        "system.allow('vnode.write_times')\n"
        "system.allow('vnode.write_security')"
    },

    /* flock:
     *  Does not trigger a kauth request
     */
    {"flock",       NULL},

    /*
     *
     */
    {"getpw",       NULL},

    /* setrlimit:
     *  process.rlimit.set
     *
     * getpriority:
     *  does not trigger a kauth request
     *
     * setpriority:
     *  process.nice
     *
     * setuid:
     *  process.setid
     *
     * seteuid:
     *  process.setid
     *
     * setreuid:
     *  process.setid
     *
     * setgid:
     *  process.setid
     *
     * setegid:
     *  process.setid
     *
     * setregid:
     *  process.setid
     *
     * setresgid:
     *  ?
     *
     * setgroups:
     *  process.setid
     *
     * setlogin:
     *  process.setid
     */
    {"id",
        "sandbox.allow('process.rlimit.set')\n"
        "sandbox.allow('process.setid')"
    },

    /* socket:
     *  network.socke.open
     *
     * connect:
     *  does not explicitly tirgger a kauth request
     *
     * bind:
     *  network.bind.port
     *  network.bind.privport 
     *
     * getsockname:
     *  does not trigger a kauth request
     *
     * listen:
     *  does not explicitly trigger a kauth request
     *
     * accept4:
     *  ?
     *
     * accept:
     *  does not trigger a kauth request
     *
     * getpeername:
     *  does not trigger a kauth request
     */
    {"inet",
        "sandbox.on('network.socket.open'), function() end)\n"
        "sandbox.on('network.bind', function() end)"
    },

    /* On OpenBSD, enables certain ioctls.
     */
    {"mcast",       NULL},

    /*
     *
     */
    {"pf",          NULL},

    /* fork:
     *  process.fork
     *
     * vfork:
     *  process.fork
     *
     * setpgid:
     *  does not trigger a kauth request
     *
     * setsid:
     *  does not trigger a kauth request
     *
     * setrlimit:
     *  process.rlimit.set
     *
     * getpriority:
     *  does not trigger a kauth request
     *
     * setpriority:
     *  process.nice 
     *
     */
    {"proc",
        "sandbox.allow('process.fork')\n"
        "sandbox.allow('process.rlimit.set')\n"
        "sandbox.allow('process.nice')"
    },

    /* Not emulatable.  The prot_exec promise allows
     * mmap and mprotect to use the PROT_EXEC flag (malloc an executable page)
     */
    {"prot_exec",   NULL},

    /* This allows certain sysctls
     *
     */
    {"ps",          NULL},

    /*
     *
     */
    {"recvfd",      NULL},

    /* This allows cetain sysctls and ioctls
     *
     */
    {"route",       NULL},

    /* chdir:
     *  might trigger:
     *      vnode.execute
     *
     * openat:
     *  ?
     *
     * fstatat:
     *  ?
     *
     * faccessat:
     *  ?
     *
     * readlinkat:
     *  ?
     *
     * lstat:
     *  ?
     *
     * rename:
     *  ?
     */
    {"rpath",       NULL},

    /*
     *
     */
    {"sendfd",      NULL},

    /* adjtime:
     *  system.time.adjtime
     *  system.time.system
     *
     * settimeofday:
     */
    {"settime",     
        "sandbox.allow('system.time.adjtime')\n"
        "sandbox.allow('system.time.system')"
    },

    /* getuid:
     *  does not trigger a kauth request
     *
     * geteuid:
     *  does not trigger a kauth request
     *
     * getresuid:
     *  ?
     *
     * getgid:
     *  ?
     *
     * getegid:
     *  ?
     *
     * getresgid:
     *  ?
     * getgroups:
     *  ?
     *
     * getlogin59:
     *  does not trigger a kauth request
     *
     * getlogin_r:
     *  ?
     *
     * getpgrp:
     *  ?
     *
     * getpgid:
     *  ?
     *
     * getppid:
     *  does not trigger a kauth request
     *
     * getsid:
     *  does not trigger a kauth request
     *
     * getthrid:
     *  ?
     * getrlimit:
     *  does not trigger a kauth request
     *
     * gettimeofday:
     *  ?
     *
     * getdtablecount:
     *  ?
     *
     * getrusage:
     *  ?
     *
     * issetugid:
     *  ?
     *
     * clock_getres:
     *  does not trigger a kauth request
     *
     * clock_gettime:
     *  does not trigger a kauth request
     *
     * getpid:
     *  does not trigger a kauth request
     *
     * sysctl:
     *  XXX: messy
     *
     * getentropy:
     *  ?
     *
     * madvise:
     *  ?
     * minherit:
     *  ?
     *
     * mmap:
     *  ?
     * mprotect:
     *  ?
     * mquery:
     *  ?
     * munmap:
     *  ?
     * msync:
     *  ?
     * break:
     *  ?
     * umask:
     *  does not trigger a kauth request
     *
     * read
     *  ?
     * readv
     *  ?
     * pread
     *  ?
     * preadv
     *  ?
     * write
     *  ?
     *
     * writev
     *  ?
     * pwrite
     *  ?
     * pwritev
     *  ?
     *
     * recvmsg
     *  ?
     * recvfrom
     *  ?
     *
     * ftruncate
     *  ?
     *
     * lseek
     *  ?
     *
     * fpathconf
     *  ?
     *
     * sendto
     *  ?
     *
     * sendmsg
     *  ?
     *
     * nanosleep:
     *  ?
     *
     * sigaltstack
     *  ?
     *
     * sigprocmask
     *  ?
     * sigsuspend
     *  ?
     * sigaction
     *  ?
     * sigreturn
     *  ?
     * sigpending
     *  ?
     *
     * getitimer
     *  ?
     *
     * setitimer
     *  ?
     *
     * poll
     *  ?
     * ppoll
     *  ?
     *
     * kevent
     *  ?
     * kqueue
     *  ?
     *
     * select
     *  /
     *
     * pselect
     *  ?
     *
     * fstat
     *  ?
     * fsync
     *  ?
     * 
     * setsockopt
     *  ?
     * getsockopt
     *  ?
     *
     * fcntl
     *  ?
     *
     * close
     *  does not trigger a kauth request
     *
     * dup
     *  does not trigger a kauth request
     *
     * dup2
     *  does not trigger a kauth request
     *
     * dup3
     *  does not trigger a kauth request
     *
     * closefrom
     *  ?
     *
     * shutdown
     *  does not trigger a kauth request
     *
     * fchdir
     *  might trigger vnode.execute
     *
     * pipe
     *  ?
     *
     * pipe2
     *  ?
     *
     * socketpair
     *  network.socket.open (twice)
     *
     * wait4
     *  ?
     *
     * kill
     *  process.signal
     *
     * ioctl
     *  ?
     *
     * open
     *  ?
     *
     * stat
     *  does not explicitly trigger a kauth request.
     *  Howeover, all intermediate directories must be searchable, which
     *  triggers multiple vnode.execute requests.
     *
     * access
     *  May generate any of:
     *      vnode.read_data, vnode.write_data, vnode.execute
     *
     * readlink
     *  vnode.read_data
     *
     * adjtime
     *  system.time.adjtime
     *
     * __tfork
     * sched_yield
     * __thrsleep
     * __thrwakeup
     * __threxit
     * __thrsigdivert
     *
     *
     */
    {"stdio",       NULL},

    /*
     *
     */
    {"tape",        NULL},

    /* lstat:
     *  ?
     *
     * unlink:
     *  may trigger:
     *      vnode.execute
     *      vnode.write_data
     */
    {"tmppath",     NULL},

    /* revoke:
     *  vnode.revoke
     */
    {"tty", "sandbox.allow('vnode.revoke')"},

    /* socket:
     *
     * connect:
     *
     * bind:
     *
     * getsockname:
     *
     * listen:
     *
     * accept4:
     *
     * accept:
     *
     * getpeername:
     *
     */
    {"unix",
        "sandbox.on('network.socket.open', function() end)\n"
        "sandbox.on('network.bind', function() end)"
    },
    
    /* swapctl:
     *  system.swapctl 
     *
     * enables some sysctls.
     *
     * On OpenBSD, to scall swapctl, the process must be root and must have
     * pledged swapctl.
     */
    {"vminfo",
        "sandbox.allow('system.swapctl')"
    },

    /* On OpenBSD, eanbles some ioctls
     *
     */
    {"vmm",         NULL},

    /* openat:
     *  ?
     *
     * fstatat:
     *  ?
     *
     * faccesssat:
     *  ?
     *
     * readlinkat:
     *  ?
     *
     * lstat:
     *  ?
     *
     * truncate:
     *  ?
     */
    {"wpath",       NULL},

    /* sentinel */
    {NULL, NULL} 
};

/* TODO: rawio_spec */
static char *sandbox_securechroot_script_template =
    "sandbox.default('defer')\n" \
    "sandbox.deny('system.chroot')\n" \
    "sandbox.deny('system.debug')\n" \
    "sandbox.deny('system.fs_reservedspace')\n" \
    "sandbox.deny('system.mknod')\n" \
    "sandbox.deny('system.module')\n" \
    "sandbox.deny('system.pset')\n" \
    "sandbox.deny('system.reboot')\n" \
    "sandbox.deny('system.setidcore')\n" \
    "sandbox.deny('system.swapctl')\n" \
    "sandbox.deny('system.cpu.setstate')\n" \
    "sandbox.deny('system.mount.new')\n" \
    "sandbox.deny('system.mount.unmount')\n" \
    "sandbox.deny('system.mount.update')\n" \
    "sandbox.deny('system.mount.umap')\n" \
    "sandbox.deny('system.mount.device')\n" \
    "sandbox.deny('system.sysctl')\n" \
    "sandbox.on('process.ptrace', function(rule, cred, proc, req)\n" \
    "  if proc.rootdir != '%s' then return false else return nil end\n" \
    "end)\n" \
    "sandbox.on('process.ktrace', function(rule, cred, proc)\n" \
    "  if proc.rootdir != '%s' then return false else return nil end\n" \
    "end)\n" \
    "sandbox.on('process.procfs', function(rule, cred, proc)\n" \
    "   if proc.rootdir != '%s' then return false else return nil end\n" \
    "end)\n" \
    "sandbox.on('process.signal', function(rule, cred, proc, signo)\n" \
    "   if proc.rootdir != '%s' then return false else return nil end\n" 
    "end)\n" \
    "sandbox.on('process.cansee', function(rule, cred, proc)\n" \
    "   if proc.rootdir != '%s' then return false else return nil end\n" \
    "end)\n" \
    "sandbox.on('process.nice', function(rule, cred, proc, nice)\n" \
    "  if nice < proc.nice then return false else return nil end\n" \
    "end)\n" \
    "sandbox.deny('process.scheduler.setaffinity')\n" \
    "sandbox.deny('process.scheduler.setparam')\n" \
    "sandbox.deny('process.corename.set')\n" \
    "sandbox.deny('process.rlimit.set')\n" \
    "sandbox.deny('network.firewall')\n" \
    "sandbox.deny('network.altq')\n" \
    "sandbox.deny('network.forwsrcrt')\n" \
    "sandbox.deny('network.interface_ppp')\n" \
    "sandbox.deny('network.interface_slip')\n" \
    "sandbox.deny('network.interface_strip')\n" \
    "sandbox.deny('network.interface_tun')\n" \
    "sandbox.deny('network.route')\n" \
    "sandbox.deny('network.interface.set')\n" \
    "sandbox.deny('network.interface.setpriv')\n" \
    "sandbox.deny('machdep.cacheflush')\n" \
    "sandbox.deny('machdep.ioperm_set')\n" \
    "sandbox.deny('machdep.iopl')\n" \
    "sandbox.deny('machdep.ldt_set')\n" \
    "sandbox.deny('machdep.mtrr_set')\n" \
    "sandbox.deny('machdep.nvram')\n" \
    "sandbox.deny('machdep.unmanagedmem')\n" \
    "sandbox.deny('device.rnd_adddata')\n" \
    "sandbox.deny('device.rnd_setpriv')\n" \
    "sandbox.deny('device.bluetooth_setpriv')\n" \
    "sandbox.deny('device.rawio_passthru')\n" \
    "sandbox.deny('device.bluetooth_bcsp.add')\n";

static char *
sandbox_sprintf(const char *fmt, ...)
{
    va_list args;
    va_list args2;
    int needed = 0;
    int written = 0;
    char *out = NULL;

    va_start(args, fmt);
    va_copy(args2, args);
    needed = snprintf(NULL, 0, fmt, args);
    va_end(args);

    out = calloc(1, needed + 1);
    if (out == NULL)
        goto done;

    written = vsnprintf(out, needed + 1, fmt, args2);
    va_end(args2);

    if (written != needed) {
        free(out);
        out = NULL;
    }

done:
    return (out);
}

/* on success, returns 0
 * on failure, returns -1, errno has error value
 */
static int
sandbox_readspec(const char *path, struct sandbox_spec *spec)
{
    int error = 0;
    int fd = -1;
    struct stat sb;
    char *s = NULL;
    size_t nbyte = 0;
    ssize_t nread = 0;

    fd = open(path, O_RDONLY);
    if (fd == -1)
        goto fail;

    error = fstat(fd, &sb);
    if (error == -1)
        goto fail;

    nbyte = sb.st_size;
    s = calloc(1, nbyte + 1);
    if (s == NULL)
        goto fail;

    nread = read(fd, s, nbyte);
    if (nread < 0)
        goto fail;

    if (((size_t)nread) != nbyte)
        /* TODO: better error handling */
        goto fail;

    spec->script = s;
    spec->script_len = nbyte + 1;
    goto succeed;

fail:
    error = -1;
    if (s != NULL)
        free(s);
succeed:
    if (fd != -1)
        (void)close(fd);
    return (error);
}

/* return 0 on suceess
 * return -1 on error; errno has error value
 */
static int
sandbox_setspec(struct sandbox_spec *spec)
{
    int error = 0;
    int fd = -1;

    fd = open("/dev/sandbox", O_RDWR);
    if (fd == - 1)
        goto fail;

    error = ioctl(fd, SANDBOX_IOC_SETSPEC, spec);
    if (error == -1)
        goto fail;

    goto succeed;

fail:
    error = -1;
succeed:
    if (fd != -1)
        (void)close(fd);
    return (error);
}

/*
 * Public API
 */

/* return 0 on suceess
 * return -1 on error; errno has error value
 */
int
sandbox(const char *script, int flags)
{
    int error = 0;
    struct sandbox_spec spec = { .script = NULL, .script_len = 0 };

    spec.script = (char*)script;
    spec.script_len = strlen(script) + 1;
    spec.flags = flags;

    error = sandbox_setspec(&spec);

    return (error);
}

/* return 0 on suceess
 * return -1 on error; errno has error value
 */
int
sandbox_from_file(const char *path, int flags)
{
    int error = 0;
    struct sandbox_spec spec = { .script = NULL, .script_len = 0 };

    spec.flags = flags;
    error = sandbox_readspec(path, &spec);
    if (error)
        goto fail;

    error = sandbox_setspec(&spec);

fail:
    if (spec.script != NULL)
        free(spec.script);
    return (error);
}

int
sandbox_securechroot(const char *dirpath)
{
    int error = 0;
    char *script = NULL;
    char canonpath[MAXPATHLEN] = { 0 };

    if (realpath(dirpath, canonpath) == NULL) {
        error = -1;
        goto fail;
    }

    /* TODO: sanitize the string:
     *  -escaping bad characters, like a single quote
     */
    script = sandbox_sprintf(sandbox_securechroot_script_template,
            canonpath, canonpath, canonpath, canonpath, canonpath);
    if (script == NULL) {
        error = -1;
        goto fail;
    }

    error = chroot(canonpath);
    if (error == -1)
        goto fail;

    error = sandbox(script, 0);

fail:
    if (script != NULL)
        free(script);
    return (error);
}

/* paths is unused at the moment, as per OpenBSD's pledge(2) */
int
sandbox_pledge(const char *promises, const char *paths[])
{
    int error = 0;
    bool found = false;
    struct sandbox_pledge_req *req = NULL;
    char *promises2 = NULL;
    char *p = NULL;
    char *last = NULL;

    promises2 = strdup(promises);
    if (promises2 == NULL) {
        error = -1;
        goto fail;
    }

    p = strtok_r(promises2, " ", &last);
    while (p != NULL) {
        found = false;
        for (req = sandbox_pledge_reqs; req->promise != NULL; req++) {
            if (strcmp(p, req->promise) == 0) {
                found = true;;
                break;
            }
        } 

        if (found == false)
            goto fail;

        /* add rules */

        p = strtok_r(NULL, " ", &last);
    }

fail:
    if (promises2 != NULL)
        free(promises2);
    return (error);
}
