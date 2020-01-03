#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/conf.h>

#include <sys/kmem.h>

#include "sandbox.h"
#include "sandbox_device.h"
#include "sandbox_spec.h"

#include "sandbox_log.h"

static dev_type_open(sandbox_device_open);
static dev_type_close(sandbox_device_close);
static dev_type_ioctl(sandbox_device_ioctl);

static const struct cdevsw sandbox_cdevsw = {
    .d_open     = sandbox_device_open,
    .d_close    = sandbox_device_close,
    .d_read     = noread,
    .d_write    = nowrite,
    .d_ioctl    = sandbox_device_ioctl,
    .d_stop     = nostop,
    .d_tty      = notty,
    .d_poll     = nopoll,
    .d_mmap     = nommap,
    .d_kqfilter = nokqfilter,
    .d_discard  = nodiscard,
    .d_flag     = D_OTHER
};

static int
sandbox_device_setspec(struct sandbox_spec *spec)
{
    int error = 0;
    char *script = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(spec != NULL);

    script = kmem_zalloc(spec->script_len, KM_SLEEP);
    error = copyinstr(spec->script, script, spec->script_len, NULL);
    if (error != 0) {
        SANDBOX_LOG_ERROR("copyinstr() failed\n");
        goto fail;
    }

    error = sandbox_attach(script, spec->flags);

fail:
    kmem_free(script, spec->script_len);
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

static int
sandbox_device_open(dev_t dev, int flag, int mode, struct lwp *l)
{
    SANDBOX_LOG_TRACE_ENTER;
    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

static int
sandbox_device_close(dev_t dev, int flag, int mode, struct lwp *l)
{
    SANDBOX_LOG_TRACE_ENTER;
    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

static int
sandbox_device_ioctl(dev_t dev, u_long cmd, void *data, int flag, struct lwp *l)
{
    int error = 0;
    struct sandbox_spec *spec = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    switch (cmd) {
    case SANDBOX_IOC_VERSION:
        *((int *)data) = SANDBOX_VERSION;
        break;
    case SANDBOX_IOC_SETSPEC:
        spec = (struct sandbox_spec *)data;
        error = sandbox_device_setspec(spec);
        break;
    case SANDBOX_IOC_NLISTS:
        *((int *)data) = sandbox_nlists;
        break;
    default:
        error = ENOTTY;
    }

    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

int
sandbox_device_init(void)
{
    int error = 0;
    devmajor_t cmajor = NODEVMAJOR, bmajor = NODEVMAJOR;

    SANDBOX_LOG_TRACE_ENTER;

    error = devsw_attach("sandbox", NULL, &bmajor, &sandbox_cdevsw, &cmajor);
    if (error != 0)
        SANDBOX_LOG_ERROR("devsw_attach('sandbox' failed: error=%d\n", error);

    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

void
sandbox_device_fini(void)
{
    int error = 0;

    SANDBOX_LOG_TRACE_ENTER;

    error = devsw_detach(NULL, &sandbox_cdevsw);
    if (error != 0)
        SANDBOX_LOG_ERROR("devsw_detach() failed: error=%d\n", error);

    SANDBOX_LOG_TRACE_EXIT;
}
