#include <stdlib.h>

#include <msys/queue.h>

#include "sandbox.h"
#include "sandbox_driver.h"

#include "sandbox_log.h"

struct sandbox_driver * 
sandbox_driver_new(void)
{
    struct sandbox_driver *driver = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    driver = calloc(1, sizeof(*driver));
    LIST_INIT(&driver->sandbox_list);

    SANDBOX_LOG_TRACE_EXIT;
    return (driver);
}

struct sandbox * 
sandbox_driver_newsandbox(struct sandbox_driver *driver, 
        const char *script)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    SANDBOX_LOG_TRACE_ENTER;
    
    sandbox = sandbox_create(script, &error);
    LIST_INSERT_HEAD(&driver->sandbox_list, sandbox, sandbox_next);
    driver->nsandbox++;

    SANDBOX_LOG_TRACE_EXIT;
    return (sandbox);
}

void
sandbox_driver_closesandbox(struct sandbox_driver *driver,
        struct sandbox *sandbox)
{
    int found = 0;
    struct sandbox *iter = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    LIST_FOREACH(iter, &driver->sandbox_list, sandbox_next) {
        if (iter == sandbox) {
            found = 1;
            break;
        }
    }

    if (found) {
        LIST_REMOVE(sandbox, sandbox_next);
        sandbox_destroy(sandbox);
        driver->nsandbox--;
    } else {
        SANDBOX_LOG_WARN("sandbox not found in driver's list\n");
    }

    SANDBOX_LOG_TRACE_EXIT;
}

void
sandbox_driver_close(struct sandbox_driver *driver)
{
    struct sandbox *iter = NULL;
    struct sandbox *tmp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    LIST_FOREACH_SAFE(iter, &driver->sandbox_list, sandbox_next, tmp) {
        LIST_REMOVE(iter, sandbox_next);
        sandbox_destroy(iter);
        driver->nsandbox--;
    }

    free(driver);

    SANDBOX_LOG_TRACE_EXIT;
}
