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
