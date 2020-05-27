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

#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/kmem.h>

#include "sandbox_ref.h"
#include "sandbox_log.h"

struct sandbox_ref *
sandbox_ref_create(int value)
{
    struct sandbox_ref *ref = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    ref = kmem_zalloc(sizeof(*ref), KM_SLEEP);
    ref->value = value;

    SANDBOX_LOG_TRACE_EXIT;
    return (ref);
}

void
sandbox_ref_destroy(struct sandbox_ref *ref)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(ref != NULL);

    kmem_free(ref, sizeof(*ref));

    SANDBOX_LOG_TRACE_EXIT;
}

void
sandbox_ref_list_destroy(struct sandbox_ref_list *ref_list)
{
    struct sandbox_ref *ref = NULL;
    struct sandbox_ref *tmp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(ref_list != NULL);

    SIMPLEQ_FOREACH_SAFE(ref, ref_list, ref_next, tmp) {
        sandbox_ref_destroy(ref);
    }

    SANDBOX_LOG_TRACE_EXIT;
}
