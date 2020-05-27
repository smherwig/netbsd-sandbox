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

#include <msys/cdefs.h>
#include <msys/systm.h>
#include <msys/kmem.h>

#include "sandbox_rule.h"

#include "sandbox_log.h"

int
sandbox_rule_size(const struct sandbox_rule *rule)
{
    if (rule->names[0] == NULL) return (0);
    if (rule->names[1] == NULL) return (1);
    if (rule->names[2] == NULL) return (2);
    return (3);
}

/* TODO: sandbox_rule_isequal() */
/* TODO: macros for levels: #define SANDBOX_RULELEVEL_SCOPE 1 */

int
sandbox_rule_isvnode(const struct sandbox_rule *rule)
{
    int result = 0;
    const char *scope = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    scope = SANDBOX_RULE_SCOPE(rule);

    if (scope == NULL)
        goto done;

    if (strcmp(scope, "vnode") == 0)
        result = 1;

done:
    SANDBOX_LOG_TRACE_EXIT;
    return (result);
}

void
sandbox_rule_freenames(struct sandbox_rule *rule)
{
    int i = 0;

    for (i = 0; i < SANDBOX_RULE_MAXNAMES; i++) {
        if (rule->names[i] != NULL) {
            kmem_free(__UNCONST(rule->names[i]), SANDBOX_RULE_MAXNAMELEN);
            rule->names[i] = NULL;
        }
    }
}

int 
sandbox_rule_initfromstring(const char *s, struct sandbox_rule *rule)
{
    int error = 0;
    int i = 0;
    const char *a = NULL;
    const char *b = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    a = s;
    b = s;

    while (*b) {
        if (*b == '.') {
            if (i >= SANDBOX_RULE_MAXNAMES) {
                SANDBOX_LOG_ERROR("rule string '%s' contains too many names\n", s);
                goto fail;
            }
            if ((b - a) == 0) {
                SANDBOX_LOG_ERROR("rule string '%s' contains an empty name\n", s);
                goto fail;
            }
            rule->names[i] = kmem_zalloc(SANDBOX_RULE_MAXNAMELEN, KM_SLEEP);
            /* TODO: error checking */
            memcpy(__UNCONST(rule->names[i]), a, b - a);
            a = b + 1;
            i++;
        }
        b++;
    }

    if (i >= SANDBOX_RULE_MAXNAMES) {
        SANDBOX_LOG_ERROR("rule string '%s' contains too many names\n", s);
        goto fail;
    }

    if ((b - a) == 0) {
        SANDBOX_LOG_ERROR("rule string '%s' contains an empty name\n", s);
        goto fail;
    }

    rule->names[i] = kmem_zalloc(SANDBOX_RULE_MAXNAMELEN, KM_SLEEP);
    /* TODO: error checking */
    memcpy(__UNCONST(rule->names[i]), a, b - a);
    goto succeed;

fail:
    error = 1;
    sandbox_rule_freenames(rule);

succeed:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}
