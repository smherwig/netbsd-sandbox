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

#ifndef _SANDBOX_RULE_H_
#define _SANDBOX_RULE_H_

#define SANDBOX_RULE_MAXNAMELEN 32      /* includes null */
#define SANDBOX_RULE_MAXNAMES 3

struct sandbox_rule {
    const char *names[SANDBOX_RULE_MAXNAMES];
};

#define SANDBOX_RULE_SCOPE(rule)       ((rule)->names[0])
#define SANDBOX_RULE_ACTION(rule)      ((rule)->names[1])
#define SANDBOX_RULE_SUBACTION(rule)   ((rule)->names[2])

#define SANDBOX_RULE_MAKE(rule, scope, action, subaction) \
    do { \
        (rule)->names[0] = scope; \
        (rule)->names[1] = action; \
        (rule)->names[2] = subaction; \
    } while (0)

int sandbox_rule_isvnode(const struct sandbox_rule *rule);
int sandbox_rule_size(const struct sandbox_rule *rule);
int sandbox_rule_initfromstring(const char *s, struct sandbox_rule *rule);
void sandbox_rule_freenames(struct sandbox_rule *rule);

#endif /* !_SANDBOX_RULE_H_*/
