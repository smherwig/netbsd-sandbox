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

#ifndef _SANDBOX_RULESET_H_
#define _SANDBOX_RULESET_H_

#include <msys/queue.h>

#include "sandbox_path.h"
#include "sandbox_ref.h"
#include "sandbox_rule.h"

/* struct sandbox_rulelist {   }; */
TAILQ_HEAD(sandbox_rulelist, sandbox_rulenode);

#define SANDBOX_RULETYPE_NONE      (0L)
#define SANDBOX_RULETYPE_TRILEAN   (1L << 0)
#define SANDBOX_RULETYPE_WHITELIST (1L << 1)
#define SANDBOX_RULETYPE_BLACKLIST (1L << 2)
#define SANDBOX_RULETYPE_FUNCTION  (1L << 3)

struct sandbox_rulenode {
    char name[SANDBOX_RULE_MAXNAMELEN];
    int type;
    int level;
    int  value;     /* 1 = allow, 0 = deny */
    struct sandbox_path_list whitelist;
    struct sandbox_path_list blacklist;
    struct sandbox_ref_list     funclist;
    TAILQ_ENTRY(sandbox_rulenode) node_next; /* link for sibling list; */
    struct sandbox_rulelist children;
};

struct sandbox_ruleset {
    /* TODO: include lock */
    struct sandbox_rulenode *root;
};

struct sandbox_ruleset * sandbox_ruleset_create(int allow);

int sandbox_ruleset_insert(struct sandbox_ruleset *set,
        const struct sandbox_rule *rule, int type,
        int value, struct sandbox_path_list *paths);

const struct sandbox_rulenode *
sandbox_ruleset_search(const struct sandbox_ruleset *set,
        const struct sandbox_rule *rule);

void sandbox_ruleset_destroy(struct sandbox_ruleset *set);

#endif /* !_SANDBOX_RULESET_H_ */
