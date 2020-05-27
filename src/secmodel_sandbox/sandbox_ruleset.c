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

#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/kmem.h>

#include "sandbox_path.h"
#include "sandbox_ref.h"
#include "sandbox_rule.h"
#include "sandbox_ruleset.h"

#include "sandbox_log.h"

static struct sandbox_rulenode *
sandbox_rulenode_create(int level, const char *name, int type,
        int value, struct sandbox_path_list *paths)
{
    struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    node = kmem_zalloc(sizeof(*node), KM_SLEEP);
    SIMPLEQ_INIT(&node->whitelist);
    SIMPLEQ_INIT(&node->blacklist);
    SIMPLEQ_INIT(&node->funclist);
    TAILQ_INIT(&node->children);

    node->level = level;
    strncpy(node->name, name, SANDBOX_RULE_MAXNAMELEN - 1);  
    node->type = type;

    switch (type) {
    case SANDBOX_RULETYPE_NONE:
        break;
    case SANDBOX_RULETYPE_TRILEAN:
        node->value = value; 
        break;
    case SANDBOX_RULETYPE_WHITELIST:
        sandbox_path_list_concat(&node->whitelist, paths);
        break;
    case SANDBOX_RULETYPE_BLACKLIST:
        sandbox_path_list_concat(&node->blacklist, paths);
        break;
    case SANDBOX_RULETYPE_FUNCTION:
        funcref = sandbox_ref_create(value);
        SIMPLEQ_INSERT_TAIL(&node->funclist, funcref, ref_next);
        break;
    default:
        SANDBOX_LOG_WARN("unknown ruletype %d\n", type);
        break;
    }

    SANDBOX_LOG_TRACE_EXIT;
    return (node);
}

static void
sandbox_rulenode_update(struct sandbox_rulenode *node, int type, int value,
        struct sandbox_path_list *paths)
{
    struct sandbox_ref *funcref = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    switch (type) {
    case SANDBOX_RULETYPE_NONE:
        break;
    case SANDBOX_RULETYPE_TRILEAN:
        node->value = value; 
        break;
    case SANDBOX_RULETYPE_WHITELIST:
        sandbox_path_list_concat(&node->whitelist, paths);
        break;
    case SANDBOX_RULETYPE_BLACKLIST:
        sandbox_path_list_concat(&node->blacklist, paths);
        break;
    case SANDBOX_RULETYPE_FUNCTION:
        funcref = sandbox_ref_create(value);
        SIMPLEQ_INSERT_TAIL(&node->funclist, funcref, ref_next);
        break;
    default:
        SANDBOX_LOG_WARN("unknown ruletype %d\n", type);
        goto done;
    }

    node->type |= type;

done:
    SANDBOX_LOG_TRACE_EXIT;
    return;
}

static void
sandbox_rulenode_destroy(struct sandbox_rulenode *node)
{
    SANDBOX_LOG_TRACE_ENTER;

    struct sandbox_rulenode *child = NULL;
    struct sandbox_rulenode *tmp = NULL;
    
    TAILQ_FOREACH_SAFE(child, &node->children, node_next, tmp)
        sandbox_rulenode_destroy(child);
    
    sandbox_path_list_destroy(&node->whitelist);
    sandbox_path_list_destroy(&node->blacklist);
    sandbox_ref_list_destroy(&node->funclist);
    kmem_free(node, sizeof(*node));

    SANDBOX_LOG_TRACE_EXIT;
}

#define SANDBOX_RULENODE_CREATE_INTERMEDIATE(level, name) \
    sandbox_rulenode_create(level, name, SANDBOX_RULETYPE_NONE, 0, NULL)

static int 
sandbox_rulenode_insert(struct sandbox_rulenode *node, int level,
        const struct sandbox_rule *rule, int type, int value, 
        struct sandbox_path_list *paths)
{
    struct sandbox_rulenode *child = NULL;
    struct sandbox_rulenode *newnode = NULL;
    int error = 0;
    int cmp = 0;
    int rule_size = 0;
    int flag = 0;

    SANDBOX_LOG_TRACE_ENTER;

    if (level > SANDBOX_RULE_MAXNAMES)
        goto done;

    rule_size = sandbox_rule_size(rule); 
    if (level > rule_size)
        goto done;

    SANDBOX_LOG_DEBUG("search level %d for '%s'\n", level, rule->names[level-1]); 
    TAILQ_FOREACH(child, &node->children, node_next) {
        SANDBOX_LOG_DEBUG("\t comparing to '%s'\n", child->name);
        cmp = strcmp(rule->names[level-1], child->name);
        if (cmp == 0) {
            flag = 1;
            if (rule_size == level) {
                /* update */
                SANDBOX_LOG_DEBUG("found a match.  updating node\n");
                sandbox_rulenode_update(child, type, value, paths);
                goto done;
            } else {
                SANDBOX_LOG_DEBUG("found a match. searching node's children\n");
                error = sandbox_rulenode_insert(child, level + 1, rule, type, value, paths);
                goto done;
            }
        } else if (cmp < 0) {
            flag = 1;
            if (rule_size == level) {
                /* terminal node */
                SANDBOX_LOG_DEBUG("inserting terminal node before existing node.\n");
                newnode = sandbox_rulenode_create(level, rule->names[level-1], type, value, paths);
                TAILQ_INSERT_BEFORE(child, newnode, node_next);
                goto done;
            }  else {
                /* intermediate node; inherit parent's values */
                SANDBOX_LOG_DEBUG("inserting intermediate node before existing node.\n");
                newnode = SANDBOX_RULENODE_CREATE_INTERMEDIATE(level, rule->names[level-1]);
                TAILQ_INSERT_BEFORE(child, newnode, node_next);
                error = sandbox_rulenode_insert(newnode, level + 1, rule, type, value, paths);
                goto done;
            }
        }
    }

    if (flag == 0) {
        /* could not find a place in the list; the list was either empty or we
         * are the last element.  In either case; insert at the tail.
         */
        if (rule_size == level) {
            /* terminal node */
            SANDBOX_LOG_DEBUG("could not find a place in the list. inserting terminal node.\n");
            newnode = sandbox_rulenode_create(level, rule->names[level-1], type, value, paths);
            TAILQ_INSERT_TAIL(&node->children, newnode, node_next);
            goto done;
        } else {
            /* intermediate node; inherit parent' values */
            SANDBOX_LOG_DEBUG("could not find a place in the list. inserting intermediate node.\n");
            newnode = SANDBOX_RULENODE_CREATE_INTERMEDIATE(level, rule->names[level-1]);
            TAILQ_INSERT_TAIL(&node->children, newnode, node_next);
            error = sandbox_rulenode_insert(newnode, level + 1, rule, type, value, paths);
        }
    }

done:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

static const struct sandbox_rulenode *
sandbox_rulenode_search(const struct sandbox_rulenode *node,
        const struct sandbox_rule *rule, int level)
{
    const struct sandbox_rulenode *child = NULL;
    const struct sandbox_rulenode *result = NULL;
    int rule_size = 0;
    int cmp = 0;

    SANDBOX_LOG_TRACE_ENTER;
    
    rule_size = sandbox_rule_size(rule); 
    if (level > rule_size)
        goto done;
    
    SANDBOX_LOG_DEBUG("search level %d for '%s'\n", level, rule->names[level-1]);
    TAILQ_FOREACH(child, &node->children, node_next) {
        cmp = strcmp(rule->names[level-1], child->name);
        if (cmp == 0) {
            if (rule_size == level) {
                /* found */
                SANDBOX_LOG_DEBUG("\tfound rule at this level\n");
                result = child;
                goto done;
            } else {
                SANDBOX_LOG_DEBUG("\tfound intermediate rule at this level; searching children\n");
                result = sandbox_rulenode_search(child, rule, level+1);
                if (result == NULL)
                    result = child;
                goto done;
            }
        }
    }

    SANDBOX_LOG_DEBUG("\tdid not find rule\n");

done:
    if ((result != NULL) && (result->type == SANDBOX_RULETYPE_NONE)) {
        SANDBOX_LOG_DEBUG("\tfound node of type NONE\n");
        result = NULL;
    }
    SANDBOX_LOG_TRACE_EXIT;
    return (result);
}

/* ===  API == */

struct sandbox_ruleset *
sandbox_ruleset_create(int value)
{
    struct sandbox_ruleset *set = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    set = kmem_zalloc(sizeof(*set), KM_SLEEP);
    set->root = sandbox_rulenode_create(0, "", SANDBOX_RULETYPE_TRILEAN, value, NULL);

    SANDBOX_LOG_TRACE_EXIT;
    return (set);
}

int
sandbox_ruleset_insert(struct sandbox_ruleset *set,
        const struct sandbox_rule *rule, int type, int value, 
        struct sandbox_path_list *paths)
{
    int error = 0;
    int rule_size = 0;
    int isvnode = 0;

    SANDBOX_LOG_TRACE_ENTER;

    rule_size = sandbox_rule_size(rule); 
    isvnode = sandbox_rule_isvnode(rule);

    if (((type == SANDBOX_RULETYPE_WHITELIST) || (type == SANDBOX_RULETYPE_BLACKLIST)) && !isvnode) {
        SANDBOX_LOG_ERROR("whitelists and blacklists are only for vnode rules, not '%s.%s.%s'\n",
                rule->names[0], rule->names[1], rule->names[2]);
        error = 1;
        goto done;
    }

    if ((rule_size == 0) && (type != SANDBOX_RULETYPE_TRILEAN)) {
        SANDBOX_LOG_ERROR("the default rule must be of type boolean\n");
        error = 1;
        goto done;
    }

    if (rule_size == 0) {
        set->root->type = type;
        set->root->value = value;
        goto done;
    } 

    error = sandbox_rulenode_insert(set->root, 1, rule, type, value, paths);

done:
    SANDBOX_LOG_TRACE_EXIT;
    return (error);

}

/* finds rulenode with longest prefix match */
const struct sandbox_rulenode *
sandbox_ruleset_search(const struct sandbox_ruleset *set,
        const struct sandbox_rule *rule)
{
    const struct sandbox_rulenode *node = NULL;
    int rule_size = 0;

    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_DEBUG("search for rule: %s.%s.%s\n", rule->names[0], rule->names[1], rule->names[2]);

    rule_size = sandbox_rule_size(rule); 
    if (rule_size == 0) {
        node = set->root; 
    } else {
        node = sandbox_rulenode_search(set->root, rule, 1);
        if (node == NULL)
            node = set->root;
    }

    SANDBOX_LOG_TRACE_EXIT;
    return (node);
}

void
sandbox_ruleset_destroy(struct sandbox_ruleset *set)
{
    SANDBOX_LOG_TRACE_ENTER;

    SANDBOX_LOG_DEBUG("destroying ruleset\n");
    sandbox_rulenode_destroy(set->root);
    kmem_free(set, sizeof(*set));

    SANDBOX_LOG_TRACE_EXIT;
}
