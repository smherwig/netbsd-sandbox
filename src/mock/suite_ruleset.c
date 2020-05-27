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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <msys/kmem.h>
#include <msys/kauth.h>

#include <CUnit/CUnit.h>
#include "test_util.h"

#include "sandbox_log.h"
#include "sandbox_ruleset.h"

static void
test_insert_default_bool(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL} };

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_default_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL} };
    int refvalue = 20;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION, refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);
    CU_ASSERT_TRUE(SIMPLEQ_EMPTY(&node->funclist));
    
    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_default_whitelist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = {.names = {NULL, NULL, NULL}};
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_WHITELIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);
    CU_ASSERT_TRUE(SIMPLEQ_EMPTY(&node->whitelist));

    sandbox_ruleset_destroy(set);

    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_insert_default_blacklist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = {.names = {NULL, NULL, NULL}};
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_BLACKLIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);
    CU_ASSERT_TRUE(SIMPLEQ_EMPTY(&node->blacklist));

    sandbox_ruleset_destroy(set);

    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_insert_scope_bool(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL} };

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN, 
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "network");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_scope_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL} };
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION, refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "network");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);
    
    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_vnode_scope_whitelist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"vnode", NULL, NULL} };
    struct sandbox_path_list *pathlist = NULL;
    struct sandbox_path_list *pathlist_save = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    pathlist_save = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_WHITELIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "vnode");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist_save, &node->whitelist));

    sandbox_ruleset_destroy(set);

    kmem_free(pathlist, sizeof(*pathlist));
    sandbox_path_list_destroy(pathlist_save);
    kmem_free(pathlist_save, sizeof(*pathlist_save));

    TEST_END;
}

static void
test_insert_vnode_scope_blacklist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"vnode", NULL, NULL} };
    struct sandbox_path_list *pathlist = NULL;
    struct sandbox_path_list *pathlist_save = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    pathlist_save = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_BLACKLIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "vnode");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist_save, &node->blacklist));

    sandbox_ruleset_destroy(set);

    kmem_free(pathlist, sizeof(*pathlist));
    sandbox_path_list_destroy(pathlist_save);
    kmem_free(pathlist_save, sizeof(*pathlist_save));

    TEST_END;
}

static void
test_insert_non_vnode_scope_whitelist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL}};
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_WHITELIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_insert_non_vnode_scope_blacklist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL}};
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_BLACKLIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_insert_scope_bool_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL} };
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION,
            refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "network");
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_FUNCTION);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);
    
    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_vnode_scope_bool_func_whitelist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"vnode", NULL, NULL} };
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;
    struct sandbox_path_list *pathlist = NULL;
    struct sandbox_path_list *pathlist_save = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    pathlist_save = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION, refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_WHITELIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "vnode");
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_FUNCTION);
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist_save, &node->whitelist));

    sandbox_ruleset_destroy(set);

    kmem_free(pathlist, sizeof(*pathlist));
    sandbox_path_list_destroy(pathlist_save);
    kmem_free(pathlist_save, sizeof(*pathlist_save));

    TEST_END;
}

static void
test_insert_action_bool(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL} };

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN, 
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_action_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL} };
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION,
            refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);
    
    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_vnode_action_whitelist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"vnode", "read_data", NULL} };
    struct sandbox_path_list *pathlist = NULL;
    struct sandbox_path_list *pathlist_save = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    pathlist_save = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_WHITELIST,
            0, pathlist); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "read_data");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist_save, &node->whitelist));

    SANDBOX_RULE_MAKE(&rule, "vnode", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    kmem_free(pathlist, sizeof(*pathlist));
    sandbox_path_list_destroy(pathlist_save);
    kmem_free(pathlist_save, sizeof(*pathlist_save));

    TEST_END;
}

static void
test_insert_vnode_action_blacklist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"vnode", "read_data", NULL} };
    struct sandbox_path_list *pathlist = NULL;
    struct sandbox_path_list *pathlist_save = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    pathlist_save = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_BLACKLIST,
            0, pathlist); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "read_data");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist_save, &node->blacklist));

    SANDBOX_RULE_MAKE(&rule, "vnode", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    kmem_free(pathlist, sizeof(*pathlist));
    sandbox_path_list_destroy(pathlist_save);
    kmem_free(pathlist_save, sizeof(*pathlist_save));

    TEST_END;
}

static void
test_insert_non_vnode_action_whitelist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_WHITELIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_insert_non_vnode_action_blacklist(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_BLACKLIST, 0, pathlist); 
    CU_ASSERT_EQUAL(error, 1);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_insert_action_bool_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL} };
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION,
            refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_FUNCTION);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);
    
    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_subaction_bool(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 3);
    CU_ASSERT_STRING_EQUAL(node->name, "open");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_subaction_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"} };
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION,
            refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 3);
    CU_ASSERT_STRING_EQUAL(node->name, "open");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);
    
    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_insert_subaction_bool_func(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    int refvalue = 20;
    struct sandbox_ref *funcref = NULL;

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_FUNCTION,
            refvalue, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 3);
    CU_ASSERT_STRING_EQUAL(node->name, "open");
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_TRUE(node->type & SANDBOX_RULETYPE_FUNCTION);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_FALSE(node->type & SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_EQUAL(funcref->value, refvalue);
    
    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_search_nonexistent_scope(void)
{
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL} };

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);

    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_search_nonexistent_action(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL} };

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    sandbox_ruleset_destroy(set);

    TEST_END;
}

static void
test_search_nonexistent_subaction(void)
{
    int error = 0;
    struct sandbox_ruleset *set = NULL;
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL} };

    TEST_START;

    set = sandbox_ruleset_create(KAUTH_RESULT_DENY);
    error = sandbox_ruleset_insert(set, &rule, SANDBOX_RULETYPE_TRILEAN,
            KAUTH_RESULT_ALLOW, NULL); 
    CU_ASSERT_EQUAL(error, 0);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", "open");
    node = sandbox_ruleset_search(set, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    sandbox_ruleset_destroy(set);

    TEST_END;
}


static CU_TestInfo suite_tests[] = {
    {"insert default (bool)", test_insert_default_bool},
    {"insert default (func)", test_insert_default_func},
    {"insert default (whitelist)", test_insert_default_whitelist},
    {"insert default (blacklist)", test_insert_default_blacklist},

    {"insert scope (bool)", test_insert_scope_bool},
    {"insert scope (func)", test_insert_scope_func},
    {"insert vnode scope (whitelist)", test_insert_vnode_scope_whitelist},
    {"insert vnode scope (blacklist)", test_insert_vnode_scope_blacklist},
    {"insert non-vnode scope (whitelist)", test_insert_non_vnode_scope_whitelist},
    {"insert non-vnode scope (blacklist)", test_insert_non_vnode_scope_blacklist},
    {"insert scope (bool, func)", test_insert_scope_bool_func},
    {"insert vnode scope (bool, func, whitelist)", test_insert_vnode_scope_bool_func_whitelist},

    {"insert action (bool)", test_insert_action_bool},
    {"insert action (func)", test_insert_action_func},
    {"insert vnode action (whitelist)", test_insert_vnode_action_whitelist},
    {"insert vnode action (blacklist)", test_insert_vnode_action_blacklist},
    {"insert non-vnode action (whitelist)", test_insert_non_vnode_action_whitelist},
    {"insert non-vnode action (blacklist)", test_insert_non_vnode_action_blacklist},
    {"insert action (bool, func)", test_insert_action_bool_func},

    {"insert subaction (bool)", test_insert_subaction_bool},
    {"insert subaction (func)", test_insert_subaction_func},
    {"insert subaction (bool, func)", test_insert_subaction_bool_func},

    {"search for nonexistent scope", test_search_nonexistent_scope},
    {"search for nonexistent action", test_search_nonexistent_action},
    {"search for nonexistent subaction", test_search_nonexistent_subaction},

    CU_TEST_INFO_NULL
};

static CU_SuiteInfo suite_ruleset = {
    .pName = "sandbox_ruleset suite", 
    .pInitFunc = NULL, 
    .pCleanupFunc = NULL,
    .pSetUpFunc = NULL,
    .pTearDownFunc = NULL,
    .pTests = suite_tests
};

CU_SuiteInfo *
suite_ruleset_open(void)
{
    return (&suite_ruleset);
}
