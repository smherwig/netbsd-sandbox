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

#include <errno.h>

#include <msys/queue.h>
#include <msys/kauth.h>
#include <msys/kmem.h>

#include <CUnit/CUnit.h>
#include "test_util.h"

#include "sandbox.h"
#include "sandbox_lua.h"
#include "sandbox_rule.h"
#include "sandbox_ruleset.h"

#include "sandbox_log.h"

static void
test_empty_script(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_syntax_error(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    
    TEST_START;

    sandbox = sandbox_create("1 foo", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_default_allow(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;
    
    TEST_START;

    sandbox = sandbox_create("sandbox.default('allow')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_default_deny(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.default('deny')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_default_argerror(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.default('foo')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_no_default_provided(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_allow_scope(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('network')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "network");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    /* also make sure default is still 0 (deny) */
    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_allow_action(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('network.socket')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_allow_subaction(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('network.socket.open')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 3);
    CU_ASSERT_STRING_EQUAL(node->name, "open");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_ALLOW);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_allow_zero_args(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow()", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_allow_too_many_args(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('one', 'two')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_allow_arg_number(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow(1)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_allow_arg_table(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow({'a', 'b'})", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_allow_arg_function(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow(function() print('hello') end)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_allow_arg_empty_string(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_deny_scope(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny('network')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "network");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    /* also make sure default is still 0 (deny) */
    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_deny_action(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny('network.socket')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_deny_subaction(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    const struct sandbox_rulenode *node = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny('network.socket.open')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 3);
    CU_ASSERT_STRING_EQUAL(node->name, "open");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_deny_zero_args(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny()", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_deny_too_many_args(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny('one', 'two')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_deny_arg_number(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny(1)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_deny_arg_table(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny({'a', 'b'})", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_deny_arg_function(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny(function() print('hello') end)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_deny_arg_empty_string(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny('')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_scope(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", NULL, NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network', function() end)", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 1);
    CU_ASSERT_STRING_EQUAL(node->name, "network");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_TRUE(funcref->value > 0);

    /* also make sure default is still 0 (deny) */
    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_on_action(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network.socket', function() end)", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_TRUE(funcref->value > 0);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_on_subaction(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network.socket.open', function() end)", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 3);
    CU_ASSERT_STRING_EQUAL(node->name, "open");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_TRUE(funcref->value > 0);

    SANDBOX_RULE_MAKE(&rule, "network", "socket", NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, "network", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_on_zero_args(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on()", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_one_arg(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_too_many_args(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network', function() end, 1)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg1_number(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on(1, function() end)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg1_table(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on({}, function() end)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg1_function(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on(function() end, function() end)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg1_empty_string(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('', function() end)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg2_string(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network', 'foo')", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg2_number(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network', 1)", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_on_arg2_table(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network', {})", &error);
    CU_ASSERT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, EINVAL);

    TEST_END;
}

static void
test_paths_allow_action(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"vnode", "read_data", NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    
    sandbox = sandbox_create("sandbox.paths_allow('read_data', {'/foo', '/bar', '/baz'})", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "read_data");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_WHITELIST);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist, &node->whitelist));

    SANDBOX_RULE_MAKE(&rule, "vnode", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);
    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

static void
test_paths_deny_action(void)
{
    int error = 0;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"vnode", "read_data", NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_path_list *pathlist = NULL;

    TEST_START;

    pathlist = test_util_make_dummy_path_list();
    
    sandbox = sandbox_create("sandbox.paths_deny('read_data', {'/foo', '/bar', '/baz'})", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "read_data");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_BLACKLIST);
    CU_ASSERT_TRUE(sandbox_path_list_isequal(pathlist, &node->blacklist));

    SANDBOX_RULE_MAKE(&rule, "vnode", NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 0);
    CU_ASSERT_STRING_EQUAL(node->name, "");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_TRILEAN);
    CU_ASSERT_EQUAL(node->value, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);
    sandbox_path_list_destroy(pathlist);
    kmem_free(pathlist, sizeof(*pathlist));

    TEST_END;
}

#if 0
static void
test_eval_funcref_allow(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;
    kauth_cred_t cred; 

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network.socket', function() return true; end)", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_TRUE(funcref->value > 0);

    cred = kauth_cred_alloc();
    result = sandbox_lua_eval(sandbox->K, funcref->value, cred, &rule);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_ALLOW);

    sandbox_destroy(sandbox);
    kauth_cred_free(cred);

    TEST_END;
}

static void
test_eval_funcref_deny(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;
    kauth_cred_t cred; 

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network.socket', function() return false; end)", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_TRUE(funcref->value > 0);

    cred = kauth_cred_alloc();
    result = sandbox_lua_eval(sandbox->K, funcref->value, cred, &rule);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);
    kauth_cred_free(cred);

    TEST_END;
}

static void
test_eval_funcref_error(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    const struct sandbox_rulenode *node = NULL;
    struct sandbox_ref *funcref = NULL;
    kauth_cred_t cred; 

    TEST_START;
    
    sandbox = sandbox_create("sandbox.on('network.socket', function() error('foo error')  end)", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);

    node = sandbox_ruleset_search(sandbox->ruleset, &rule);
    CU_ASSERT_EQUAL(node->level, 2);
    CU_ASSERT_STRING_EQUAL(node->name, "socket");
    CU_ASSERT_EQUAL(node->type, SANDBOX_RULETYPE_FUNCTION);
    funcref = SIMPLEQ_FIRST(&node->funclist);
    CU_ASSERT_TRUE(funcref->value > 0);

    cred = kauth_cred_alloc();
    result = sandbox_lua_eval(sandbox->K, funcref->value, cred, &rule);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_DENY);

    sandbox_destroy(sandbox);
    kauth_cred_free(cred);

    TEST_END;
}
#endif

static CU_TestInfo suite_tests[] = {
    {"empty script", test_empty_script},
    {"syntax error", test_syntax_error},

    {"default('allow')", test_default_allow},
    {"default('deny')", test_default_deny},
    {"default(bad arg)", test_default_argerror},
    {"no default provided", test_no_default_provided},

    {"allow(scope)", test_allow_scope},
    {"allow(action)", test_allow_action},
    {"allow(subaction)", test_allow_subaction},

    {"allow(zero args)", test_allow_zero_args},
    {"allow(too many args)", test_allow_too_many_args},
    {"allow(arg number)", test_allow_arg_number},
    {"allow(arg table)", test_allow_arg_table},
    {"allow(arg function)", test_allow_arg_function},
    {"allow(arg empty string)", test_allow_arg_empty_string},

    {"deny(scope)", test_deny_scope},
    {"deny(action)", test_deny_action},
    {"deny(subaction)", test_deny_subaction},

    {"deny(zero args)", test_deny_zero_args},
    {"deny(too many args)", test_deny_too_many_args},
    {"deny(arg number)", test_deny_arg_number},
    {"deny(arg table)", test_deny_arg_table},
    {"deny(arg function)", test_deny_arg_function},
    {"deny(arg empty string)", test_deny_arg_empty_string},

    {"on(scope)", test_on_scope},
    {"on(action)", test_on_action},
    {"on(subaction)", test_on_subaction},

    {"on(zero args)", test_on_zero_args},
    {"on(one arg)", test_on_one_arg},
    {"on(too many args)", test_on_too_many_args},
    {"on(arg1 number)", test_on_arg1_number},
    {"on(arg1 table)", test_on_arg1_table},
    {"on(arg1 function)", test_on_arg1_function},
    {"on(arg1 empty string)", test_on_arg1_empty_string},
    {"on(arg2 string)", test_on_arg2_string},
    {"on(arg2 number)", test_on_arg2_number},
    {"on(arg2 table)", test_on_arg2_table},

    {"paths_allow(action)", test_paths_allow_action},
    {"paths_deny(action)", test_paths_deny_action},
    /* TODO: add more paths_allow()/paths_deny() tests */

#if 0
    {"eval funcref allow", test_eval_funcref_allow},
    {"eval funcref deny", test_eval_funcref_deny},
    {"eval funcref error", test_eval_funcref_error},
#endif

    CU_TEST_INFO_NULL
};

static CU_SuiteInfo suite_ruleset = {
    .pName = "sandbox_lua suite", 
    .pInitFunc = NULL, 
    .pCleanupFunc = NULL,
    .pSetUpFunc = NULL,
    .pTearDownFunc = NULL,
    .pTests = suite_tests
};

CU_SuiteInfo *
suite_lua_open(void)
{
    return (&suite_ruleset);
}
