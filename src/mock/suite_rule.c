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

#include <CUnit/CUnit.h>
#include "test_util.h"

#include "sandbox_log.h"
#include "sandbox_rule.h"

static void
test_rule_size_0(void)
{
    int size = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    size = sandbox_rule_size(&rule);
    CU_ASSERT_EQUAL(size, 0);

    TEST_END;
}

static void
test_rule_size_1(void)
{
    int size = 0;
    struct sandbox_rule rule = {.names={"network", NULL, NULL}};
    
    TEST_START;

    size = sandbox_rule_size(&rule);
    CU_ASSERT_EQUAL(size, 1);

    TEST_END;
}

static void
test_rule_size_2(void)
{
    int size = 0;
    struct sandbox_rule rule = {.names={"network", "socket", NULL}};

    TEST_START;

    size = sandbox_rule_size(&rule);
    CU_ASSERT_EQUAL(size, 2);

    TEST_END;
}

static void
test_rule_size_3(void)
{
    int size = 0;
    struct sandbox_rule rule = {.names={"network", "socket", "open"}};

    TEST_START;

    size = sandbox_rule_size(&rule);
    CU_ASSERT_EQUAL(size, 3);

    TEST_END;
}

static void
test_initfromstring_scope(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("network", &rule);
    CU_ASSERT_EQUAL(error, 0);
    CU_ASSERT_EQUAL(sandbox_rule_size(&rule), 1);
    CU_ASSERT_STRING_EQUAL(rule.names[0], "network");

    sandbox_rule_freenames(&rule);

    TEST_END;
}

static void
test_initfromstring_action(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("network.socket", &rule);
    CU_ASSERT_EQUAL(error, 0);
    CU_ASSERT_EQUAL(sandbox_rule_size(&rule), 2);
    printf("names[0]='%s'\n", rule.names[0]);
    CU_ASSERT_STRING_EQUAL(rule.names[0], "network");
    printf("names[1]='%s'\n", rule.names[1]);
    CU_ASSERT_STRING_EQUAL(rule.names[1], "socket");

    sandbox_rule_freenames(&rule);

    TEST_END;
}

static void
test_initfromstring_subaction(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("network.socket.open", &rule);
    CU_ASSERT_EQUAL(error, 0);
    CU_ASSERT_EQUAL(sandbox_rule_size(&rule), 3);
    CU_ASSERT_STRING_EQUAL(rule.names[0], "network");
    CU_ASSERT_STRING_EQUAL(rule.names[1], "socket");
    CU_ASSERT_STRING_EQUAL(rule.names[2], "open");

    sandbox_rule_freenames(&rule);

    TEST_END;
}

static void
test_initfromstring_too_many_names(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("network.socket.open.tcp", &rule);
    CU_ASSERT_EQUAL(error, 1);
    CU_ASSERT_EQUAL(rule.names[0], NULL);
    CU_ASSERT_EQUAL(rule.names[1], NULL);
    CU_ASSERT_EQUAL(rule.names[2], NULL);

    TEST_END;
}

static void
test_initfromstring_consecutive_dots(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("network..open", &rule);
    CU_ASSERT_EQUAL(error, 1);
    CU_ASSERT_EQUAL(rule.names[0], NULL);
    CU_ASSERT_EQUAL(rule.names[1], NULL);
    CU_ASSERT_EQUAL(rule.names[2], NULL);

    TEST_END;
}

static void
test_initfromstring_single_dot(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring(".", &rule);
    CU_ASSERT_EQUAL(error, 1);
    CU_ASSERT_EQUAL(rule.names[0], NULL);
    CU_ASSERT_EQUAL(rule.names[1], NULL);
    CU_ASSERT_EQUAL(rule.names[2], NULL);

    TEST_END;
}

static void
test_initfromstring_empty_string(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("", &rule);
    CU_ASSERT_EQUAL(error, 1);
    CU_ASSERT_EQUAL(rule.names[0], NULL);
    CU_ASSERT_EQUAL(rule.names[1], NULL);
    CU_ASSERT_EQUAL(rule.names[2], NULL);

    TEST_END;
}

static void
test_initfromstring_ends_in_dot(void)
{
    int error = 0;
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    error = sandbox_rule_initfromstring("network.", &rule);
    CU_ASSERT_EQUAL(error, 1);
    CU_ASSERT_EQUAL(rule.names[0], NULL);
    CU_ASSERT_EQUAL(rule.names[1], NULL);
    CU_ASSERT_EQUAL(rule.names[2], NULL);

    TEST_END;
}

static void
test_isvnode_vnode(void)
{
    struct sandbox_rule rule = {.names={"vnode", NULL, NULL}};

    TEST_START;

    CU_ASSERT_TRUE(sandbox_rule_isvnode(&rule));

    TEST_END;
}

static void
test_isvnode_default(void)
{
    struct sandbox_rule rule = {.names={NULL, NULL, NULL}};

    TEST_START;

    CU_ASSERT_FALSE(sandbox_rule_isvnode(&rule));

    TEST_END;
}

static void
test_isvnode_network(void)
{
    struct sandbox_rule rule = {.names={"network", NULL, NULL}};

    TEST_START;

    CU_ASSERT_FALSE(sandbox_rule_isvnode(&rule));

    TEST_END;
}

static CU_TestInfo suite_tests[] = {
    {"rule size 0", test_rule_size_0},
    {"rule size 1", test_rule_size_1},
    {"rule size 2", test_rule_size_2},
    {"rule size 3", test_rule_size_3},

    {"initfromstring scope", test_initfromstring_scope},
    {"initfromstring action", test_initfromstring_action},
    {"initfromstring subaction", test_initfromstring_subaction},

    {"initfromstring too many names", test_initfromstring_too_many_names},
    {"initfromstring consecutive dots", test_initfromstring_consecutive_dots},
    {"initfromstring single dot", test_initfromstring_single_dot},
    {"initfromstring empty string", test_initfromstring_empty_string},
    {"initfromstring ends in dot", test_initfromstring_ends_in_dot},

    {"isvnode(vnode)", test_isvnode_vnode},
    {"isvnode(default)", test_isvnode_default},
    {"isvnode(network)", test_isvnode_network},

    CU_TEST_INFO_NULL
};

static CU_SuiteInfo suite_ruleset = {
    .pName = "sandbox_rule suite", 
    .pInitFunc = NULL, 
    .pCleanupFunc = NULL,
    .pSetUpFunc = NULL,
    .pTearDownFunc = NULL,
    .pTests = suite_tests
};


CU_SuiteInfo *
suite_rule_open(void)
{
    return (&suite_ruleset);
}
