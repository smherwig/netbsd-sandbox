#include <msys/kauth.h>

#include <CUnit/CUnit.h>
#include "test_util.h"

#include "sandbox.h"
#include "sandbox_rule.h"

#include "sandbox_log.h"

static void
test_allow_action(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    kauth_cred_t cred;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('network.socket')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);
    
    cred = kauth_cred_alloc();
    result = sandbox_eval(sandbox, cred, &rule, NULL, NULL);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_ALLOW);

    kauth_cred_free(cred);
    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_deny_action(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", NULL}};
    kauth_cred_t cred;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.deny('network.socket')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);
    
    cred = kauth_cred_alloc();
    result = sandbox_eval(sandbox, cred, &rule, NULL, NULL);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_DENY);

    kauth_cred_free(cred);
    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_eval_subaction_for_action_rule(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    kauth_cred_t cred;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('network.socket')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);
    
    cred = kauth_cred_alloc();
    result = sandbox_eval(sandbox, cred, &rule, NULL, NULL);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_ALLOW);

    kauth_cred_free(cred);
    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_eval_subaction_for_scope_rule(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    kauth_cred_t cred;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.allow('network')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);
    
    cred = kauth_cred_alloc();
    result = sandbox_eval(sandbox, cred, &rule, NULL, NULL);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_ALLOW);

    kauth_cred_free(cred);
    sandbox_destroy(sandbox);

    TEST_END;
}

static void
test_eval_subaction_for_default_rule(void)
{
    int error = 0;
    int result = KAUTH_RESULT_DENY;
    struct sandbox *sandbox = NULL;
    struct sandbox_rule rule = { .names = {"network", "socket", "open"}};
    kauth_cred_t cred;

    TEST_START;
    
    sandbox = sandbox_create("sandbox.default('allow')", &error);
    CU_ASSERT_NOT_EQUAL(sandbox, NULL);
    CU_ASSERT_EQUAL(error, 0);
    
    cred = kauth_cred_alloc();
    result = sandbox_eval(sandbox, cred, &rule, NULL, NULL);
    CU_ASSERT_EQUAL(result, KAUTH_RESULT_ALLOW);

    kauth_cred_free(cred);
    sandbox_destroy(sandbox);

    TEST_END;
}

static CU_TestInfo suite_tests[] = {
    {"allow action", test_allow_action},
    {"deny action", test_deny_action},

    {"eval subaction for action rule", test_eval_subaction_for_action_rule},
    {"eval subaction for scope rule", test_eval_subaction_for_scope_rule},
    {"eval subaction for default rule", test_eval_subaction_for_default_rule},

    CU_TEST_INFO_NULL
};

static CU_SuiteInfo suite_sandbox = {
    .pName = "sandbox suite", 
    .pInitFunc = NULL, 
    .pCleanupFunc = NULL,
    .pSetUpFunc = NULL,
    .pTearDownFunc = NULL,
    .pTests = suite_tests
};


CU_SuiteInfo *
suite_sandbox_open(void)
{
    return (&suite_sandbox);
}
