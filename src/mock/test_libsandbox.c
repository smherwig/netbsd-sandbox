#include <stdlib.h>
#include <unistd.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Console.h>

#include "sandbox_log.h"

#include "suite_rule.h"
#include "suite_ruleset.h"
#include "suite_lua.h"
#include "suite_sandbox.h"

#define ADD_SUITE(name) \
    do { \
        suiteInfo = name##_open(); \
        add_suite(suiteInfo); \
    } while (0)

static void
add_suite(CU_SuiteInfo *suiteInfo)
{
    CU_pSuite suite = NULL;
    CU_TestInfo *testInfo = NULL;

    suite = CU_add_suite(suiteInfo->pName, suiteInfo->pInitFunc, suiteInfo->pCleanupFunc);
    
    for (testInfo = suiteInfo->pTests; testInfo->pName != NULL; testInfo++) {
        CU_add_test(suite, testInfo->pName, testInfo->pTestFunc);
    }
}

static void 
usage(void)
{
    fprintf(stderr, 
            "usage: test_libsandbox [-c]\n"
            "\n"
            "options:\n"
            "\t-c\n"
            "\t\trun tests with an interactive console\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int result = 0;
    CU_ErrorCode cuerror;
    CU_SuiteInfo *suiteInfo = NULL;
    int c = 0;
    int use_console = 0;

    opterr = 0;
    while ((c = getopt(argc, argv, "c")) != -1) {
        switch (c) {
        case 'c':
            use_console = 1;
            break;
        default:
            usage();
        }
    }

    cuerror = CU_initialize_registry();
    if (cuerror != CUE_SUCCESS) {
        SANDBOX_LOG_ERROR("CU_initialize_registry() failed\n");
        result = 1;
        goto done;
    }

    ADD_SUITE(suite_rule);
    ADD_SUITE(suite_ruleset);
    ADD_SUITE(suite_lua);
    ADD_SUITE(suite_sandbox);

    CU_basic_set_mode(CU_BRM_VERBOSE);  /* CU_BRM_NORMAL */
    CU_set_error_action(CUEA_ABORT);
    if (use_console)
        CU_console_run_tests();
    else
        CU_basic_run_tests();

done:
    CU_cleanup_registry();
    return (result);
}
