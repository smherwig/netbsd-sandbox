#ifndef _TEST_UTIL_H_
#define _TEST_UTIL_H_

#include <stdio.h>

#include "sandbox_path.h"

#define TEST_START  printf("\n--------------------------\n")
#define TEST_END    do {} while (0); 

struct sandbox_path_list * test_util_make_dummy_path_list(void);

#endif /* !_TEST_UTIL_H */
