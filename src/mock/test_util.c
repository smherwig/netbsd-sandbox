#include <msys/queue.h>
#include <msys/kmem.h>

#include "sandbox_path.h"

#include "test_util.h"

struct sandbox_path_list *
test_util_make_dummy_path_list(void)
{
    struct sandbox_path_list *pathlist = NULL;
    struct sandbox_path *path = NULL;

    pathlist = kmem_zalloc(sizeof(*pathlist), KM_SLEEP);
    SIMPLEQ_INIT(pathlist);

    path = sandbox_path_create("/foo"); 
    SIMPLEQ_INSERT_TAIL(pathlist, path, path_next);

    path = sandbox_path_create("/bar");
    SIMPLEQ_INSERT_TAIL(pathlist, path, path_next);

    path = sandbox_path_create("/baz");
    SIMPLEQ_INSERT_TAIL(pathlist, path, path_next);

    return (pathlist);
}
