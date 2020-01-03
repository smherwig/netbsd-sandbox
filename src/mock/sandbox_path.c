#include <msys/systm.h>
#include <msys/queue.h>
#include <msys/kmem.h>
#include <msys/atomic.h>

#include "sandbox_path.h"

#include "sandbox_log.h"

struct sandbox_path *
sandbox_path_create(const char *path)
{
    struct sandbox_path *sp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(path != NULL);

    sp = kmem_zalloc(sizeof(*sp), KM_SLEEP);
    sp->refcnt = 1;
    /* TODO: check for overflow */
    memcpy(sp->path, path, strlen(path));

    /* TODO: MOCK: namei_simple_kernel() */

    SANDBOX_LOG_TRACE_EXIT;
    return(sp);
}

void
sandbox_path_hold(struct sandbox_path *sp)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(sp != NULL);
    KASSERT(sp->refcnt > 0);

    atomic_inc_uint(&sp->refcnt);

    SANDBOX_LOG_TRACE_EXIT;
}

void
sandbox_path_destroy(struct sandbox_path *sp)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(sp != NULL);
    KASSERT(sp->refcnt > 0);

    if (atomic_dec_uint_nv(&sp->refcnt) > 0)
        goto done;

    SANDBOX_LOG_DEBUG("destroying sandbox_path\n");
    /* TODO: MOCK: mock holdrele */
    kmem_free(sp, sizeof(*sp));

done:
    SANDBOX_LOG_TRACE_EXIT;
    return;
}

int
sandbox_path_isequal(const struct sandbox_path *spa, 
        const struct sandbox_path *spb)
{
    int result = 0;

    SANDBOX_LOG_TRACE_ENTER;

    if ((spa == NULL) && (spb == NULL)) {
        result = 1;
        goto done;
    }

    if ((spa == NULL) && (spb != NULL)) {
        result = 0;
        goto done;
    }

    if ((spa != NULL) && (spb == NULL)) {
        result = 0;
        goto done;
    }

    if (strcmp(spa->path, spb->path) == 0)
        result = 1;
    else
        result = 0;

done:
    SANDBOX_LOG_TRACE_EXIT;
    return (result);
}

void
sandbox_path_list_destroy(struct sandbox_path_list *list)
{
    struct sandbox_path *sp = NULL;
    struct sandbox_path *tmp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(list != NULL);

    SIMPLEQ_FOREACH_SAFE(sp, list, path_next, tmp) {
        sandbox_path_destroy(sp);
    }

    SANDBOX_LOG_TRACE_EXIT;
}

void 
sandbox_path_list_concat(struct sandbox_path_list *to, 
        struct sandbox_path_list *from)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(to != NULL);
    KASSERT(from != NULL);

    /* nodes get transfered from 'from' to 'to'; 'from' gets initialized back
     * to an empty list
     */
    SIMPLEQ_CONCAT(to, from);

    SANDBOX_LOG_TRACE_EXIT;
}

int
sandbox_path_list_isequal(const struct sandbox_path_list *a, 
        const struct sandbox_path_list *b)
{
    int equal = 1;
    struct sandbox_path *spa = NULL;
    struct sandbox_path *spb = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(a != NULL);
    KASSERT(b != NULL);

    spa = SIMPLEQ_FIRST(a);
    spb = SIMPLEQ_FIRST(b);

    while (1) {
        if (spa == NULL || spb == NULL)
            break;

        if (!sandbox_path_isequal(spa, spb)) {
            equal = 0;
            break;
        }

        spa = SIMPLEQ_NEXT(spa, path_next);
        spb = SIMPLEQ_NEXT(spb, path_next);
    }

    if (equal == 1)
        if ((spa == NULL && spb != NULL) || (spa != NULL && spb == NULL))
                equal = 0;

    SANDBOX_LOG_TRACE_EXIT;
    return (equal);
}

int
sandbox_path_list_containsvnode(const struct sandbox_path_list *list,
        const struct vnode *vp)
{
    int contains = 0;

    SANDBOX_LOG_TRACE_EXIT;

    KASSERT(list != NULL);

    if (vp == NULL)
        goto done;

    /* TODO: MOCK: implement */

done:
    SANDBOX_LOG_TRACE_ENTER;
    return (contains);
}
