#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/kmem.h>

#include "sandbox_ref.h"
#include "sandbox_log.h"

struct sandbox_ref *
sandbox_ref_create(int value)
{
    struct sandbox_ref *ref = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    ref = kmem_zalloc(sizeof(*ref), KM_SLEEP);
    ref->value = value;

    SANDBOX_LOG_TRACE_EXIT;
    return (ref);
}

void
sandbox_ref_destroy(struct sandbox_ref *ref)
{
    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(ref != NULL);

    kmem_free(ref, sizeof(*ref));

    SANDBOX_LOG_TRACE_EXIT;
}

void
sandbox_ref_list_destroy(struct sandbox_ref_list *ref_list)
{
    struct sandbox_ref *ref = NULL;
    struct sandbox_ref *tmp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    KASSERT(ref_list != NULL);

    SIMPLEQ_FOREACH_SAFE(ref, ref_list, ref_next, tmp) {
        sandbox_ref_destroy(ref);
    }

    SANDBOX_LOG_TRACE_EXIT;
}
