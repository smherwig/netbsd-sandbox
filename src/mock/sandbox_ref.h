#ifndef _SANDBOX_REF_H_
#define _SANDBOX_REF_H_

#include <msys/queue.h>

struct sandbox_ref {
    int value;
    SIMPLEQ_ENTRY(sandbox_ref) ref_next;
};

/* struct sandbox_ref_list { }; */
SIMPLEQ_HEAD(sandbox_ref_list, sandbox_ref);

struct sandbox_ref * sandbox_ref_create(int value);
void sandbox_ref_destroy(struct sandbox_ref *ref);

/* does not destroy ref_list head, just the elements */
void sandbox_ref_list_destroy(struct sandbox_ref_list *ref_list);

#endif /* !_SANDBOX_REF_H_ */
