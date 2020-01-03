#ifndef _SANDBOX_PATH_H_
#define _SANDBOX_PATH_H_

#include <msys/param.h>
#include <msys/types.h>
#include <msys/queue.h>
#include <msys/vnode.h>

#define SANDBOX_PATH_MAXPATHLEN 256

struct sandbox_path {
    char path[SANDBOX_PATH_MAXPATHLEN];
    struct vnode *vp;
    u_int refcnt;
    SIMPLEQ_ENTRY(sandbox_path) path_next;
};

/* struct sandbox_path_list { }; */
SIMPLEQ_HEAD(sandbox_path_list, sandbox_path);

struct sandbox_path * sandbox_path_create(const char *path);
void sandbox_path_hold(struct sandbox_path *path);
void sandbox_path_destroy(struct sandbox_path *path);
int sandbox_path_isequal(const struct sandbox_path *a, 
        const struct sandbox_path *b);

void sandbox_path_list_concat(struct sandbox_path_list *to, 
        struct sandbox_path_list *from);

/* does not destroy head */
void sandbox_path_list_destroy(struct sandbox_path_list *list);
int sandbox_path_list_isequal(const struct sandbox_path_list *a, 
        const struct sandbox_path_list *b);

int sandbox_path_list_containsvnode(const struct sandbox_path_list *list,
        const struct vnode *vp);

#endif /* !_SANDBOX_PATH_H_ */
