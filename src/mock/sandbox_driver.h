#ifndef _SANDBOX_DRIVER_H_
#define _SANDBOX_DRIVER_H_

#include <msys/queue.h>

#include "sandbox.h"

struct sandbox_driver {
    LIST_HEAD( , sandbox) sandbox_list;
    int nsandbox;
};

struct sandbox_driver * sandbox_driver_new(void);

struct sandbox * sandbox_driver_newsandbox(struct sandbox_driver *driver,
        const char *script);

void sandbox_driver_closesandbox(struct sandbox_driver *driver, 
        struct sandbox *sandbox);

void sandbox_driver_close(struct sandbox_driver *driver);

#endif /* !_SANDBOX_DRIVER_H_ */
