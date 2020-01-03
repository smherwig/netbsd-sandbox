#ifndef _SANDBOX_LUA_H_
#define _SANDBOX_LUA_H_

#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/kauth.h>
#include <sys/lua.h>

#include "sandbox.h"
#include "sandbox_rule.h"

int sandbox_lua_load(klua_State *K, const char *script);

int sandbox_lua_veval(klua_State *K, int funcref, kauth_cred_t cred, 
        const struct sandbox_rule *rule, const char *fmt, va_list ap);

void sandbox_lua_newstate(struct sandbox *sandbox);

#endif /* !_SANDBOX_LUA_H_ */
