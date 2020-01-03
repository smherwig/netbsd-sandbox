#include <msys/kmem.h>
#include <msys/lua.h>

#include <lua.h>
#include <lauxlib.h>

void klua_lock(klua_State *K)
{
    return;
}

void
klua_unlock(klua_State *K)
{
    return;
}

klua_State *
kluaL_newstate(const char *name, const char *desc, int flags)
{
    klua_State *K = NULL;

    K = kmem_zalloc(sizeof(*K), KM_SLEEP);
    K->L = luaL_newstate();

    return (K);
}

void
klua_close(klua_State *K)
{
    lua_close(K->L);
    kmem_free(K, sizeof(*K));
}

