#include <stdio.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "sandbox.h"

static void 
usage(int rc)
{
    fprintf(stderr, "sblua <sandbox-policy> <lua-script>\n");
    exit(rc);
}

int main(int argc, char *argv[])
{
    int error = 0;
    lua_State *L = NULL;

    if (argc != 3)
        usage(1);

    error = sandbox_from_file(argv[1], 0);
    if (error != 0) {
        fprintf(stderr, "failed to set sandbox policy\n");
        return (EXIT_FAILURE);
    }

    L = luaL_newstate();
    if (L == NULL) {
        fprintf(stderr, "cannot create state: not enough memory\n");
        return (EXIT_FAILURE);
    }

    luaL_openlibs(L);
    error = luaL_dofile(L, argv[2]);
    if (error) {
        fprintf(stderr, "%s\n", lua_tostring(L, -1));
        lua_pop(L, 1); /* pop error message from the stack */
    }
    lua_close(L);

    return (0);
}
