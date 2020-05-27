/*-
 * Copyright (c) 2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by 
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <msys/queue.h>
#include <msys/vnode.h>
#include <msys/proc.h>
#include <msys/kmem.h>
#include <msys/kauth.h>
#include <msys/socketvar.h>
#include <msys/lua.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <errno.h>

#include "sandbox.h"
#include "sandbox_lua.h"
#include "sandbox_path.h"
#include "sandbox_rule.h"
#include "sandbox_ruleset.h"

#include "sandbox_log.h"

struct sandbox_lua_const {
    int value;
    const char *name;
};

#define SANDBOX_LUA_CONST(konst)    {konst, #konst}
#define SANDBOX_LUA_CONST_SENTINEL    {0, NULL}

static struct sandbox_lua_const sandbox_lua_consts[] = {
    /* 
     * sys/socket.h 
     */ 

    /* socket domains (families) */
    SANDBOX_LUA_CONST(AF_UNIX),       SANDBOX_LUA_CONST(PF_UNIX),
    SANDBOX_LUA_CONST(AF_INET),       SANDBOX_LUA_CONST(PF_INET),
    SANDBOX_LUA_CONST(AF_INET6),      SANDBOX_LUA_CONST(PF_INET6),

    /* socket types */
    SANDBOX_LUA_CONST(SOCK_STREAM),
    SANDBOX_LUA_CONST(SOCK_DGRAM),
    SANDBOX_LUA_CONST(SOCK_RAW),
    SANDBOX_LUA_CONST(SOCK_SEQPACKET),

    /*
     * netinet/in.h
     */

    /* protocols */
    SANDBOX_LUA_CONST(IPPROTO_TCP),
    SANDBOX_LUA_CONST(IPPROTO_UDP),
    SANDBOX_LUA_CONST(IPPROTO_RAW),

    /* 
     * sys/stat.h 
     */ 

    /* owner permissions */
    SANDBOX_LUA_CONST(S_IRWXU),
    SANDBOX_LUA_CONST(S_IRUSR),
    SANDBOX_LUA_CONST(S_IWUSR),
    SANDBOX_LUA_CONST(S_IXUSR),

    /* group permissions */
    SANDBOX_LUA_CONST(S_IRWXG),
    SANDBOX_LUA_CONST(S_IRGRP),
    SANDBOX_LUA_CONST(S_IWGRP),
    SANDBOX_LUA_CONST(S_IXGRP),

    /* other permissions */
    SANDBOX_LUA_CONST(S_IRWXO),
    SANDBOX_LUA_CONST(S_IROTH),
    SANDBOX_LUA_CONST(S_IWOTH),
    SANDBOX_LUA_CONST(S_IXOTH),

    /* file types */
    SANDBOX_LUA_CONST(S_IFMT),
    SANDBOX_LUA_CONST(S_IFIFO),
    SANDBOX_LUA_CONST(S_IFCHR),
    SANDBOX_LUA_CONST(S_IFDIR),
    SANDBOX_LUA_CONST(S_IFBLK),
    SANDBOX_LUA_CONST(S_IFREG),
    SANDBOX_LUA_CONST(S_IFLNK),
    SANDBOX_LUA_CONST(S_IFSOCK),

    SANDBOX_LUA_CONST_SENTINEL
};

/* assumes stack position -1 is table and constant value is an integer */
#define SANDBOX_LUA_PUSHCONST(L, konst) \
    do { \
	    lua_pushinteger(L, konst->value); \
        lua_setfield(L, -2, konst->name); \
    } while (0)


static void
sandbox_lua_pushconsts(lua_State *L, struct sandbox_lua_const *konsts)
{
    struct sandbox_lua_const *konst = NULL;
    konst = konsts;
    while (konst->name) {
        SANDBOX_LUA_PUSHCONST(L, konst);
        konst++;
    }
}

/* cred = {
 *   uid     =  integer,
 *   euid    =  integer,
 *   svuid   =  integer,
 *   gid     =  integer,
 *   egid    =  integer,
 *   svgid   =  integer,
 *   groups  =  {integer, integer, ..., integer}
 * }
 */
static void
sandbox_lua_pushcred(lua_State *L, kauth_cred_t cred)
{
    u_int ngroups = 0;
    u_int idx = 0;

    SANDBOX_LOG_TRACE_ENTER;

    lua_newtable(L);
    lua_pushinteger(L, kauth_cred_getuid(cred));
    lua_setfield(L, -2, "uid");

    lua_pushinteger(L, kauth_cred_geteuid(cred));
    lua_setfield(L, -2, "euid");

    lua_pushinteger(L,  kauth_cred_getsvuid(cred));
    lua_setfield(L, -2, "svuid");

    lua_pushinteger(L, kauth_cred_getgid(cred));
    lua_setfield(L, -2, "gid");

    lua_pushinteger(L, kauth_cred_getegid(cred));
    lua_setfield(L, -2, "egid");

    lua_pushinteger(L, kauth_cred_getsvgid(cred));
    lua_setfield(L, -2, "svgid");

    lua_newtable(L);
    ngroups = kauth_cred_ngroups(cred);
    for (idx = 0; idx < ngroups; idx++) {
        lua_pushinteger(L, kauth_cred_group(cred, idx));
        lua_seti(L, -2, idx + 1);
    }
    lua_setfield(L, -2, "groups");

    SANDBOX_LOG_TRACE_EXIT;
}

/* rule = {
 *   scope = string
 *   action = string
 *   rule = string
 * }
 */
static void
sandbox_lua_pushrule(lua_State *L, const struct sandbox_rule *rule)
{
    SANDBOX_LOG_TRACE_ENTER;

    lua_newtable(L);

    lua_pushstring(L, SANDBOX_RULE_SCOPE(rule));
    lua_setfield(L, -2, "scope");

    lua_pushstring(L, SANDBOX_RULE_ACTION(rule));
    lua_setfield(L, -2, "action");

    lua_pushstring(L, SANDBOX_RULE_SUBACTION(rule));
    lua_setfield(L, -2, "subaction");

    SANDBOX_LOG_TRACE_EXIT;
}

/* The vnode table combines the vnode's file name with
 * the stat info for the vnode.
 *
 * vnode = {
 *  name        = string (just basename for now)
 *  type        = string,
 *  mode        = integer,
 *  nlink       = integer,
 *  uid         = integer,
 *  gid         = integer,
 *  size        = integer,
 *  atime       = integer,
 *  mtime       = integer,
 *  ctime       = integer,
 *  blksize     = integer,
 *  blocks      = integer,
 *  ino         = integer
 * }
 */
static void
sandbox_lua_pushvnode(lua_State *L, struct vnode *vp)
{
    lua_newtable(L);
    return;
}

/* proc = {
 *   pid     =  integer,
 *   ppid    =  integer,
 *   comm    =  string,
 *   nice    =  integer
 * }
 * TODO: add more fields, as needed.
 */
static void
sandbox_lua_pushproc(lua_State *L,  struct proc *p)
{
    lua_newtable(L);
    /* stack: -1=proc */
    lua_pushinteger(L, p->p_pid);
    /* stack: -2=proc, -1=pid */
    lua_setfield(L, -2, "pid");
    /* stack: -1=proc */
    lua_pushinteger(L, p->p_ppid);
    /* stack: -2=proc, -1=ppid */
    lua_setfield(L, -2, "ppid");
    /* stack: -1=proc */

    lua_pushinteger(L, p->p_nice);
    /* stack: -2=proc, -1=nice */
    lua_setfield(L, -2, "nice");
    /* stack: -1=proc */
    lua_pushstring(L, p->p_comm);
    /* stack: -2=proc, -1=comm */
    lua_setfield(L, -2, "comm");
    /* stack: -1=proc */
}

static void
sandbox_lua_pushsocket(lua_State *L, struct socket *so)
{
    lua_newtable(L);
    /* TODO: implement */
}

/* sockaddr = {
 *      family      integer,
 *      port        integer     (in/in6),
 *      address     string      (in/in6),
 *      path        string      (unix),
 * }
 */
static void
sandbox_lua_pushsockaddr_in(lua_State *L, struct sockaddr_in *s)
{
    unsigned char *ip = NULL;

    ip = (unsigned char *)&s->sin_addr;

    lua_newtable(L);
    lua_pushinteger(L, s->sin_family);
    lua_setfield(L, -2, "family");
    lua_pushinteger(L, ntohs(s->sin_port));
    lua_setfield(L, -2, "port");
    lua_pushfstring(L, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    lua_setfield(L, -2, "address"); 
}

static void
sandbox_lua_pushsockaddr_in6(lua_State *L, struct sockaddr_in6 *s)
{
    lua_newtable(L);
    lua_pushinteger(L, s->sin6_family);
    lua_setfield(L, -2, "family");
    lua_pushinteger(L, ntohs(s->sin6_port));
    lua_setfield(L, -2, "port");
    /* TODO: push s->sin6_addr: might have to use parts of inet_ntop.c */
}

static void
sandbox_lua_pushsockaddr_un(lua_State *L, struct sockaddr_un *s)
{
    lua_newtable(L);
    lua_pushinteger(L, s->sun_family);
    lua_setfield(L, -2, "family");
    /* XXX: perhaps use pushlstring in case sun_path is not null-terminated */
    lua_pushstring(L, s->sun_path);
    lua_setfield(L, -2, "path");
}

static void
sandbox_lua_pushsockaddr(lua_State *L, struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        sandbox_lua_pushsockaddr_in(L, (struct sockaddr_in *)sa);
        break;
    case AF_INET6:
        sandbox_lua_pushsockaddr_in6(L, (struct sockaddr_in6 *)sa);
        break;
    case AF_UNIX:
        sandbox_lua_pushsockaddr_un(L, (struct sockaddr_un *)sa);
        break;
    default:
        SANDBOX_LOG_WARN("unknown socket family %u\n", sa->sa_family);
        /* just push table with family */
        lua_newtable(L);
        lua_pushinteger(L, sa->sa_family);
        lua_setfield(L, -2, "family");
        break;
    }
}

/* TODO: consider allowing default to be a function
 * sandbox.default('allow' | 'deny' | 'defer')
 */
static int
sandbox_lua_default(lua_State *L)
{
    int nargs = 0;
    int idx = 0;
    int error = 0;
    const char *sval = NULL;
    int val = 0;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL }};
    struct sandbox *sandbox = NULL;
    
    SANDBOX_LOG_TRACE_ENTER;

    nargs = lua_gettop(L);
    if (nargs != 1)
        return luaL_error(L, "wrong number of arguments");

    sval = luaL_checkstring(L, 1);

    if (strcmp(sval, "allow") == 0)
        val = KAUTH_RESULT_ALLOW;
    else if (strcmp(sval, "deny") == 0)
        val = KAUTH_RESULT_DENY;
    else if (strcmp(sval, "defer") == 0)
        val = KAUTH_RESULT_DEFER;
    else
        return luaL_error(L, "value must be 'allow', 'deny', 'defer'");

    idx = lua_upvalueindex(1);
    if (lua_isnone(L, idx))
        return luaL_error(L, "internal error -- sandbox not found");

    sandbox = (struct sandbox*)lua_touserdata(L, idx);
    if (sandbox == NULL)
        return luaL_error(L, "internal error -- invalid sandbox");
    
    SANDBOX_RULE_MAKE(&rule, NULL, NULL, NULL);
    error = sandbox_ruleset_insert(sandbox->ruleset, &rule, 
            SANDBOX_RULETYPE_TRILEAN, val, NULL);
    if (error)
        return luaL_error(L,  "internal error");

    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

/* sandbox.allow('foo.bar.baz') */
static int
sandbox_lua_allow(lua_State *L)
{
    int nargs = 0;
    int error = 0;
    int idx = 0;
    size_t len = 0;
    struct sandbox *sandbox = NULL;
    const char *rulename = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL }};
    
    SANDBOX_LOG_TRACE_ENTER;

    nargs = lua_gettop(L);
    if (nargs != 1)
        return luaL_error(L, "wrong number of arguments");

    luaL_checktype(L, 1, LUA_TSTRING);
    rulename = lua_tolstring(L, 1, &len);
    if (len == 0)
        return luaL_error(L, "name must have length > 0");
    
    idx = lua_upvalueindex(1);
    if (lua_isnone(L, idx))
        return luaL_error(L, "internal error -- sandbox not found");

    sandbox = (struct sandbox*)lua_touserdata(L, idx);
    if (sandbox == NULL)
        return luaL_error(L, "internal error -- invalid sandbox");

    error = sandbox_rule_initfromstring(rulename, &rule);
    if (error)
        return luaL_argerror(L, 1, "invalid rule name");

    error = sandbox_ruleset_insert(sandbox->ruleset, &rule, 
            SANDBOX_RULETYPE_TRILEAN, KAUTH_RESULT_ALLOW, NULL);
    sandbox_rule_freenames(&rule);
    if (error)
        return luaL_error(L,  "internal error");

    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

/* sandbox.deny('foo.bar.baz') */
/* TODO: deny() and allow() could be refactored to call into a common
 * function
 */
static int
sandbox_lua_deny(lua_State *L)
{
    int nargs = 0;
    int error = 0;
    size_t len = 0;
    int idx = 0;
    struct sandbox *sandbox = NULL;
    const char *rulename = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL }};
    
    SANDBOX_LOG_TRACE_ENTER;

    nargs = lua_gettop(L);
    if (nargs != 1)
        return luaL_error(L, "wrong number of arguments");

    luaL_checktype(L, 1, LUA_TSTRING);
    rulename = lua_tolstring(L, 1, &len);
    if (len == 0)
        return luaL_error(L, "name must have length > 0");
    
    idx = lua_upvalueindex(1);
    if (lua_isnone(L, idx))
        return luaL_error(L, "internal error -- sandbox not found");

    sandbox = (struct sandbox*)lua_touserdata(L, idx);
    if (sandbox == NULL)
        return luaL_error(L, "internal error -- invalid sandbox");

    error = sandbox_rule_initfromstring(rulename, &rule);
    if (error)
        return luaL_argerror(L, 1, "invalid rule name");

    error = sandbox_ruleset_insert(sandbox->ruleset, &rule, 
            SANDBOX_RULETYPE_TRILEAN, KAUTH_RESULT_DENY, NULL);
    sandbox_rule_freenames(&rule);
    if (error)
        return luaL_error(L,  "internal error -- unknown");

    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

/* sandbox.on('foo.bar.baz', function(cred, rule, arg1, arg2, arg3) ... end) */
static int
sandbox_lua_on(lua_State *L)
{
    int nargs = 0;
    int error = 0;
    size_t len = 0;
    int idx = 0;
    int ref = 0;
    struct sandbox *sandbox = NULL;
    const char *rulename = NULL;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL }};
    
    SANDBOX_LOG_TRACE_ENTER;

    nargs = lua_gettop(L);
    if (nargs != 2)
        return luaL_error(L, "wrong number of arguments");

    luaL_checktype(L, 1, LUA_TSTRING);
    rulename = lua_tolstring(L, 1, &len);
    if (len == 0)
        return luaL_error(L, "name must have length > 0");

    luaL_checktype(L, 2, LUA_TFUNCTION);
    
    idx = lua_upvalueindex(1);
    if (lua_isnone(L, idx))
        return luaL_error(L, "internal error -- sandbox not found");

    sandbox = (struct sandbox*)lua_touserdata(L, idx);
    if (sandbox == NULL)
        return luaL_error(L, "internal error -- invalid sandbox");

    error = sandbox_rule_initfromstring(rulename, &rule);
    if (error)
        return luaL_argerror(L, 1, "invalid rule name");

    /* TODO: add function to registry */
    lua_pushvalue(L, 2);
    /* stack: -1=func */
    ref = luaL_ref(L, LUA_REGISTRYINDEX);
    /* stack: */
    error = sandbox_ruleset_insert(sandbox->ruleset, &rule, 
            SANDBOX_RULETYPE_FUNCTION, ref, NULL);
    sandbox_rule_freenames(&rule);
    if (error)
        return luaL_error(L,  "internal error -- unknown");

    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

static int
sandbox_lua_paths_allow(lua_State *L)
{
    int error = 0;
    int nargs = 0;
    size_t len = 0;
    int idx = 0;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL }};
    const char *actionname = NULL;
    const char *pathname = NULL;
    lua_Integer tlen = 0;
    lua_Integer tidx = 0;
    struct sandbox_path_list pathlist;
    struct sandbox_path *sp = NULL;
    struct sandbox *sandbox = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    SIMPLEQ_INIT(&pathlist);

    nargs = lua_gettop(L);
    if (nargs != 2)
        return luaL_error(L, "wrong number of arguments");

    luaL_checktype(L, 1, LUA_TSTRING);
    actionname = lua_tolstring(L, 1, &len);
    if (len == 0)
        return luaL_error(L, "name must have length > 0");

    luaL_checktype(L, 2, LUA_TTABLE);

    idx = lua_upvalueindex(1);
    if (lua_isnone(L, idx))
        return luaL_error(L, "internal error -- sandbox not found");

    sandbox = (struct sandbox*)lua_touserdata(L, idx);
    if (sandbox == NULL)
        return luaL_error(L, "internal error -- invalid sandbox");

    /* TODO_ check for zero-length path */
    lua_len(L, 2);
    /* 1=action, 2=table, 3=table_len */
    tlen = lua_tointeger(L, 3);
    SANDBOX_LOG_DEBUG("table length = %ld\n", (long)tlen);
    lua_pop(L, 1);
    /* 1=action, 2=table, */
    for (tidx = 1; tidx <= tlen; tidx++) {
        SANDBOX_LOG_DEBUG("getting t[%ld]\n", (long)tidx);
        lua_geti(L, 2, tidx);
        /* 1=action, 2=table, 3=table[tidx] */
        pathname = luaL_checkstring(L, 3);
        sp = sandbox_path_create(pathname);
        SIMPLEQ_INSERT_TAIL(&pathlist, sp, path_next);
        lua_pop(L, 1);
        /* 1=action, 2=table */
    }

    SANDBOX_RULE_MAKE(&rule, "vnode", actionname, NULL);
    error = sandbox_ruleset_insert(sandbox->ruleset, &rule, 
            SANDBOX_RULETYPE_WHITELIST, 0, &pathlist);
    if (error)
        return luaL_error(L,  "internal error -- unknown");

    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

static int
sandbox_lua_paths_deny(lua_State *L)
{
    int error = 0;
    int nargs = 0;
    size_t len = 0;
    int idx = 0;
    struct sandbox_rule rule = { .names = {NULL, NULL, NULL }};
    const char *actionname = NULL;
    const char *pathname = NULL;
    lua_Integer tlen = 0;
    lua_Integer tidx = 0;
    struct sandbox_path_list pathlist;
    struct sandbox_path *sp = NULL;
    struct sandbox *sandbox = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    SIMPLEQ_INIT(&pathlist);

    nargs = lua_gettop(L);
    if (nargs != 2)
        return luaL_error(L, "wrong number of arguments");

    luaL_checktype(L, 1, LUA_TSTRING);
    actionname = lua_tolstring(L, 1, &len);
    if (len == 0)
        return luaL_error(L, "name must have length > 0");

    luaL_checktype(L, 2, LUA_TTABLE);

    idx = lua_upvalueindex(1);
    if (lua_isnone(L, idx))
        return luaL_error(L, "internal error -- sandbox not found");

    sandbox = (struct sandbox*)lua_touserdata(L, idx);
    if (sandbox == NULL)
        return luaL_error(L, "internal error -- invalid sandbox");

    /* TODO_ check for zero-length path */
    lua_len(L, 2);
    /* 1=action, 2=table, 3=table_len */
    tlen = lua_tointeger(L, 3);
    SANDBOX_LOG_DEBUG("table length = %ld\n", (long)tlen);
    lua_pop(L, 1);
    /* 1=action, 2=table, */
    for (tidx = 1; tidx <= tlen; tidx++) {
        SANDBOX_LOG_DEBUG("getting t[%ld]\n", (long)tidx);
        lua_geti(L, 2, tidx);
        /* 1=action, 2=table, 3=table[tidx] */
        pathname = luaL_checkstring(L, 3);
        sp = sandbox_path_create(pathname);
        SIMPLEQ_INSERT_TAIL(&pathlist, sp, path_next);
        lua_pop(L, 1);
        /* 1=action, 2=table */
    }

    SANDBOX_RULE_MAKE(&rule, "vnode", actionname, NULL);
    error = sandbox_ruleset_insert(sandbox->ruleset, &rule, 
            SANDBOX_RULETYPE_BLACKLIST, 0, &pathlist);
    if (error)
        return luaL_error(L,  "internal error -- unknown");

    SANDBOX_LOG_TRACE_EXIT;
    return (0);
}

static const struct luaL_Reg sandbox_lua_funcs[] = {
    {"default", sandbox_lua_default},
    {"allow", sandbox_lua_allow},
    {"deny", sandbox_lua_deny},
    {"on", sandbox_lua_on},
    {"paths_allow", sandbox_lua_paths_allow},
    {"paths_deny", sandbox_lua_paths_deny},
    {NULL, NULL}    /* sentinel */
};

static void
sandbox_lua_open(struct sandbox *sandbox)
{
    lua_State *L = NULL;

    L = sandbox->K->L;

    luaL_newlibtable(L, sandbox_lua_funcs);
    /* stack: -1 = libtbl */
    /* sandbox is an upvalue of all library functions */
    lua_pushlightuserdata(L, (void *)sandbox);
    /* stack: -2 = libtbl, -1=sandbox */
    luaL_setfuncs(L, sandbox_lua_funcs, 1);
    /* stack: -1 = libtbl */
    sandbox_lua_pushconsts(L, sandbox_lua_consts);
    /* stack: -1 = libtbl  */
    lua_setglobal(L, "sandbox");
    /* stack: */
}

int
sandbox_lua_veval(klua_State *K, int funcref, kauth_cred_t cred, 
        const struct sandbox_rule *rule, const char *fmt, va_list ap)
{
    lua_State *L = NULL;
    int result = KAUTH_RESULT_DENY;
    int type = LUA_TNIL;
    int error = 0;
    int bret = 0;
    const char *msg = NULL;
    int npushed = 0;
    int nargs = 2;  /* rule, cred */
    const char *c = NULL;
    struct vnode *vp = NULL;
    struct proc *procp = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    klua_lock(K);

    L = K->L;

    type = lua_rawgeti(L, LUA_REGISTRYINDEX, funcref); npushed++;
    /* stack: -1 = function */
    if (type != LUA_TFUNCTION) {
        SANDBOX_LOG_ERROR("expected a reference to a Lua function but got type=%s\n", 
                lua_typename(L, type));
        goto fail;
    }

    sandbox_lua_pushrule(L, rule); npushed++;
    /* stack: -2=func, -1=rule{} */
    sandbox_lua_pushcred(L, cred); npushed++;
    /* stack: -3=func, -2=rule{}, -1=cred{} */

    c = fmt;
    while (*c != '\0') {
        switch (*c) {
        case 'v':
            vp = va_arg(ap, struct vnode *);
            sandbox_lua_pushvnode(L, vp);
            npushed++;
            nargs++;
            break;
        case 'p':
            procp = va_arg(ap, struct proc *);
            sandbox_lua_pushproc(L, procp);
            npushed++;
            nargs++;
            break;
        case 'i':
            lua_pushinteger(L, va_arg(ap, lua_Integer));
            npushed++;
            nargs++;
            break;
        case 'o':
            sandbox_lua_pushsocket(L, va_arg(ap, struct socket *));
            npushed++;
            nargs++;
            break;
        case 'a':
            sandbox_lua_pushsockaddr(L, va_arg(ap, struct sockaddr *));
            npushed++;
            nargs++;
            break;
        default:
            SANDBOX_LOG_ERROR("unknown format character '%c'\n", *c);
            break;
        }
        c++;
    }

    error = lua_pcall(L, nargs, /*nresults*/ 1, /*msgh*/ 0);
    /* stack: -1=result/error
     * lua_pcall() pops the function and the function arguments, and pushes 
     * either a single result or an error
     */
    npushed -= 2; 
    if (error == LUA_OK) {
        bret = lua_toboolean(L, -1);    /* TODO: should we check that the type is actually boolean? */
        result = bret == 1 ? KAUTH_RESULT_ALLOW : KAUTH_RESULT_DENY;
    } else {
        msg = lua_tostring(L, -1);
        SANDBOX_LOG_ERROR("Lua function failed; %s\n", msg);
    }

fail:
    lua_pop(L, npushed);
    klua_unlock(K);
    SANDBOX_LOG_TRACE_EXIT;
    return (result);
}

int 
sandbox_lua_load(klua_State *K, const char *script)
{
    int error = 0;
    const char *msg = NULL;
    lua_State *L = K->L;

    SANDBOX_LOG_TRACE_ENTER;

    klua_lock(K);

    error = luaL_loadstring(L, script);
    if (error != LUA_OK) {
        /* stack: -1 = errmsg */
        msg = lua_tostring(L, -1);
        SANDBOX_LOG_ERROR("luaL_loadstring() failed; %s\n", msg);
        lua_pop(L, 1);
        error = error == LUA_ERRMEM ? ENOMEM : EINVAL;
        goto fail;
    }
    /* stack: -1 = chunk */
    error = lua_pcall(L, 0, 0, 0);
    if (error != LUA_OK)  {
        /* stack: - 1 = errmsg */
        msg = lua_tostring(L, -1);
        SANDBOX_LOG_ERROR("luaL_pcall() failed; %s\n", msg);
        lua_pop(L, 1);
        error = error == LUA_ERRMEM ? ENOMEM : EINVAL;
        goto fail;
    }

fail:
    klua_unlock(K);
    SANDBOX_LOG_TRACE_EXIT;
    return (error);
}

void
sandbox_lua_newstate(struct sandbox *sandbox)
{
    klua_State *K = NULL;

    SANDBOX_LOG_TRACE_ENTER;

    K = kluaL_newstate("sandbox", "sandbox", IPL_NONE);
    luaL_openlibs(K->L);
    sandbox->K = K;
    sandbox_lua_open(sandbox);

    SANDBOX_LOG_TRACE_EXIT;
}
