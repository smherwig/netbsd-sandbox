CC= gcc 
CFLAGS=-ggdb -Wall
CPPFLAGS= -I$(HOME)/include -I$(PWD)

AR= ar rcu
RANLIB= ranlib
RM= rm -f

# mock system library
MSYS_LIB= libmsys.a
MSYS_OBJS= klua.o kmem.o kern_kauth.o atomic.o systm.o
MSYS_HEADERS= msys/kauth.h msys/lua.h msys/proc.h msys/queue.h msys/vnode.h \
			  msys/atomic.h msys/systm.h

# user-space sandbox module
SANDBOX_LIB= libsandbox.a
SANDBOX_OBJS= sandbox.o sandbox_lua.o sandbox_path.o \
		  sandbox_ref.o sandbox_rule.o sandbox_ruleset.o
SANDBOX_HEADERS= sandbox.h sandbox_lua.h sandbox_path.h sandbox_rule.h \
				 sandbox_ruleset.h

# test program
TEST= test_libsandbox
TEST_OBJS= test_libsandbox.o suite_rule.o suite_ruleset.o suite_lua.o suite_sandbox.o test_util.o
TEST_HEADERS= suite_rule.h suite_ruleset.h suite_lua.h suite_sandbox.h test_util.h

# debug utilities
DEBUG_HEADERS= sandbox_log.h

# additional dependencies
LIBCUNIT= $(HOME)/lib/libcunit.a
LIBLUA= $(HOME)/lib/liblua.a

ALL_HEADERS= $(MSYS_HEADERS) $(SANDBOX_HEADERS) $(TEST_HEADERS) $(DEBUG_HEADERS)

all: $(MSYS_LIB) $(SANDBOX_LIB) $(TEST)

$(MSYS_LIB) : $(MSYS_OBJS)
	$(AR) $@ $(MSYS_OBJS)
	$(RANLIB) $@

$(SANDBOX_LIB) : $(SANDBOX_OBJS)
	$(AR) $@ $(SANDBOX_OBJS)
	$(RANLIB) $@

$(TEST): $(TEST_OBJS) $(SANDBOX_LIB) $(MSYS_LIB)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(TEST_OBJS) $(SANDBOX_LIB) $(MSYS_LIB) $(LIBLUA) $(LIBCUNIT) -ldl -lm

# mock system library objects
klua.o: klua.c msys/lua.h
kmem.o: kmem.c msys/kmem.h
kern_kauth.o: kern_kauth.c msys/kauth.h

# user-space sandbox module objects 
sandbox.o: sandbox.c sandbox.h sandbox_lua.h sandbox_rule.h sandbox_ruleset.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
sandbox_lua.o: sandbox_lua.c sandbox.h sandbox_lua.h sandbox_rule.h sandbox_ruleset.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
sandbox_path.o: sandbox_path.c sandbox_path.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
sandbox_ref.o: sandbox_ref.c sandbox_ref.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
sandbox_rule.o: sandbox_rule.c sandbox_rule.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
sandbox_ruleset.o: sandbox_ruleset.c sandbox_path.h sandbox_rule.h sandbox_ruleset.h $(DEBUG_HEADERS) $(MSYS_HEADERS)

# test objects
test_libsandbox.o: test_libsandbox.c $(ALL_HEADERS)
test_util.o: test_util.c sandbox_path.h test_util.h
suite_lua.o: suite_lua.c sandbox.h sandbox_lua.h sandbox_rule.h sandbox_ruleset.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
suite_rule.o: suite_rule.c sandbox_rule.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
suite_ruleset.o: suite_ruleset.c sandbox_path.h sandbox_rule.h suite_ruleset.h $(DEBUG_HEADERS) $(MSYS_HEADERS)
suite_sandbox.o: suite_sandbox.c sandbox.h $(DEBUG_HEADERS) $(MSYS_HEADERS)

clean:
	$(RM) $(MSYS_LIB) $(MSYS_OBJS) $(SANDBOX_LIB) $(SANDBOX_OBJS) $(TEST) $(TEST_OBJS)

.PHONY: all lib test clean
