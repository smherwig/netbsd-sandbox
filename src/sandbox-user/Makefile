CC= gcc
CFLAGS= -ggdb -Wall
CPPFLAGS=

AR= ar rcu
RANLIB= ranlib
RM= rm -f

# user-space sandbox library
SANDBOX_LIB= libsandbox.a
SANDBOX_LIB_OBJS= sandbox.o

# sandbox-exec program
SANDBOX_EXEC= sandbox-exec
SANDBOX_EXEC_OBJS= sandbox-exec.o

# sandbox-stats program
SANDBOX_STATS= sandbox-stats
SANDBOX_STATS_OBJS= sandbox-stats.o

# sblua program
SBLUA= sblua
SBLUA_OBJS= sblua.o

all: $(SANDBOX_LIB) $(SANDBOX_EXEC) $(SANDBOX_STATS) $(SBLUA)

$(SANDBOX_LIB): $(SANDBOX_LIB_OBJS)
	$(AR) $@ $(SANDBOX_LIB_OBJS)
	$(RANLIB) $@

$(SANDBOX_EXEC): $(SANDBOX_EXEC_OBJS)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(SANDBOX_EXEC_OBJS) $(SANDBOX_LIB)

$(SANDBOX_STATS): $(SANDBOX_STATS_OBJS)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(SANDBOX_STATS_OBJS) $(SANDBOX_LIB)

$(SBLUA): $(SBLUA_OBJS)
	$(CC) -o $@ $(CPPGLAGS) $(CFLAGS) $(SBLUA_OBJS) $(SANDBOX_LIB) -llua

clean:
	$(RM) $(SANDBOX_LIB) $(SANDBOX_LIB_OBJS) $(SANDBOX_EXEC) $(SANDBOX_EXEC_OBJS) \
		$(SANDBOX_STATS) $(SANDBOX_STATS_OBJS) $(SBLUA) $(SBLUA_OBJS)

.PHONY: all lib

