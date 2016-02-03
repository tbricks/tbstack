AM_CPPFLAGS = -Wall -Wextra

bin_PROGRAMS = tbstack
tbstack_SOURCES = \
	src/tbstack.c \
	src/backtrace.h \
	src/backtrace.c \
	src/mem_map.h \
	src/mem_map.c \
	src/proc.h \
	src/proc.c \
	src/snapshot.h \
	src/snapshot.c \
	src/unwind.c

tbstack_CFLAGS = $(AM_CFLAGS) $(LIBUNWIND_CFLAGS)
tbstack_LDADD = $(LIBUNWIND_LIBS)

EXTRA_DIST = LICENSE
