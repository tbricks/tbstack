CC = gcc
CPPFLAGS = -D_XOPEN_SOURCE -D_GNU_SOURCE
CFLAGS = -O2

BINDIR = /usr/bin

LIBUNWIND_LDFLAGS += -lunwind -lunwind-generic -lunwind-x86_64

ifneq ($(LIBUNWIND_DIR),)
LIBUNWIND_CPPFLAGS = -I$(LIBUNWIND_DIR)/include
LIBUNWIND_LDFLAGS += -L$(LIBUNWIND_DIR)/lib
endif

ifneq ($(NO_LIBUNWIND_PTRACE),1)
LIBUNWIND_LDFLAGS += -lunwind-ptrace
else
CPPFLAGS += -DNO_LIBUNWIND_PTRACE
endif

CPPFLAGS += $(LIBUNWIND_CPPFLAGS)
LDFLAGS = -lelf $(LIBUNWIND_LDFLAGS)

DEPS = $(wildcard src/*.h)
SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)

src/%.o: %.c $(DEPS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

tbstack: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

all: tbstack

install: all
	install tbstack $(BINDIR)/

clean:
	rm -f $(OBJECTS) tbstack
