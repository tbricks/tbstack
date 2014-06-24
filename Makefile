CC = gcc
CFLAGS = -D_XOPEN_SOURCE -D_GNU_SOURCE -O2 -I/export/home/nvs/tools/include
LDFLAGS = -lelf -lunwind-generic -lunwind-ptrace -L/export/home/nvs/tools/lib

DEPS = $(wildcard src/*.h)
SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)

src/%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

tbstack: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

all: tbstack

clean:
	rm -f $(OBJECTS) tbstack
