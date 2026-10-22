CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2
LDFLAGS ?=
LDLIBS ?= -lcrypt -lutil

.PHONY: all clean debug
all: lxc-dashboard

lxc-dashboard: src/main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

debug: CFLAGS = -O1 -g -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer
debug: LDFLAGS = -fsanitize=address,undefined
debug: clean lxc-dashboard

clean:
	rm -f lxc-dashboard
