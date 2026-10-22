CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2
LDFLAGS ?=
LDLIBS ?= -lcrypt -lutil

.PHONY: all clean debug
all: lxc-dashboard

lxc-dashboard: src/main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

debug:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined" lxc-dashboard

clean:
	rm -f lxc-dashboard
