CC = gcc
CPPFLAGS += -D_GNU_SOURCE -I../src/include/
CFLAGS += -O3 -Wall
LDFLAGS += -luring-ffi

example_srcs := \
	clear_cache.c \
	multi_bench.c \
	shared.c \
	simple.c

example_targets := $(patsubst %.c,%,$(patsubst %.cc,%,$(example_srcs)))
all_targets += $(example_targets)

all: $(example_targets)

%: %.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	@rm -f $(all_targets)

.PHONY: all clean
