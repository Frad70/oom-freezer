CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

.PHONY: all test test-live clean
all: oom-freezer

oom-freezer: oom-freezer.c util.c util.h
	$(CC) $(CFLAGS) -o oom-freezer oom-freezer.c util.c

test-freezer: test_freezer.c oom-freezer.c util.c util.h
	$(CC) $(CFLAGS) -o test-freezer test_freezer.c util.c

test: test-freezer
	./test-freezer

test-live:
	python3 tests/test_freeze_live.py

clean:
	rm -f oom-freezer test-freezer
