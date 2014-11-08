#ifndef _COMMON_H
#define _COMMON_H

typedef void (*signal_handler_fn) (int);

#define _expect_false(expr)		__builtin_expect(!!(expr), 0)
#define _expect_true(expr)		__builtin_expect(!!(expr), 1)
#define expect_false(cond)		_expect_false(cond)
#define expect_true(cond)		_expect_true(cond)

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

void BlockSignals(bool block, int signum);
signal_handler_fn CatchSignal(int signum, signal_handler_fn handler);
int set_blocking(int fd, bool set);

#endif

