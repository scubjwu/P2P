#ifndef _COMMON_H
#define _COMMON_H

typedef void (*signal_handler_fn) (int);

void BlockSignals(bool block, int signum);
signal_handler_fn CatchSignal(int signum, signal_handler_fn handler);
int set_blocking(int fd, bool set);

#endif

