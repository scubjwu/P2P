#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "common.h"

void BlockSignals(bool block, int signum)
{
  	sigset_t set;
	
  	sigemptyset(&set);
  	sigaddset(&set, signum);
  	sigprocmask(block?SIG_BLOCK:SIG_UNBLOCK, &set, NULL);
}

signal_handler_fn CatchSignal(int signum, signal_handler_fn handler)
{
	struct sigaction act;
	struct sigaction oldact;

	memset(&act, 0, sizeof(act));

	act.sa_handler = handler;
	
#ifdef SA_RESTART
	if(signum != SIGALRM)
		act.sa_flags |= SA_RESTART;
#endif

	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signum);
	sigaction(signum, &act, &oldact);
	
	return oldact.sa_handler;
}

int set_blocking(int fd, bool set)
{
	int val;

	if((val = fcntl(fd, F_GETFL, 0)) == -1)
		return -1;
		
	if(set) /* Turn blocking on - ie. clear nonblock flag */
		val &= ~O_NONBLOCK;
	else
		val |= O_NONBLOCK;
	
	return fcntl( fd, F_SETFL, val);
}