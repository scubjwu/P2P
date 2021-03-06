#ifndef _INCLUDES_H
#define _INCLUDES_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#define IPV4_ADDR_LEN	16
#define MD5_LEN			32
#define CLI_MSG_LEN		512
#define DATA_LEN			0xFFFF
#define MAGIC_NUM		0xD21BB

#define _expect_false(expr)		__builtin_expect(!!(expr), 0)
#define _expect_true(expr)		__builtin_expect(!!(expr), 1)
#define expect_false(cond)		_expect_false(cond)
#define expect_true(cond)		_expect_true(cond)
#define prefetch(x) 			__builtin_prefetch(x)
#define offsetof(a,b)			__builtin_offsetof(a,b)

#define container_of(ptr, type, member) ({				\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

#define _free(x)	\
{				\
	if(x)	free(x);	\
}

#endif

