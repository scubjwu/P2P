#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/un.h>
#include <netinet/in.h>

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))

struct
{
	char *name;
	int level;
	int option;
	int value;
} socket_options[] = {
	{"SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE, 1},
	{"SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR, 1},
#ifdef TCP_NODELAY
	{"TCP_NODELAY", IPPROTO_TCP, TCP_NODELAY, 1},
#endif
#ifdef IPTOS_LOWDELAY
	{"IPTOS_LOWDELAY", IPPROTO_IP, IP_TOS, IPTOS_LOWDELAY},
#endif
#ifdef IPTOS_THROUGHPUT
	{"IPTOS_THROUGHPUT", IPPROTO_IP, IP_TOS, IPTOS_THROUGHPUT},
#endif
#ifdef SO_SNDBUF
	{"SO_SNDBUF", SOL_SOCKET, SO_SNDBUF, 65535},
#endif
#ifdef SO_RCVBUF
	{"SO_RCVBUF", SOL_SOCKET,    SO_RCVBUF, 65535},
#endif
	{NULL, 0, 0, 0}
};

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

void set_socketopt(int fd)
{
	int i, ret = 0;
	for(i = 0; i < ARRAY_SIZE(socket_options); i++) {
		if(socket_options[i].name == NULL)
			break;
			
		ret = setsockopt(fd, socket_options[i].level,
					socket_options[i].option, 
					(char *)&(socket_options[i].value), 
					sizeof(int));
		
		if(ret != 0) {
			perror("set socket option error");
			exit(1);
		}
	}
}

int open_unix_socket_in(char *path) 
{
	int sfd;
	struct sockaddr_un unix_sock;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (-1 == sfd) {
		perror("socket error");
		exit(1);
	}
	unlink(path);

	unix_sock.sun_family = AF_UNIX;
	strcpy(unix_sock.sun_path, path);
	
	if(bind(sfd, (const struct sockaddr *)&unix_sock, (socklen_t)sizeof(unix_sock)) == -1 ) {
		perror("bind error");
		exit(1); 
	}
	
	set_socketopt(sfd);
	set_blocking(sfd, false);
	
	if (listen(sfd, 50) == -1) {
		perror("listen error");
		exit(1);
	}
	
	return sfd;
}

int open_socket_in(int port, char *ip_addr)
{
	int sfd;
	struct sockaddr_in addr;
	
	if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket error");
		exit(1);
	}
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port=htons(port);
	addr.sin_addr.s_addr = inet_addr(ip_addr);
	
	if(bind(sfd, (const struct sockaddr *)&addr, (socklen_t)sizeof(addr)) == -1 ) {
		perror("bind error");
		exit(1); 
	}
	
	set_socketopt(sfd);
	set_blocking(sfd, false);
	
	if (listen(sfd, 50) == -1) {
		perror("listen error");
		exit(1);
	}
	
	return sfd;
}

int open_unix_socket_out(const char *path)
{
	int sfd;
	struct sockaddr_un unix_sock;
	
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (-1 == sfd) {
		perror("socket error");
		exit(1);
	}

	bzero(&unix_sock, sizeof(unix_sock));
	unix_sock.sun_family = AF_UNIX;
	strcpy(unix_sock.sun_path, path);

	if(connect(sfd, (struct sockaddr *)&unix_sock, (socklen_t)sizeof(unix_sock)) < 0) {
		perror("connect error");
		exit(1);
	}
	
	set_socketopt(sfd);
	set_blocking(sfd, false);

	return sfd;
}

int open_socket_out(int port, char *ip_addr)
{
	int sfd;
	struct sockaddr_in addr;
	
	if((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket error");
		exit(1);
	}
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip_addr);
	
	if(connect(sfd, (const struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
		perror("connect error");
		exit(1);
	}
	
	set_socketopt(sfd);
	set_blocking(sfd, false);
	
	return sfd;
}

static ssize_t real_recv(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do
		ret = read(fd, buf, count);
	while (ret == -1 && 
			(errno == EINTR || 
			errno == EAGAIN));

	return ret;
}

ssize_t socket_read(int fd, char *buff, size_t len)
{
	size_t total = 0;  
  	ssize_t  ret;

  	while (total < len)
    {
      	ret = real_recv(fd, buff + total, len - total);

		/* ret == 0 means the other end is closed. 
		 * ret == -1 means recv error.
		*/
      	if(ret == 0 || ret == -1)
			return ret;
			
      	total += ret;
    }
	
  	return total;
}

static ssize_t real_send(int fd, void *buf, size_t count)
{
	ssize_t ret;

	do
		ret = write(fd, buf, count);
	while (ret == -1 && 
			(errno == EINTR || 
			errno == EAGAIN));
	
	return ret;
}

ssize_t socket_write(int fd, char *buffer, size_t len)
{
	size_t total = 0;
	ssize_t ret;

	while (total < len)
	{
		ret = real_send(fd, buffer + total, len - total);

		if(ret == 0 || ret == -1)
			return ret;

		total += ret;
    }
	return total;
}
