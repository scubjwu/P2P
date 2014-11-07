#include <stdbool.h>

int set_blocking(int fd, bool set);
void set_socketopt(int fd);
int open_unix_socket_in(char *path) ;
int open_socket_in(int port, char *ip_addr);
int open_unix_socket_out(const char *path);
int open_socket_out(int port, char *ip_addr);
ssize_t socket_read(int fd, char *buff, size_t len);
ssize_t socket_write(int fd, char *buffer, size_t len);

