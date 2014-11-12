#ifndef _UTIL_H
#define _UTIL_H

char *cmd_system(const char *cmd);
bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type);
bool process_exists(pid_t pid);
pid_t pidfile_pid(char *pidFile);
void pidfile_create(char *name);
bool check_pidfile(char *name);
int getlocalip(char outip[][IPV4_ADDR_LEN]);
unsigned int BKDRHash(char *str);
unsigned int getclientID(void);


#endif

