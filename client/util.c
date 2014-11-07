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

char *cmd_system(const char *cmd)
{
#define BUFLEN	512
	char *res = "";
	static char buf[BUFLEN];
	FILE *f;
	
	f = popen(cmd, "r");
	memset(buf, 0, BUFLEN * sizeof(char));
	while(fgets(buf, BUFLEN - 1, f) != NULL)
		res = buf;

	if(f != NULL)
		pclose(f);

	return res;
#undef BUFLEN
}

bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type)
{
	struct flock lock;
	int ret;

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = offset;
	lock.l_len = count;
	lock.l_pid = 0;

	ret = fcntl(fd, op, &lock);
    
/* a lock query */
	if(op == F_GETLK) {
		if ((ret != -1) &&
			(lock.l_type != F_UNLCK) && 
			(lock.l_pid != 0) && 
			(lock.l_pid != getpid()))
			return true;

		return false;
	}
	
	if(ret == -1)
		return false;

	return true;
}

bool process_exists(pid_t pid)
{
	return (kill(pid, 0) == 0 || errno != ESRCH);
}

pid_t pidfile_pid(char *pidFile)
{
	int fd;
	char pidstr[32] = {0};
	int ret;

	fd = open(pidFile, O_NONBLOCK | O_RDWR, 0644);
	if (fd == -1)
		return 0;

	if (read(fd, pidstr, sizeof(pidstr) - 1) <= 0)
		goto ok;

	ret = atoi(pidstr);
	
	if (!process_exists((pid_t)ret))
		goto ok;

	if (fcntl_lock(fd, F_SETLK, 0, 1, F_WRLCK))
		goto ok; /* we could get the lock - it can't be a Samba process */

	close(fd);
	return (pid_t)ret;

 ok:
	close(fd);
	unlink(pidFile);
	return 0;
}

bool pidfile_setup(char *name)
{
	int fd;
	char buf[32] = {0};
	char pidFile[512] = {0};
	char rdir[512] = {0};
	char *tmp = cmd_system("echo $HOME");
	pid_t pid;

	memcpy(rdir, tmp, strlen(tmp) - 1);
	sprintf(pidFile, "%s/%s.pid", rdir, name);

	pid = pidfile_pid(pidFile);
	if (pid != 0) {
		printf("%s(pid: %d) is already running\n", name, pid);
		return false;
	}

	fd = open(pidFile, O_NONBLOCK | O_CREAT | O_WRONLY | O_EXCL, 0644);
	if(fd == -1) {
		perror("open");
		exit(1);
	}

	if(fcntl_lock(fd, F_SETLK, 0, 1, F_WRLCK)==false) {
		perror("fcntl_lock");
		exit(1);
	}

	sprintf(buf, "%d\n", getpid());
	if(write(fd, buf, sizeof(buf)) != sizeof(buf)) {
		perror("write");
		exit(1);
	}
	/* Leave pid file open & locked for the duration... */
	
	return true;
}

/*
//test
int main(void)
{
	if(pidfile_setup("test") == false) {
		printf("already running\n");
		return -1;
	}
	
	for(;;) {}
}
*/

