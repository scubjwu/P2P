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

#define IPV4_ADDR_LEN	16

char *cmd_system(const char *cmd)
{
#define BUFLEN	512
	static char buf[BUFLEN];
	char *res = "";
	char tmp[BUFLEN] = {0};
	FILE *f;

	f = popen(cmd, "r");
	while(fgets(tmp, BUFLEN - 1, f) != NULL)
		;

	if(f != NULL)
		pclose(f);

	//delete the \n ending char
	memset(buf, 0, BUFLEN * sizeof(char));
	memcpy(buf, tmp, strlen(tmp) - 1);
	res = buf;

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

void pidfile_create(char *name)
{
	int fd;
	char pidFile[512] = {0};
	char buf[32] = {0};

	sprintf(pidFile, "%s/%s.pid", cmd_system("echo $HOME"), name);
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
}

bool check_pidfile(char *name)
{
	char pidFile[512] = {0};
	pid_t pid;

	sprintf(pidFile, "%s/%s.pid", cmd_system("echo $HOME"), name);
	pid = pidfile_pid(pidFile);
	if (pid != 0) {
		printf("%s(pid: %d) is already running\n", name, pid);
		return false;
	}
	
	return true;
}

//get all the interfaces' ip address
int getlocalip(char outip[][IPV4_ADDR_LEN])
{
	int i = 0, res = -1, n = 0;
	int sockfd;
	struct ifconf ifconf;
	char buf[512];
	struct ifreq *ifreq;
	char* ip;

	ifconf.ifc_len = sizeof(buf);
	ifconf.ifc_buf = buf;

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	ioctl(sockfd, SIOCGIFCONF, &ifconf);
	close(sockfd);

	ifreq = (struct ifreq *)buf;
	for(i=(ifconf.ifc_len/sizeof(struct ifreq)); i>0; i--)
	{
		ip = inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr);
		ifreq++;
		
		if(strcmp(ip, "127.0.0.1")==0)
			continue;

		strcpy(outip[n++],ip);
		res = n;
	}

	return res;
}

unsigned int BKDRHash(char *str)
{
	unsigned int seed = 131;
	unsigned int hash = 0;

	while(*str)
		hash = hash * seed + (*str++);

	return (hash & 0x7FFFFFFF);
}

//use MAC addr to generate client ID
unsigned int getclientID(void)
{
    int fd, interface;
    struct ifreq buf[16];
    struct ifconf ifc;
    char mac[32] = {0};

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        int i = 0;
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = (caddr_t)buf;
        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            interface = ifc.ifc_len / sizeof(struct ifreq);
            while (i < interface)
            {
                if (!(ioctl(fd, SIOCGIFHWADDR, (char *)&buf[i])))
                {
                    sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        (unsigned char)buf[i].ifr_hwaddr.sa_data[0],
                        (unsigned char)buf[i].ifr_hwaddr.sa_data[1],
                        (unsigned char)buf[i].ifr_hwaddr.sa_data[2],
                        (unsigned char)buf[i].ifr_hwaddr.sa_data[3],
                        (unsigned char)buf[i].ifr_hwaddr.sa_data[4],
                        (unsigned char)buf[i].ifr_hwaddr.sa_data[5]);
		    
		    if(strcmp(mac, "00:00:00:00:00:00")) {
			close(fd);
			return BKDRHash(mac);
		    }
                }
                i++;
            }
        }
    }

    close(fd);
    return 0;
}


/*
//test
int main(void)
{
	printf("%d\n", getclientID());
	
	return 0;
}
*/
