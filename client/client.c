#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>

#define IPV4_ADDR_LEN	16
#define G_SRV_IP_ADDR	"10.0.0.1"
#define G_CONFIG_FILE	"/etc/PP2P/client.config"
	
int SERVER_PORT = 49999;

//read from config file
int CLIENT_LISTEN_PORT = 60010;
int MIN_TRANS_PORT = 33000;
int MAX_TRANS_PORT = 61000;
int INTERFACE_ID = 1;
char SERVER_IP[IPV4_ADDR_LEN] = G_SRV_IP_ADDR;
char CLIENT_IP[IPV4_ADDR_LEN] = "0.0.0.0";
char CONFIG_FILE[256] = G_CONFIG_FILE;

//get all the interfaces' ip address
int getlocalip(char outip[][IPV4_ADDR_LEN])
{
	int i = 0, res = -1, n = 0;
	int sockfd;
	struct ifconf ifconf;
	char buf[512];
	struct ifreq *ifreq;
	char* ip;

	ifconf.ifc_len = 512;
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

void load_config_file(char *file)
{
	if(access(file, F_OK) == 0) {
		FILE *f = fopen(file, "r");
		char *line = NULL;
		size_t len = 0;
		ssize_t read;
		char id[32] = {0};
		char value[128] = {0};
		
		while((read = getline(&line, &len, f)) != -1) {
			if(line[0] == '#')
				continue;
			
			memset(id, 0, sizeof(char) * 32);
			memset(value, 0, sizeof(char) * 128);
			
			sscanf(line, "%s = %s", id, value);
			if(!strcmp(id, "CLIENT_LISTEN_PORT"))
				CLIENT_LISTEN_PORT = atoi(value);
			else if(!strcmp(id, "MIN_TRANS_PORT"))
				MIN_TRANS_PORT = atoi(value);
			else if(!strcmp(id, "MAX_TRANS_PORT"))
				MAX_TRANS_PORT = atoi(value);
			else if(!strcmp(id, "INTERFACE_ID"))
				INTERFACE_ID = atoi(value);
			else if(!strcmp(id, "SERVER_IP"))
				strcpy(SERVER_IP, value);
			else if(!strcmp(id, "CLIENT_IP"))
				strcpy(CLIENT_IP, value);
			else
				printf("unknown parameter: %s\n", id);
		}
		
		free(line);
		fclose(f);
	}

	if(strcmp(CLIENT_IP, "0.0.0.0") == 0) {
		char _ip[16][IPV4_ADDR_LEN];
		
		if(getlocalip(_ip) > 0)
			strcpy(CLIENT_IP, _ip[INTERFACE_ID - 1]);
		else {
			printf("no ip usable\n");
			exit(-1);
		}
	}

	printf("%d %d %d %d %s %s\n", CLIENT_LISTEN_PORT, MIN_TRANS_PORT, MAX_TRANS_PORT, INTERFACE_ID, SERVER_IP, CLIENT_IP);
}

void show_usage(void)
{
	printf( "-i [1 ~ n]: specify which interface you want to use for data transmission\n"
		"-c [config file]: give the abs path of the customized config file\n"
		"-L: show the current sharing files on P2P networks\n"
		"-D [file ID]: download a file\n"
		"-R [file]: restore the file download work\n"
		"-S [file]: share the file on P2P networks\n"
		"-h: show usage\n");
}

void show_shared_files(void)
{
//TODO:
//
/*test:*/	
//	load_config_file(CONFIG_FILE);
}

void download_file(char *file_id)
{
//TODO:
}

void restore_download(char *file_path)
{
//TODO:
}

void start_sharing_file(char *file_path)
{
//TODO
}

int main(int argc, char *argv[])
{
	extern char *optarg;
	int opt;
	
	while(argc > 1 && (*argv[1] != '-')) {
		argv++;
		argc--;
	}
	
	while(EOF != (opt = getopt(argc, argv, "i:LD:R:S:c:h")))	
		switch (opt)  {
		case 'i':
			INTERFACE_ID = atoi(optarg);
			break;
			
		case 'h':
			show_usage();
			break;

		case 'L':
			show_shared_files();
			break;

		case 'D':
			download_file(optarg);
			break;

        	case 'R':
			if(access(optarg, F_OK)) {
				printf("file: %s does not exist\n", optarg);
				exit(-1);
			}

			restore_download(optarg);
			break;
			
		case 'S':
			if(access(optarg, F_OK)) {
				printf("file: %s does not exist\n", optarg);
				exit(-1);
			}

			start_sharing_file(optarg);
			break;
			
		case 'c':
			if(access(optarg, F_OK)) {
				printf("file: %s does not exist\n", optarg);
				exit(-1);
			}

			memset(CONFIG_FILE, 0, 256 * sizeof(char));
			strcpy(CONFIG_FILE, optarg);
			break;

		default:
			printf("Incorrect program usage. Use -h to show help\n");
			exit(1);
		}
		
	return 0;
}
