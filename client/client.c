#include "includes.h"
#include "socket.h"
#include "common.h"
#include "util.h"

#include <ev.h>

#define IPV4_ADDR_LEN	16
#define CLI_MSG_LEN		512
#define G_SRV_IP_ADDR	"10.0.0.1"
#define G_CONFIG_FILE	"/etc/PP2P/client.config"
#define UNIX_SOCK_PATH	"/tmp/PP2P.sock"
	
int SERVER_PORT = 49999;

//read from config file
int CLIENT_LISTEN_PORT = 60010;
int MIN_TRANS_PORT = 33000;
int MAX_TRANS_PORT = 61000;
int INTERFACE_ID = 1;
char SERVER_IP[IPV4_ADDR_LEN] = G_SRV_IP_ADDR;
char CLIENT_IP[IPV4_ADDR_LEN] = "0.0.0.0";
char CONFIG_FILE[256] = G_CONFIG_FILE;
char SHARE_DIR[256] = "empty";
unsigned int ID;

extern int errno;

struct ev_loop *loop;

void load_config_file(char *file)
{
	if(access(file, F_OK) == 0) {
		FILE *f = fopen(file, "r");
		char *line = NULL;
		size_t len = 0;
		ssize_t read;
		char id[32] = {0};
		char value[256] = {0};
		
		while((read = getline(&line, &len, f)) != -1) {
			if(line[0] == '#')
				continue;
			
			memset(id, 0, sizeof(char) * 32);
			memset(value, 0, sizeof(char) * 256);
			
			sscanf(line, "%s = %s", id, value);
			if(!strcmp(id, "CLIENT_LISTEN_PORT"))
				CLIENT_LISTEN_PORT = atoi(value);
			else if(!strcmp(id, "MIN_TRANS_PORT"))
				MIN_TRANS_PORT = atoi(value);
			else if(!strcmp(id, "MAX_TRANS_PORT"))
				MAX_TRANS_PORT = atoi(value);
			else if(!strcmp(id, "INTERFACE_ID"))
				INTERFACE_ID = atoi(value);
			else if(!strcmp(id, "SERVER_IP")) {
				memset(SERVER_IP, 0, IPV4_ADDR_LEN * sizeof(char));
				strcpy(SERVER_IP, value);
			}
			else if(!strcmp(id, "CLIENT_IP")) {
				memset(CLIENT_IP, 0, IPV4_ADDR_LEN * sizeof(char));
				strcpy(CLIENT_IP, value);
			}
			else if(!strcmp(id, "SHARE_DIR")) {
				memset(SHARE_DIR, 0, 256 * sizeof(char));
				strcpy(SHARE_DIR, value);
			}
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
	
	if(strcmp(SHARE_DIR, "empty") == 0) {
		memset(SHARE_DIR, 0, 256 * sizeof(char));
		sprintf(SHARE_DIR, "%s/Download/", cmd_system("echo $HOME"));
	}

	printf("%d %d %d %d %s %s %s\n", CLIENT_LISTEN_PORT, MIN_TRANS_PORT, MAX_TRANS_PORT, INTERFACE_ID, SERVER_IP, CLIENT_IP, SHARE_DIR);
}

void exit_save(void)
{
	//TODO: save all necessary info before exit
}

void client_exit(int para)
{ 
	//TODO:
	
	exit(1);
}

void init_var(void)
{
	//TODO: init all needed GLOBAL variables. eg: the table maintain the status of each sharing file
}

bool construct_cli_msg(char **msg, int type)
{
//TODO: construct the CLI msg...

}

void parse_cli_cmd(char *cmd)
{
//TODO:
//parse the cmd and excute it...

}

void cli_cmd_cb(EV_P_ ev_io *w, int events)
{
	ssize_t read;
	char buf[CLI_MSG_LEN] = {0};
	read = socket_read(w->fd, buf, sizeof(buf));

	if(read == 0 || read == -1) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));
		
		close(w->fd);
		ev_io_stop(loop, w);
		free(w);
		w = NULL;
		return;
	}

	parse_cli_cmd(buf);
}

void accept_cli_cb(EV_P_ ev_io *w, int events)
{
	int fd;
	fd = accept(w->fd, NULL, NULL);
	if(fd == -1) {
		if(errno != EAGAIN && errno != EWOULDBLOCK) {
			perror("accept");
			exit(-1);
		}
		return;
	}

	set_socketopt(fd);
	set_blocking(fd, false);

	ev_io *cli_client_io = (ev_io *)malloc(sizeof(ev_io));
	ev_io_init(cli_client_io, cli_cmd_cb, fd, EV_READ);
	ev_io_start(loop, cli_client_io);
}

void reply_server_cb(EV_P_ ev_io *w, int events)
{
//TODO: 1. handle if it is server reply about file ID check - start the download job
//		2. handle if it is server keepalive msg - reply client's status
	
}

void peer_req_cb(EV_P_ ev_io *w, int events)
{
//TODO: parse peer req: 1. conn req - setup data trans listening port for the peer
//					 2. keepalive msg - exchange file bitmap info
}

void accept_peer_cb(EV_P_ ev_io *w, int events)
{
	int fd;
	fd = accept(w->fd, NULL, NULL);
	if(fd == -1 &&
		errno != EAGAIN &&
		errno != EWOULDBLOCK) {
		printf("peer accept error: %s\n", strerror(errno));
		return;
	}

	set_socketopt(fd);
	set_blocking(fd, false);

	ev_io *peer_listen_io = (ev_io *)malloc(sizeof(ev_io));
	ev_io_init(peer_listen_io, peer_req_cb, fd, EV_READ);
	ev_io_start(loop, peer_listen_io);
}

void check_fileID(int fd, char *id)
{
	//TODO: just send chekc_fileID req to server
}

void download_file(char *file_id)
{
	if(check_pidfile("PP2P_client") == false) {
	//tell client daemon what job needs to do by UNIX socket. Once the client daemon receives the request it will fork a new process to handle the job
		int cli_fd = open_unix_socket_out(UNIX_SOCK_PATH);
		char *cli_msg;
		
		if(construct_cli_msg(&cli_msg, 0/*new download*/) == false)
			abort();
		
		if(socket_write(cli_fd, cli_msg, strlen(cli_msg)) <= 0)
			perror("failed to start a new job");
		
		close(cli_fd);
		free(cli_msg);
		exit(0);
	}
	else {
	//setup the client daemon with cli module
		loop = EV_DEFAULT;

		CatchSignal(SIGTERM, client_exit);
		BlockSignals(false, SIGTERM);
		BlockSignals(true,SIGPIPE);

		init_var();

		daemon(1, 1);

		int clientCLI_fd;
		ev_io cli_io;
		clientCLI_fd = open_unix_socket_in(UNIX_SOCK_PATH);
		ev_io_init(&cli_io, accept_cli_cb, clientCLI_fd, EV_READ);
		ev_io_start(loop, &cli_io);

		int client2srv_fd;
		ev_io csrv_io;
		client2srv_fd = open_socket_out(SERVER_PORT, SERVER_IP);
		ev_io_init(&csrv_io, reply_server_cb, client2srv_fd, EV_READ);
		ev_io_start(loop, &csrv_io);
	
		int p2p_listen_fd;
		ev_io plisten_io;
		p2p_listen_fd = open_socket_in(CLIENT_LISTEN_PORT, CLIENT_IP); 
		ev_io_init(&plisten_io, accept_peer_cb, p2p_listen_fd, EV_READ);
		ev_io_start(loop, &plisten_io);

		check_fileID(client2srv_fd, file_id);

		ev_run(loop, 0);
	}
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
