#include "includes.h"
#include <ev.h>

#include "socket.h"
#include "common.h"
#include "util.h"
#include "list.h"
#include "fifo.h"

#include "client.h"
	
int SERVER_PORT = 49999;
double VERSION = 0.01;

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
struct pmsg_t P2P_MSG_OUT;
struct pmsg_t P2P_MSG_IN;
struct list_head JOBS;

extern int errno;

struct ev_loop *loop;

#define ev_fd_close(watcher)	\
{							\
	close((watcher)->fd);		\
	ev_io_stop(loop, watcher);	\
}

#define _free(x)	\
{				\
	if(x)	free(x);	\
}

int file_check_fn(EV_P_ ev_io *w);
int server_keepalive_fn(EV_P_ ev_io *w);

struct msg_handle_fn {
	char *name;
	int (* func) ();
}
msg_fns[3] = {

/*0x00*/		{NULL, NULL},
/*0x01*/		{"filecheck", file_check_fn},
/*0x02*/		{"srvkeepalive", server_keepalive_fn}
//TODO:
};

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
	ID = getclientID();

	P2P_MSG_OUT.magic = MAGIC_NUM;
	P2P_MSG_OUT.version = VERSION;
	P2P_MSG_OUT.cid = ID;

	INIT_LIST_HEAD(&JOBS);
}

void check_fileID(int fd, char *fid)
{
	P2P_MSG_OUT.type = 0x01;
	P2P_MSG_OUT.len = strlen(fid);
	strcpy(P2P_MSG_OUT.content, fid);

	if(socket_write(fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0)
		perror("failed to connect to server.\n");
}

void start_new_download(int fd, char *cmd)
{
	check_fileID(fd, cmd);
}

void parse_cli_cmd(int fd, unsigned type, char *cmd)
{
//parse the cmd and excute it...
	switch (type) {
	case 0:
		start_new_download(fd, cmd);
		break;
	//TODO: add new cli msg to be parsed here
	
	default:
		printf("error cli msg\n");
		break;
	}
}

void cli_cmd_cb(EV_P_ ev_io *w, int events)
{
	ssize_t read;
	struct cli_cmd_t data;
	size_t cli_head_len = cli_cmd_header_len;
	
	read = socket_read(w->fd, (char *)&data, cli_head_len);
	if(read != cli_head_len) {
		ev_fd_close(w);
		_free(w);
		return;
	}

	read = socket_read(w->fd, data.cmd, data.len);
	if(read == 0 || read == -1) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));
		
		ev_fd_close(w);
		_free(w);
		return;
	}

	parse_cli_cmd(w->fd, data.type, data.cmd);
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

void peerinfo_cb(EV_P_ ev_io *w, int events)
{
//handle incoming msg on client listening port
	ssize_t read;
	size_t len = msg_header_len;
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len ||
		P2P_MSG_IN.magic != MAGIC_NUM ||
		P2P_MSG_IN.cid != ID ||
		P2P_MSG_IN.len == 0) {
		ev_fd_close(w);
		return;
	}

	int dlen = P2P_MSG_IN.len;	
	char data[dlen];
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));
		
		ev_fd_close(w);
		return;
	}
	
	char file_id[MD5_LEN] = {0};
	memcpy(file_id, data, MD5_LEN);

	unsigned int msg_type;
	memcpy(&msg_type, data + MD5_LEN, sizeof(unsigned int));

	if(msg_type == 1 /*conn rep msg*/) {
//TODO:
	}
	else if(msg_type == 2 /*peer keepalive msg*/) {
//TODO:
	}
}

void peer_keepalive(EV_P_ ev_timer *w, int events)
{
//send keepalive msg to peer
	struct peer_info_t *ptr;
	ptr = container_of(w, struct peer_info_t, peerinfo_timer);
	struct download_job_t *job = ptr->job;

	if(ptr->alive > KEEPALIVE_TIMEOUT) {
//TODO: if the value of ptr->alive is higher than KEEPALIVE_TIMEOUT, we need to remove this peer	
	}
	
	P2P_MSG_OUT.type = 0x04;
	P2P_MSG_OUT.len = MD5_LEN + job->map_len;
	
	char *p = P2P_MSG_OUT.content;
	memcpy(p, job->file_id, MD5_LEN);
	memcpy(p + MD5_LEN, job->file_map, job->map_len);

	ptr->alive++;
	if(socket_write(ptr->peerinfo_io.fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		ev_fd_close(&(ptr->peerinfo_io));
		return;
	}
}

void build_peer_connreq(char *fid, char *file_map)
{
	int map_len = strlen(file_map);
	P2P_MSG_OUT.type = 0x03;
	P2P_MSG_OUT.len = MD5_LEN + map_len;

	char *p = P2P_MSG_OUT.content;
	memcpy(p, fid, MD5_LEN);
	memcpy(p + MD5_LEN, file_map, map_len);
}

void init_peer_conn(EV_P_ struct peer_list_t peer, char *fid, struct download_job_t *job)
{
	int peerinfo_fd;
	
	//TODO: need to use ICE to setup peer socket fd!!!
	peerinfo_fd = open_socket_out(peer.port, peer.ip);
	if(peerinfo_fd == -1)
		return;

	struct peer_info_t *ptr = (struct peer_info_t *)malloc(sizeof(struct peer_info_t));

	ptr->job = job;
	ptr->peer_id = peer.cid;
	ptr->peer_filemap = NULL;
	ptr->alive = 0;
	
	ev_io_init(&(ptr->peerinfo_io), peerinfo_cb, peerinfo_fd, EV_READ);
	ev_io_start(loop, &(ptr->peerinfo_io));

	build_peer_connreq(fid, job->file_map);
	if(socket_write(peerinfo_fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		perror("failed to make connection with peer.\n");
		ev_fd_close(&(ptr->peerinfo_io));
		_free(ptr);
		return;
	}

	ev_timer_init(&(ptr->peerinfo_timer), peer_keepalive, PEER_KEEPALIVE_TINTER, PEER_KEEPALIVE_TINTER);
	ev_timer_start(loop, &(ptr->peerinfo_timer));

	list_add(&(ptr->list), &(job->peer_list));
}

void build_csrv_keepalive(char *fid)
{
	P2P_MSG_OUT.type = 0x02;
	P2P_MSG_OUT.len = 0;

	//get the file bitmap
	struct download_job_t *ptr;
	list_for_each_entry(ptr, &JOBS, list) {
		if(strcmp(ptr->file_id, fid) == 0) {
			P2P_MSG_OUT.len = ptr->map_len;
			strcpy(P2P_MSG_OUT.content, ptr->file_map);
			break;
		}
	}
}

struct download_job_t *find_job(char *fid)
{
	struct download_job_t *res;

	list_for_each_entry(res, &JOBS, list) {
		if(strcmp(res->file_id, fid) == 0)
			return res;
	}

	return NULL;
}

bool find_peer(struct list_head *plist, unsigned int id)
{
	struct peer_info_t *res;

	list_for_each_entry(res, plist, list) {
		if(res->peer_id == id)
			return true;
	}

	return false;
}

int server_keepalive_fn(EV_P_ ev_io *w)
{
	ssize_t read;
	int dlen = P2P_MSG_IN.len;
	int peer_num = (dlen - MD5_LEN) / sizeof(struct peer_list_t);

	char data[dlen];
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));
		
		ev_fd_close(w);
		return -1;
	}
	
	char fid[MD5_LEN];
	memcpy(fid, data, MD5_LEN);
	
	build_csrv_keepalive(fid);
	if(socket_write(w->fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0)
		perror("failed to connect to server.\n");

	if(peer_num == 0)
		return 0;

	struct peer_list_t peers[peer_num];
	memcpy(peers, data + MD5_LEN, peer_num * sizeof(struct peer_list_t));

	struct download_job_t *job = find_job(fid);
	int i;
	for(i=0; i<peer_num; i++) {
		if(find_peer(&(job->peer_list), peers[i].cid) == false)
			init_peer_conn(EV_A_ peers[i], fid, job);
	}
}

struct download_job_t *add_download_job(char *fid, unsigned int map_len, unsigned int peer_num)
{
	struct download_job_t *new = (struct download_job_t *)malloc(sizeof(struct download_job_t));

	strcpy(new->file_id, fid);
	new->map_len = map_len;
	new->file_map = (char *)calloc(map_len, sizeof(char));
	new->peer_num = peer_num;
	INIT_LIST_HEAD(&(new->peer_list));
	
	list_add(&new->list, &JOBS);

	return new;
}

int file_check_fn(EV_P_ ev_io *w)
{
	ssize_t read;
	int i;
	int dlen = P2P_MSG_IN.len;
	int peer_num = (dlen - MD5_LEN - sizeof(unsigned int)) / sizeof(struct peer_list_t);
	if(peer_num < 0) {
		printf("file id error\n");
		return -1;
	}
	
	if(peer_num == 0) {
		printf("no peers to share the file\n");
		return 0;
	}

	char data[dlen];
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));
		
		ev_fd_close(w);
		return -1;
	}

	char file_id[MD5_LEN] = {0};
	memcpy(file_id, data, MD5_LEN);

	unsigned int bitmap_len;
	memcpy(&bitmap_len, data + MD5_LEN, sizeof(unsigned int));

	struct peer_list_t peers[peer_num];
	memcpy(peers, data + MD5_LEN + sizeof(unsigned int), peer_num * sizeof(struct peer_list_t));

	struct download_job_t *job = add_download_job(file_id, bitmap_len, peer_num);

	for(i=0; i<peer_num; i++)
		init_peer_conn(EV_A_ peers[i], file_id, job);

	return 0;
}

void reply_server_cb(EV_P_ ev_io *w, int events)
{
// 1. handle if it is server reply about file ID check - start the download job
// 2. handle if it is server keepalive msg - reply client's status

	ssize_t read;
	size_t len = msg_header_len;
	
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len || 
		//sanity check the msg header...
		P2P_MSG_IN.magic != MAGIC_NUM || 
		P2P_MSG_IN.cid != ID || 
		P2P_MSG_IN.version == 0.) {
		ev_fd_close(w);
		return;
	}

	if(msg_fns[P2P_MSG_IN.type].func == NULL) {
		printf("unknown msg type\n");
		return;
	}

	msg_fns[P2P_MSG_IN.type].func(w);
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

void download_file(char *file_id)
{
	if(check_pidfile("PP2P_client") == false) {
	//tell client daemon what job needs to do by UNIX socket. Once the client daemon receives the request it will handle the job
		int cli_fd = open_unix_socket_out(UNIX_SOCK_PATH);
		if(cli_fd == -1)
			exit(-1);

		struct cli_cmd_t data = {.type = 0, .len = strlen(file_id)};
		strcpy(data.cmd, file_id);
		
		if(socket_write(cli_fd, (char *)&data, cli_cmd_header_len + data.len) <= 0)
			perror("failed to start a new job");
		
		close(cli_fd);
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
		if(clientCLI_fd == -1)
			exit(-1);
		
		ev_io_init(&cli_io, accept_cli_cb, clientCLI_fd, EV_READ);
		ev_io_start(loop, &cli_io);

		int client2srv_fd;
		ev_io csrv_io;
		client2srv_fd = open_socket_out(SERVER_PORT, SERVER_IP);
		if(client2srv_fd == -1)
			exit(-1);
		
		ev_io_init(&csrv_io, reply_server_cb, client2srv_fd, EV_READ);
		ev_io_start(loop, &csrv_io);
	
		int p2p_listen_fd;
		ev_io plisten_io;
		p2p_listen_fd = open_socket_in(CLIENT_LISTEN_PORT, CLIENT_IP); 
		if(p2p_listen_fd == -1)
			exit(-1);
		
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
			if(strlen(optarg) < MD5_LEN * sizeof(char))
				printf("invalid file ID.\n");
			else
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
