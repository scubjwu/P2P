#include "includes.h"
#include <ev.h>
#include <pthread.h>

#include "socket.h"
#include "common.h"
#include "util.h"
#include "list.h"
#include "fifo.h"
#include "file.h"

#include "client.h"
	
int SERVER_PORT = 49999;
double VERSION = 0.01;

//read from config file
int CLIENT_LISTEN_PORT = 60010;
int MIN_TRANS_PORT = 33000;
int MAX_TRANS_PORT = 61000;
char *port_range;
int INTERFACE_ID = 1;
char SERVER_IP[IPV4_ADDR_LEN] = G_SRV_IP_ADDR;
char CLIENT_IP[IPV4_ADDR_LEN] = "0.0.0.0";
char CONFIG_FILE[256] = G_CONFIG_FILE;
char SHARE_DIR[256] = "empty";

unsigned int ID;
struct pmsg_t P2P_MSG_OUT;
struct pmsg_t P2P_MSG_IN;
struct list_head JOBS;
char file_info[512];
char wb_buff[WB_BUFF_LEN];

int clientCLI_fd;
int client2srv_fd;
int p2p_listen_fd;

extern int errno;

struct ev_loop *loop;

#define ev_fd_close(watcher)	\
{							\
	close((watcher)->fd);		\
	ev_io_stop(loop, watcher);	\
}

#define filemap_update_req(job)				\
{							\
	pthread_mutex_lock(&(job)->assign_lock);	\
	(job)->piece_update = 1;			\
	pthread_cond_signal(&(job)->assign_req);	\
	while((job)->piece_update == 1)			\
		pthread_cond_wait(&(job)->assign_rep, &(job)->assign_lock);		\
	pthread_mutex_unlock(&(job)->assign_lock);		\
}

#define queue_shrank(fifo)			\
{								\
	(fifo)->size = (fifo)->size / 2;	\
	if((fifo)->size < 4)				\
		(fifo)->size = 4;			\
	fifo = fifo_realloc(fifo, (fifo)->size);	\
}

int file_check_fn(EV_P_ ev_io *w);
int server_keepalive_fn(EV_P_ ev_io *w);
int client_conn_req_fn(EV_P_ ev_io *w);
int peer_conn_rep_fn(EV_P_ ev_io *w);
int client_keepalive_fn(EV_P_ ev_io *w);
int peer_keepalive_fn(EV_P_ ev_io *w);

struct msg_handle_fn {
	char *name;
	int (* func) ();
}
msg_fns[7] = {

/*0x00*/		{NULL, NULL},
/*0x01*/		{"filecheck", file_check_fn},
/*0x02*/		{"srvkeepalive", server_keepalive_fn},
/*0x03*/		{"connreq", client_conn_req_fn},
/*0x04*/		{"connrep", peer_conn_rep_fn},
/*0x05*/		{"clientkeepalive", client_keepalive_fn},
/*0x06*/		{"peerkeepalive", peer_keepalive_fn}
//TODO:
};

static int piece_cmp(const void *n1, const void *n2)
{
	return (((struct piece_info_t *)n1)->count - ((struct piece_info_t *)n2)->count);
}

static int offset_cmp(const void *n1, const void *n2)
{
	return (*(off_t *)n1 - *(off_t *)n2);
}

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

	port_range = (char *)calloc(MAX_TRANS_PORT - MIN_TRANS_PORT, sizeof(char));

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
	//init all needed GLOBAL variables. eg: the table maintain the status of each sharing file
	load_config_file(CONFIG_FILE);
	
	ID = getclientID();

	P2P_MSG_OUT.magic = MAGIC_NUM;
	P2P_MSG_OUT.version = VERSION;
	P2P_MSG_OUT.cid = ID;
	P2P_MSG_OUT.error = 0x0;

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

	parse_cli_cmd(client2srv_fd, data.type, data.cmd);
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

int peer_keepalive_fn(EV_P_ ev_io *w)
{
// handle peer keep-alive msg on client listening port. reset alive value to 0...
// update the finished pieces info and write back to the tmp file for download restore
// do not reset alive value to 0 if it already equals to PEER_DEAD
// 1. file_id 2. file_bitmap 3. peer upload capacity
	
	struct peer_info_t *ptr;
	ptr= container_of(w, struct peer_info_t, peerinfo_io);
	struct download_job_t *job = ptr->job;
	ssize_t read;
	size_t dlen, download, upload, len;
	char data[dlen];
	char file_id[MD5_LEN] = {0};
	char file_map[job->map_len];

	if(ptr->alive == PEER_DEAD)
		goto KEEPALIVE_ERROR;

	dlen = P2P_MSG_IN.len;
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("%s recv msg from server error?\n", __func__);
		goto KEEPALIVE_ERROR;
	}

	memcpy(file_id, data, MD5_LEN);
	memcpy(&download, data + MD5_LEN, sizeof(size_t));
	memcpy(&upload, data + MD5_LEN + sizeof(size_t), sizeof(size_t));
	memcpy(file_map, data + MD5_LEN + 2 * sizeof(size_t), job->map_len);

	if(strcmp(file_id, job->file_id))
		goto KEEPALIVE_ERROR;
	
	ptr->p_download = download;
	ptr->p_upload = upload;
	ptr->alive = 0;
	
	if(strcmp(file_map, ptr->peer_filemap)) {
		strcpy(ptr->peer_filemap, file_map);
		ptr->new_piece = 1;
		//check if we need to do the reassignement...
		if(ptr->choke != 2) {
			filemap_update_req(job);
			ptr->new_piece = 0;
		}
	}

	//only write back info to file here...
	len = MD5_LEN + sizeof(off_t) + sizeof(unsigned int);
	memcpy(file_info + len, job->file_map, job->map_len);
	len += job->map_len;
	if(file_write(job->fd, file_info, len, job->size + 0x400/*1KB safe space*/) != len) {
		printf("file info write back error. (%s)\n", strerror(errno));
		goto KEEPALIVE_ERROR;
	}

	return 0;

KEEPALIVE_ERROR:
	ev_fd_close(w);
	ptr->alive = PEER_DEAD;
	return -1;
}

void trans_REQ_cb(EV_P_ ev_io *w, int events)
{
// send data req to peer. put the req into pending list.
// 1. file_id 2. piece_id
// if the length of pending list equals to plist_len, stop the watcher util new data_tran_rep comes
// if the req queue is empty, stop the watcher util new pieces assignment is done

	struct peer_info_t *ptr;
	ptr = container_of(w, struct peer_info_t, peer_transreq_io);
	struct download_job_t *job = ptr->job;
	fifo_data_t tmp;
	char *buf;

	// 1. if the pending list is full, do not send any new data req. choke the peer and wait
	if(ptr->plist_len == ptr->plist_cur) {
		ptr->choke = 2;		//pending full choke
		ev_io_stop(EV_A_ w);
		return;
	}
	// 2. if the pending list is not full but the queue is empty. try get new piece assignment
	else if(FIFO_EMPTY(ptr->piece_queue)) {
		//check if we have new pieces assign to queue
		int i, flag = 0;
		for(i=job->pc_cur; i<job->pc_len; i++) {
			if(job->pc[i].assign == 0 && 
				get_bit(ptr->peer_filemap, job->pc[i].index)) {
				if(fifo_put(ptr->piece_queue, &(job->pc[i])) == -1)
					break;

				job->pc[i].assign = 1;
				flag = 1;
				if(i == job->pc_cur)
					job->pc_cur++;
			}
		}
		//if no piece could be assigned but the map could be updated
		if(flag == 0) {
			if(ptr->new_piece) {
				ptr->choke = 1;	//queue empty
				filemap_update_req(job);
				ptr->new_piece = 0;
			}
			else {
				ptr->choke = 3;		//piece lack choke
				ev_io_stop(EV_A_ w);
				return;
			}
		}
	}

	
	if(fifo_get(ptr->piece_queue, &tmp) == -1) {
		ptr->choke = 3;		//piece lack choke
		ev_io_stop(EV_A_ w);
		return;
	}

	P2P_MSG_OUT.type = 0x07;
	P2P_MSG_OUT.pid = ptr->peer_id;
	P2P_MSG_OUT.len = MD5_LEN + sizeof(off_t);
	buf = P2P_MSG_OUT.content;
	
	memcpy(buf, ptr->job->file_id, MD5_LEN);
	memcpy(buf + MD5_LEN, &((struct piece_info_t *)tmp)->index, sizeof(off_t));

	if(socket_write(ptr->peer_transreq_io.fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		ev_fd_close(w);
		ptr->alive = PEER_DEAD;
		return;
	}

	//put into pending list
	qsort(ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
	off_t *pos, key = -1;
	pos = bsearch(&key, ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
	*pos = ((struct piece_info_t *)tmp)->index;
	ptr->plist_cur++;
	return;
}

void trans_REP_cb(EV_P_ ev_io *w, int events)
{
// do the actual file trans. recv the tran reply from peer and write back data to file
// check if the sending queue is choked after finish wb

	struct peer_info_t *ptr;
	ptr = container_of(w, struct peer_info_t, peer_transrep_io);

	struct download_job_t *job = ptr->job;

	ssize_t read;
	size_t len = msg_header_len + MD5_LEN + sizeof(off_t);
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len ||
		P2P_MSG_IN.magic != MAGIC_NUM ||
		P2P_MSG_IN.pid != ID ||
		P2P_MSG_IN.len == 0) {
		printf("trans rep msg error\n");
		goto REP_ERROR;
	}

	if(P2P_MSG_IN.error) {
	//TODO: handle error of trans req from peer
	}

	char file_id[MD5_LEN] = {0};
	memcpy(file_id, P2P_MSG_IN.content, MD5_LEN);

	off_t piece_id;
	memcpy(&piece_id, P2P_MSG_IN.content + MD5_LEN, sizeof(off_t));

	if(strcmp(file_id, job->file_id)) {
		printf("wrong file_id of trans rep\n");
		goto REP_ERROR;
	}

	qsort(ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
	off_t *pos;
	pos = bsearch(&piece_id, ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
	if(pos == NULL) {
		printf("wrong file piece of trans rep\n");
		goto REP_ERROR;
	}

	len = P2P_MSG_IN.len - MD5_LEN - sizeof(off_t);	//actual data len
	if(len > PIECE_SIZE) {
		printf("wrong data len of trans rep\n");
		goto REP_ERROR;
	}

	read = socket_read(w->fd, wb_buff, len);
	if(read == 0 || read == -1 || read != len) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("%s error?\n", __func__);
		goto REP_ERROR;
	}

	if(write_p2pfile(ptr, piece_id, len) == -1) {
		printf("write back file error?\n");
		goto REP_ERROR;
	}

	//update related info
	*pos = -1;
	ptr->plist_cur--;
	ptr->peer_trans_cnt++;
	job->c_download++;
	
	if(ptr->choke == 2 && 
		!FIFO_EMPTY(ptr->piece_queue) &&
		ptr->plist_len - ptr->plist_cur >= FIFO_LEN(ptr->piece_queue)) {
		ptr->choke = 0;
		ev_io_start(loop, &ptr->peer_transreq_io);
	}
	
	return;

REP_ERROR:
	ev_fd_close(w)
	ptr->alive = PEER_DEAD;
	return;
}

int write_p2pfile(struct peer_info_t *peer, off_t pos, size_t len)
{
	unsigned char *bitmap = peer->job->file_map;
	size_t p_num = peer->job->map_len * 8;

	if(get_bit(bitmap, pos) == 1) {	//duplicated piece???
		printf("recv duplicated piece....\n");
		return 0;
	}

	if(pos >= p_num ||
		(pos != p_num - 1 && len != PIECE_SIZE))
		return -1;

	if(file_write(peer->job->fd, wb_buff, len, pos * PIECE_SIZE) != len)
		return -1;

	//update file map
	set_bit_true(bitmap, pos);

	return 0;
}

int peer_conn_rep_fn(EV_P_ ev_io *w)
{
//handle peer conn reply msg on client listening port
// 1. file_id 2. peer ip 3. peer port 4. file_bitmap 
	ssize_t read;
	size_t dlen = P2P_MSG_IN.len;
	char data[dlen];
	struct peer_info_t *ptr;
	struct download_job_t *job;
	char file_id[MD5_LEN] = {0};
	char ip[IPV4_ADDR_LEN] = {0};
	unsigned int port_d;
	char file_map[job->map_len];
	int data_fd;
	
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("%s recv msg from peer error?\n", __func__);
		goto REP_ERROR;
	}

	
	ptr= container_of(w, struct peer_info_t, peerinfo_io);
	job = ptr->job;
	
	memcpy(file_id, data, MD5_LEN);
	memcpy(ip, data + MD5_LEN, IPV4_ADDR_LEN);
	memcpy(&port_d, data + MD5_LEN + IPV4_ADDR_LEN, sizeof(unsigned int));
	memcpy(file_map, data + MD5_LEN + IPV4_ADDR_LEN + sizeof(unsigned int), job->map_len);

	//TODO: need to use ICE to setup the socket
	data_fd = open_socket_out(port_d, ip);
	if(data_fd == -1) {
		printf("failed to setup data trans connection with peer\n");
		goto REP_ERROR;
	}

	//pre-alloc the file space
	if(file_alloc(job->file_name, &(job->fd), job->size + PIECE_SIZE) == -1) {
		printf("file pre-alloc space failed\n");
		goto REP_ERROR;
	}
	
	ptr->peer_filemap = (char *)calloc(job->map_len, sizeof(unsigned char));
	strcpy(ptr->peer_filemap, file_map);
	ptr->new_piece = 1;

	ev_io_init(&(ptr->peer_transrep_io), trans_REP_cb, data_fd, EV_READ);
	ev_io_init(&(ptr->peer_transreq_io), trans_REQ_cb, data_fd, EV_WRITE);
	ev_io_start(loop, &(ptr->peer_transrep_io));
	ev_io_start(loop, &(ptr->peer_transreq_io));

	return 0;

REP_ERROR:
	ev_fd_close(w);
	ptr->alive = PEER_DEAD;
	return -1;
}

void peerinfo_cb(EV_P_ ev_io *w, int events)
{
//handle incoming msg on client listening port: 
//1. peer conn rep 0x04; 3. peer keepalive msg 0x06

	ssize_t read;
	size_t len = msg_header_len;
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len ||
		P2P_MSG_IN.magic != MAGIC_NUM ||
		P2P_MSG_IN.pid != ID ||
		P2P_MSG_IN.len == 0) {
		ev_fd_close(w);
		return;
	}

	//TODO: handle error from peer. May need to remove this peer. unable to connect with the peer???
	if(P2P_MSG_IN.error) {

	}

	if(msg_fns[P2P_MSG_IN.type].func == NULL) {
		printf("unknow peer msg type\n");
		return;
	}

	msg_fns[P2P_MSG_IN.type].func(EV_A_ w);
}

void build_peerinfo_msg(unsigned int type, unsigned int id, char *fid, unsigned char *file_map, size_t download, size_t upload)
{
	int map_len = strlen(file_map);
	P2P_MSG_OUT.type = type;
	P2P_MSG_OUT.pid = id;
	P2P_MSG_OUT.len = MD5_LEN + 2 * sizeof(size_t) + map_len;

	char *p = P2P_MSG_OUT.content;
	memcpy(p, fid, MD5_LEN);
	memcpy(p + MD5_LEN, &download, sizeof(size_t));
	memcpy(p + MD5_LEN + sizeof(size_t), &upload, sizeof(size_t));
	memcpy(p + MD5_LEN + 2 * sizeof(size_t), file_map, map_len);
}

void peer_keepalive(EV_P_ ev_timer *w, int events)
{
//send keepalive msg to peer
	struct peer_info_t *ptr;
	ptr = container_of(w, struct peer_info_t, peerinfo_timer);
	struct download_job_t *job = ptr->job;

	if(ptr->alive > KEEPALIVE_TIMEOUT) {
//if the value of ptr->alive is higher than KEEPALIVE_TIMEOUT, we simplely remove this peer	
		_free(ptr->peer_filemap);
		_free(ptr->pending_list);
		fifo_free(ptr->piece_queue, 0);
		ev_fd_close(&ptr->peerinfo_io);
		ev_fd_close(&ptr->peer_transrep_io);
		ev_fd_close(&ptr->peer_transreq_io);
		ev_timer_stop(loop, &ptr->peerinfo_timer);

		list_del(&ptr->list);
		return;
	}

	ptr->alive++;
	build_peerinfo_msg(0x05, ptr->peer_id, job->file_id, job->file_map, job->c_download, job->c_upload);
	if(socket_write(ptr->peerinfo_io.fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		ev_fd_close(&(ptr->peerinfo_io));
		return;
	}
}

void init_peer_conn(EV_P_ struct peer_list_t peer, char *fid, struct download_job_t *job)
{
	int peerinfo_fd, i;
	
	//TODO: need to use ICE to setup peer socket fd!!!
	peerinfo_fd = open_socket_out(peer.port, peer.ip);
	if(peerinfo_fd == -1)
		return;

	struct peer_info_t *ptr = (struct peer_info_t *)malloc(sizeof(struct peer_info_t));

	ptr->job = job;
	ptr->peer_id = peer.cid;
	ptr->peer_filemap = NULL;
	ptr->new_piece = 0;
	ptr->choke = 0;
	ptr->alive = 0;
	ptr->p_download = 0;
	ptr->p_upload = 0;
	ptr->peer_trans_cnt = 0;
	
	ev_io_init(&(ptr->peerinfo_io), peerinfo_cb, peerinfo_fd, EV_READ);
	ev_io_start(loop, &(ptr->peerinfo_io));

	build_peerinfo_msg(0x03,ptr->peer_id,  fid, job->file_map, job->c_download, job->c_upload);
	if(socket_write(peerinfo_fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		perror("failed to make connection with peer.\n");
		ev_fd_close(&(ptr->peerinfo_io));
		_free(ptr);
		return;
	}

	ev_timer_init(&(ptr->peerinfo_timer), peer_keepalive, PEER_KEEPALIVE_TINTER, PEER_KEEPALIVE_TINTER);
	ev_timer_start(loop, &(ptr->peerinfo_timer));

	ptr->piece_queue = fifo_alloc(DEFAULT_QUEUE_LEN);
	ptr->plist_len = 2 * DEFAULT_QUEUE_LEN;
	ptr->plist_cur = 0;
	ptr->pending_list = (off_t *)malloc(DEFAULT_QUEUE_LEN * sizeof(off_t));
	for(i=0; i<2 * DEFAULT_QUEUE_LEN; i++)
		ptr->pending_list[i] = -1;
	
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
	size_t dlen = P2P_MSG_IN.len;
	int peer_num = (dlen - MD5_LEN) / sizeof(struct peer_list_t);

	char data[dlen];
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("srv keepalive msg error\n");
	//	ev_fd_close(w);
		return -1;
	}
	
	char fid[MD5_LEN];
	memcpy(fid, data, MD5_LEN);

	struct download_job_t *job = find_job(fid);
	if(job == NULL) {
		printf("srv keepalive msg error. No such file id\n");
		return -1;
	}
	
	build_csrv_keepalive(fid);
	if(socket_write(w->fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0)
		perror("failed to connect to server.\n");

	if(peer_num == 0)
		return 0;

	struct peer_list_t peers[peer_num];
	memcpy(peers, data + MD5_LEN, peer_num * sizeof(struct peer_list_t));

	int i;
	for(i=0; i<peer_num; i++) {
		if(find_peer(&(job->peer_list), peers[i].cid) == false)
			init_peer_conn(EV_A_ peers[i], fid, job);
	}

	return 0;
}

void *assign_piece(void *arg)
{
	pthread_detach(pthread_self());
	
	struct download_job_t *job = (struct download_job_t *)arg;

	size_t p_num = job->map_len * 8;
	job->pc = (struct piece_info_t *)calloc(p_num, sizeof(struct piece_info_t));
	job->pc_len = 0;
	job->pc_cur = 0;
	struct peer_info_t *ptr;
	unsigned char *bitmap;
	size_t bitn, cur, average_p;
	average_p = p_num / job->peer_num;

	for(;;) {
		int cn, finished = 1;
		size_t i;
		bitn = 0; cur = 0;
		bitmap = job->file_map;
		
		pthread_mutex_lock(&job->assign_lock);
		while(job->piece_update == 0)
			pthread_cond_wait(&job->assign_req, &job->assign_lock);

		
		list_for_each_entry(ptr, &job->peer_list, list) {
			if(ptr->alive == PEER_DEAD)
				continue;
			ptr->piece_queue->in = ptr->piece_queue->out = 0;
			qsort(ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
		}
		
		//get pieces stat	
		for(i=0; i<p_num; i++) {
			cn = 0;
			if(get_bit(bitmap, i) == 1)
				continue;

			finished = 0;
			list_for_each_entry(ptr, &job->peer_list, list) {
				if(ptr->alive == PEER_DEAD)
					continue;
				//check if it is in the pending list
				if(bsearch(&i, ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp)) {
					cn = 0;
					break;
				}
				cn += get_bit(ptr->peer_filemap, i);
			}
			if(cn == 0)
				continue;
			
			job->pc[cur].index = i;
			job->pc[cur].assign = 1;
			job->pc[cur].count = cn;
			cur++;
		}
		if(finished == 1) {
		//TODO: job finished....
		}
		
		qsort(job->pc, cur, sizeof(struct piece_info_t), piece_cmp);
		job->pc_len = cur;
		job->pc_cur = 0;
		
		//choke method
		list_for_each_entry(ptr, &job->peer_list, list) {
			if(ptr->alive == PEER_DEAD)
				continue;
			
			/* if we have got certain pieces and the peer is choked, then:
			*	1. if the peer is choked because of pending list is full, reduce the assign queue len.
			*	2. if the peer is choked beacuse of the assign queue is empty and the len of pending list is low, enlargethe queue len.
			*/
			if(ptr->choke && job->c_download > DOWNLOAD_THRESHOLD) {
				if(ptr->choke == 2) {
					queue_shrank(ptr->piece_queue);
				}
				else if(ptr->choke == 1 && ptr->plist_cur < DEFAULT_QUEUE_LEN/2) {
					ptr->piece_queue = fifo_realloc(ptr->piece_queue, ptr->piece_queue->size + 4);
					ptr->choke = 0;
					ev_io_start(loop, &ptr->peer_transreq_io);
				}
				else if(ptr->choke == 3 && ptr->new_piece) {
					ptr->choke = 0;
					ev_io_start(loop, &ptr->peer_transreq_io);
				}
			}

			/* if the peer has been lived for a certain time and its share rate is low, 
			*	then reduce the assign queue len.
			*/
			if(ptr->p_download > average_p
				&& ptr->p_download / ptr->p_upload > SHARE_RATE) {
				queue_shrank(ptr->piece_queue);
			}

			/* if both of the client and the peer have been lived for a certain time but the total trans piece from the peer
			*	is low, then reduce the assign queue
			*/
			if(job->c_download > average_p && 
				ptr->p_download > average_p &&
				ptr->peer_trans_cnt < DEFAULT_QUEUE_LEN) {
				queue_shrank(ptr->piece_queue);
			}
		}
		
		//assign pieces
		for(i=0; i<cur; i++) {
			int flag = 0;
			list_for_each_entry(ptr, &job->peer_list, list) {
				if(ptr->alive == PEER_DEAD)
					continue;
				if(get_bit(ptr->peer_filemap, job->pc[i].index) && 
					fifo_put(ptr->piece_queue, &(job->pc[i])) == 0) {
					job->pc[i].assign = 1;
					job->pc_cur++;
					flag = 1;
					break;
				}
			}
			if(flag == 0)
				break;
		}

		job->piece_update = 0;
		pthread_cond_signal(&job->assign_rep);	
		pthread_mutex_unlock(&job->assign_lock);
	}
}

struct download_job_t *add_download_job(char *name, char *fid, off_t size, unsigned int map_len, unsigned int peer_num)
{
	struct download_job_t *new = (struct download_job_t *)malloc(sizeof(struct download_job_t));

	strcpy(new->file_name, name);
	strcpy(new->file_id, fid);
	new->fd = 0;				//open the file after the data tran conn is setup
	new->size = size;
	new->map_len = map_len;
	new->file_map = (unsigned char *)calloc(map_len, sizeof(unsigned char));
	
	new->piece_update = 0;
	pthread_mutex_init(&new->assign_lock, NULL);
	pthread_cond_init(&new->assign_req, NULL);
	pthread_cond_init(&new->assign_rep, NULL);

	new->c_download = 0;
	new->c_upload = 0;
	new->peer_num = peer_num;
	INIT_LIST_HEAD(&(new->peer_list));
	
	list_add(&new->list, &JOBS);

	pthread_t tid;
	pthread_create(&tid, NULL, assign_piece, new);

	//init file_info buff. fullfill file_info everytime when recv keepalive msg from peer and write it back to tmp file
	memcpy(file_info, fid, MD5_LEN);
	memcpy(file_info + MD5_LEN, &size, sizeof(off_t));
	memcpy(file_info + MD5_LEN + sizeof(off_t), &map_len, sizeof(unsigned int));

	return new;
}

int file_check_fn(EV_P_ ev_io *w)
{
	ssize_t read;
	int i;
	size_t dlen = P2P_MSG_IN.len;
	int peer_num = (dlen - MD5_LEN - sizeof(unsigned int) - sizeof(off_t) - FILE_NAME_LEN) 
					/ sizeof(struct peer_list_t);
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

		printf("%s recv msg from server error?\n", __func__);
	//keep the srv socket open
	//	ev_fd_close(w);
		return -1;
	}

	char file_name[FILE_NAME_LEN] = {0};
	memcpy(file_name, data, FILE_NAME_LEN);

	char file_id[MD5_LEN] = {0};
	memcpy(file_id, data + FILE_NAME_LEN, MD5_LEN);

	off_t size;
	memcpy(&size, data + FILE_NAME_LEN + MD5_LEN, sizeof(off_t));
	if(size + PIECE_SIZE >= available_space("/")) {
		printf("hard disk space is not enough\n");
		return -1;
	}

	unsigned int bitmap_len;
	memcpy(&bitmap_len, data + FILE_NAME_LEN + MD5_LEN + sizeof(off_t), sizeof(unsigned int));

	struct peer_list_t peers[peer_num];
	memcpy(peers, data + MD5_LEN + sizeof(off_t) + sizeof(unsigned int), peer_num * sizeof(struct peer_list_t));

	struct download_job_t *job = add_download_job(file_name, file_id, size, bitmap_len, peer_num);

	for(i=0; i<peer_num; i++)
		init_peer_conn(EV_A_ peers[i], file_id, job);

	return 0;
}

void reply_server_cb(EV_P_ ev_io *w, int events)
{
// 1. handle if it is server reply about file ID check - start the download job -0x01
// 2. handle if it is server keepalive msg - reply client's status - 0x02

	ssize_t read;
	size_t len = msg_header_len;
	
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len || 
		//sanity check the msg header...
		P2P_MSG_IN.magic != MAGIC_NUM || 
		P2P_MSG_IN.pid != ID || 
		P2P_MSG_IN.version == 0.) {
		printf("srv msg error?\n");
	//keep the client_srv socket open...
	//	ev_fd_close(w);
		return;
	}

	if(P2P_MSG_IN.error) {
	//TODO: handle error from server. file ID is wrong??? 
	}

	if(msg_fns[P2P_MSG_IN.type].func == NULL) {
		printf("unknown msg type\n");
		return;
	}

	msg_fns[P2P_MSG_IN.type].func(EV_A_ w);
}

unsigned int datatrans_port(void)
{
	int i;
	for(i=0; i<MAX_TRANS_PORT - MIN_TRANS_PORT; i++) {
		if(port_range[i] == 0) {
			port_range[i] = 1;
			return i;
		}
	}
	return 0;
}

size_t get_piece_size(char *map, off_t size, off_t id)
{
	size_t p_num = strlen(map) * 8;
	size_t res;
	
	if(get_bit(map, id) == 0 || id >= p_num)
		return 0;

	res = size % PIECE_SIZE;
	return (res == 0 ? PIECE_SIZE : res);
}

void data_send_cb(EV_P_ ev_io *w, int events)
{
//recv data trans req msg (0x07). send the req data back to client (0x08)

	ssize_t read;
	size_t len = msg_header_len + MD5_LEN + sizeof(off_t);
	char file_id[MD5_LEN] = {0};
	off_t piece_id;
	struct download_job_t *job;
	size_t piece_size;
	
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len ||
		P2P_MSG_IN.magic != MAGIC_NUM ||
		P2P_MSG_IN.pid != ID) {
		printf("peer read trans req msg error\n");
		//TODO: send error msg back to client

		goto SEND_ERROR;
	}
	
	memcpy(file_id, P2P_MSG_IN.content, MD5_LEN);
	memcpy(&piece_id, P2P_MSG_IN.content + MD5_LEN, sizeof(off_t));

	job = find_job(file_id);
	if(job == NULL) {
	//TODO: send error msg back to client

		goto SEND_ERROR;
	}

	piece_size = get_piece_size(job->file_map, job->size, piece_id);
	if(piece_size == 0) {
	//TODO: error piece size. send back error msg

		goto SEND_ERROR;
	}

	if(file_read(job->fd, wb_buff + msg_header_len + MD5_LEN + sizeof(off_t), 
				piece_size, piece_id) != piece_size) {
	//TODO: file read error. send back error msg

		goto SEND_ERROR;
	}

	P2P_MSG_OUT.pid = P2P_MSG_IN.cid;
	P2P_MSG_OUT.type = 0x08;
	P2P_MSG_OUT.len = MD5_LEN + sizeof(off_t) + piece_size;
	memcpy(wb_buff, &P2P_MSG_OUT, msg_header_len);
	memcpy(wb_buff + msg_header_len, file_id, MD5_LEN);
	memcpy(wb_buff + msg_header_len + MD5_LEN, &piece_id, sizeof(off_t));

	if(socket_write(w->fd, wb_buff, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		goto SEND_ERROR;
	}

	job->c_upload++;
	return;
	
SEND_ERROR:
	ev_fd_close(w);
	_free(w);
}

void accept_datareq_cb(EV_P_ ev_io *w, int events)
{
	ev_io *data_trans_io;
	int fd;
	fd = accept(w->fd, NULL, NULL);
	if(fd == -1 &&
		errno != EAGAIN &&
		errno != EWOULDBLOCK) {
		printf("peer accept error: %s\n", strerror(errno));
		//TODO: send back accept error msg to client???
		goto ACPT_END;
	}

	set_socketopt(fd);
	set_blocking(fd, false);

	data_trans_io = (ev_io *)malloc(sizeof(ev_io));
	ev_io_init(data_trans_io, data_send_cb, fd, EV_READ);
	ev_io_start(loop, data_trans_io);

ACPT_END:
	ev_fd_close(w);
	_free(w);
}

int client_keepalive_fn(EV_P_ ev_io *w)
{
//handle client keepalive detect msg on peer listening port
//reply keepalive msg with: 1. file_id 2. file_bitmap 3. peer upload capacity

	ssize_t read;
	char file_id[MD5_LEN];
	char *p;
	struct download_job_t *job;

	read = socket_read(w->fd, file_id, MD5_LEN);
	if(read == 0 || read == -1 || read != MD5_LEN) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("%s socket read error?\n", __func__);
		goto CKEEPALIVE_END;
	}

	job = find_job(file_id);
	if(job == NULL) {
	//TODO: construct error msg and send back to client
	
		goto CKEEPALIVE_END;
	}

	build_peerinfo_msg(0x06, P2P_MSG_IN.cid, file_id, job->file_map, job->c_download, job->c_upload);
	if(socket_write(w->fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0)
		goto CKEEPALIVE_END;

	return 0;

CKEEPALIVE_END:
	ev_fd_close(w);
	_free(w);
	return -1;
}

int client_conn_req_fn(EV_P_ ev_io *w)
{
// handle client conn req msg on peer listening port
// send reply with: 1. file_id 2. peer ip 3. peer data trans port 4. file_bitmap
// setup data trans socket on peer to wait client data trans req

	ssize_t read;
	size_t dlen = P2P_MSG_IN.len;
	char data[dlen];
	char file_id[MD5_LEN];
	struct download_job_t *job;
	struct peer_info_t *ptr;
	size_t download, upload;
	unsigned int port;
	
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("%s socket read error?\n", __func__);
		ev_fd_close(w);
		_free(w);
		return -1;
	}

	
	memcpy(file_id, data, MD5_LEN);
	memcpy(&download, data + MD5_LEN, sizeof(size_t));
	memcpy(&upload, data + MD5_LEN + sizeof(size_t), sizeof(size_t));

	job = find_job(file_id);
	if(job == NULL) {
	//TODO: construct error msg and send back to client
	
		ev_fd_close(w);
		_free(w);
		return -1;
	}

	char file_map[job->map_len];
	memcpy(file_map, data + MD5_LEN + 2 * sizeof(size_t), job->map_len);

	//assign a random port for data trans
	port = datatrans_port();
	if(port == 0) {
	//TODO: send error back. no port available on peer for data trans...

		ev_fd_close(w);
		_free(w);
		return -1;
	}

	//setup data trans socket to wait incoming connection
	int data_fd;
	data_fd = open_socket_in(port, CLIENT_IP); 
	if(data_fd == -1) {
	//TODO: setup recv socket error. send back error msg

		ev_fd_close(w);
		_free(w);
		return -1;
	}

	ev_io *data_send_io = (ev_io *)malloc(sizeof(ev_io));
	ev_io_init(data_send_io, accept_datareq_cb, data_fd, EV_READ);
	ev_io_start(loop, data_send_io);

	//prepare reply
	P2P_MSG_OUT.pid = P2P_MSG_IN.cid;
	P2P_MSG_OUT.type = 0x04;
	P2P_MSG_OUT.len = MD5_LEN + IPV4_ADDR_LEN + sizeof(unsigned int) + job->map_len;

	char *p = P2P_MSG_OUT.content;
	memcpy(p, file_id, MD5_LEN);
	memcpy(p + MD5_LEN, CLIENT_IP, IPV4_ADDR_LEN);
	memcpy(p + MD5_LEN + IPV4_ADDR_LEN, &port, sizeof(unsigned int));
	memcpy(p + MD5_LEN + IPV4_ADDR_LEN + sizeof(unsigned int), job->file_map, job->map_len);	
	if(socket_write(w->fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		ev_fd_close(w);
		_free(w);
		ev_fd_close(data_send_io);
		_free(data_send_io);
		return -1;	
	}

	//Do not care if we have this client in local peer list or not. just wait for next peerlist update from server...
	return 0;
}

void peer_req_cb(EV_P_ ev_io *w, int events)
{
//	1. conn req - setup data trans listening port for the peer	0x03
//	2. keepalive msg - exchange file bitmap info				0x05

	ssize_t read;
	size_t len = msg_header_len;
	read = socket_read(w->fd, (char *)&P2P_MSG_IN, len);
	if(read != len ||
		P2P_MSG_IN.magic != MAGIC_NUM ||
		P2P_MSG_IN.pid != ID ||
		P2P_MSG_IN.len == 0) {
		//this is client listening port... do not close it. just stop the watcher
		ev_fd_close(w)
		_free(w);
		return;
	}

	if(msg_fns[P2P_MSG_IN.type].func == NULL) {
		printf("unknown msg type\n");
		return;
	}

	msg_fns[P2P_MSG_IN.type].func(EV_A_ w);
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
		
		ev_io cli_io;
		clientCLI_fd = open_unix_socket_in(UNIX_SOCK_PATH);
		if(clientCLI_fd == -1)
			exit(-1);
		
		ev_io_init(&cli_io, accept_cli_cb, clientCLI_fd, EV_READ);
		ev_io_start(loop, &cli_io);

		ev_io csrv_io;
		client2srv_fd = open_socket_out(SERVER_PORT, SERVER_IP);
		if(client2srv_fd == -1)
			exit(-1);
		
		ev_io_init(&csrv_io, reply_server_cb, client2srv_fd, EV_READ);
		ev_io_start(loop, &csrv_io);
	
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
