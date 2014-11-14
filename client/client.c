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

int peer_keepalive_fn(EV_P_ ev_io *w)
{
//TODO: handle peer keep-alive msg on client listening port. reset alive value to 0...
// update the finished pieces info and write back to the tmp file for download restore
// do not reset alive value to 0 if it already equals to PEER_DEAD
// 1. file_id 2. file_bitmap 3. peer upload capacity


}

void trans_REQ(EV_P_ ev_io *w, int events)
{
// send data req to peer. put the req into pending list.
// 1. file_id 2. piece_id
// if the length of pending list equals to plist_len, stop the watcher util new data_tran_rep comes
// if the req queue is empty, stop the watcher util new pieces assignment is done

	struct peer_info_t *ptr;
	ptr = container_of(w, struct peer_info_t, peer_transreq_io);

	if(FIFO_EMPTY(ptr->piece_queue) || ptr->plist_len == ptr->plist_cur) {
		ptr->choke = 1;
		ev_io_stop(EV_A_ w);
		return;
	}

	fifo_data_t tmp;
	fifo_get(ptr->piece_queue, &tmp);

	P2P_MSG_OUT.type = 0x07;
	P2P_MSG_OUT.len = MD5_LEN + sizeof(off_t);
	char *buf = P2P_MSG_OUT.content;
	
	memcpy(buf, ptr->job->file_id, MD5_LEN);
	memcpy(buf + MD5_LEN, &((struct piece_info_t *)tmp)->index, sizeof(off_t));

	if(socket_write(ptr->peer_transreq_io.fd, (char *)&P2P_MSG_OUT, msg_header_len + P2P_MSG_OUT.len) <= 0) {
		ptr->alive = PEER_DEAD;
		return;
	}

	//put into pending list
	qsort(ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
	off_t *pos, key = -1;
	pos = bsearch(&key, ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
	*pos = ((struct piece_info_t *)tmp)->index;
	ptr->plist_cur++;
}

void trans_REP(EV_P_ ev_io *w, int events)
{
//TODO: do the actual file trans. recv the tran reply from peer and write back data to file
// check if the sending queue is choked
}

int peer_conn_rep_fn(EV_P_ ev_io *w)
{
//handle peer conn reply msg on client listening port
// 1. file_id 2. peer ip 3. peer port 4. file_bitmap 
	ssize_t read;
	int dlen = P2P_MSG_IN.len;
	char data[dlen];
	read = socket_read(w->fd, data, dlen);
	if(read == 0 || read == -1 || read != dlen) {
		if(read == -1)
			printf("socket read error: %s\n", strerror(errno));

		printf("%s recv msg from peer error?\n", __func__);
		ev_fd_close(w);
		return -1;
	}

	struct peer_info_t *ptr;
	ptr= container_of(w, struct peer_info_t, peerinfo_io);

	struct download_job_t *job = ptr->job;
	
	char file_id[MD5_LEN] = {0};
	memcpy(file_id, data, MD5_LEN);

	char ip[IPV4_ADDR_LEN] = {0};
	memcpy(ip, data + MD5_LEN, IPV4_ADDR_LEN);

	unsigned int port_d;
	memcpy(&port_d, data + MD5_LEN + IPV4_ADDR_LEN, sizeof(unsigned int));

	char file_map[job->map_len];
	memcpy(file_map, data + MD5_LEN + IPV4_ADDR_LEN + sizeof(unsigned int), job->map_len);

	int data_fd;
	//TODO: need to use ICE to setup the socket
	data_fd = open_socket_out(port_d, ip);
	if(data_fd == -1) {
		printf("failed to setup data trans connection with peer\n");
		ptr->alive = PEER_DEAD;
		return -1;
	}

	//pre-alloc the file space
	if(file_alloc(job->file_name, &(job->fd), job->size + PIECE_SIZE) == -1) {
		printf("file pre-alloc space failed\n");
		ptr->alive = PEER_DEAD;
		return -1;
	}
	
	int flag = 0;
	if(ptr->peer_filemap == NULL) {
		ptr->peer_filemap = (char *)calloc(job->map_len, sizeof(unsigned char));
		strcpy(ptr->peer_filemap, file_map);
		flag = 1;
	}
	else if(strcmp(ptr->peer_filemap, file_map)) {
		strcpy(ptr->peer_filemap, file_map);
		flag = 1;
	}

	if(flag == 1) {
		pthread_mutex_lock(&job->assign_lock);

		job->piece_update = 1;
		pthread_cond_signal(&job->assign_req);
		while(job->piece_update == 1)
			pthread_cond_wait(&job->assign_rep, &job->assign_lock);

		pthread_mutex_unlock(&job->assign_lock);	
	}

	ev_io_init(&(ptr->peer_transrep_io), trans_REP, data_fd, EV_READ);
	ev_io_init(&(ptr->peer_transreq_io), trans_REQ, data_fd, EV_WRITE);
	ev_io_start(loop, &(ptr->peer_transrep_io));
	ev_io_start(loop, &(ptr->peer_transreq_io));
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
		P2P_MSG_IN.cid != ID ||
		P2P_MSG_IN.len == 0) {
		ev_fd_close(w);
		return;
	}

	if(msg_fns[P2P_MSG_IN.type].func == NULL) {
		printf("unknow peer msg type\n");
		return;
	}

	msg_fns[P2P_MSG_IN.type].func(EV_A_ w);
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
	
	P2P_MSG_OUT.type = 0x05;
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

void build_peer_connreq(char *fid, unsigned char *file_map)
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
	int peerinfo_fd, i;
	
	//TODO: need to use ICE to setup peer socket fd!!!
	peerinfo_fd = open_socket_out(peer.port, peer.ip);
	if(peerinfo_fd == -1)
		return;

	struct peer_info_t *ptr = (struct peer_info_t *)malloc(sizeof(struct peer_info_t));

	ptr->job = job;
	ptr->peer_id = peer.cid;
	ptr->peer_filemap = NULL;
	ptr->choke = 0;
	ptr->alive = 0;
	ptr->download = 0;
	
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

	ptr->piece_queue = fifo_alloc(DEFAULT_QUEUE_LEN);
	ptr->plist_len = 2 * DEFAULT_QUEUE_LEN;
	ptr->plist_cur = 0;
	ptr->pending_list = (off_t *)malloc(2 * DEFAULT_QUEUE_LEN * sizeof(off_t));
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
	int dlen = P2P_MSG_IN.len;
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

void *assign_piece(void *arg)
{
	pthread_detach(pthread_self());
	
	struct download_job_t *job = (struct download_job_t *)arg;

	unsigned int p_num = job->map_len * 8;
	struct piece_info_t *pc = (struct piece_info_t *)calloc(p_num, sizeof(struct piece_info_t));
	struct peer_info_t *ptr;
	unsigned char *bitmap;
	off_t *res = NULL;

	for(;;) {
		pthread_mutex_lock(&job->assign_lock);

		while(job->piece_update == 0)
			pthread_cond_wait(&job->assign_req, &job->assign_lock);

			list_for_each_entry(ptr, &job->peer_list, list) {
				ptr->piece_queue->in = ptr->piece_queue->out = 0;
				qsort(ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);

				if(ptr->choke && ptr->download > DOWNLOAD_THRESHOLD) {
					if(ptr->plist_len == ptr->plist_cur) {
						ptr->piece_queue->size = ptr->piece_queue->size / 2;
						if(ptr->piece_queue->size < 4)
							ptr->piece_queue->size = 4;
					
						ptr->piece_queue = fifo_realloc(ptr->piece_queue, ptr->piece_queue->size);
					}
					else if(FIFO_EMPTY(ptr->piece_queue)) {
						ptr->piece_queue = fifo_realloc(ptr->piece_queue, ptr->piece_queue->size + 4);
						ptr->choke = 0;
						ev_io_start(loop, &ptr->peer_transreq_io);
					}
				}
			}

		//get pieces stat
		int i, cn, cur = 0;
		bitmap = job->file_map;
		for(i=0; i<p_num; i++) {
			cn = 0;
			if(get_bit(bitmap, i) == 1)
				continue;

			list_for_each_entry(ptr, &job->peer_list, list) {
				//check if it is in the pending list
				res = bsearch(&i, ptr->pending_list, ptr->plist_len, sizeof(off_t), offset_cmp);
				if(res) {
					cn = 0;
					break;
				}
				cn += get_bit(ptr->peer_filemap, i);
			}
			if(cn == 0)
				continue;
			
			pc[cur].index = i;
			pc[cur].count = cn;
			cur++;
		}
		qsort(pc, cur, sizeof(struct piece_info_t), piece_cmp);
		
		//assign pieces
		for(i=0; i<cur; i++) {
			int flag = 0;
			list_for_each_entry(ptr, &job->peer_list, list) {
				if(get_bit(ptr->peer_filemap, pc[i].index) && 
					fifo_put(ptr->piece_queue, &pc[i]) == 0) {
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

	new->upload = 0;
	new->peer_num = peer_num;
	INIT_LIST_HEAD(&(new->peer_list));
	
	list_add(&new->list, &JOBS);

	pthread_t tid;
	pthread_create(&tid, NULL, assign_piece, new);

	return new;
}

int file_check_fn(EV_P_ ev_io *w)
{
	ssize_t read;
	int i;
	int dlen = P2P_MSG_IN.len;
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
		P2P_MSG_IN.cid != ID || 
		P2P_MSG_IN.version == 0.) {
		printf("srv msg error?\n");
	//keep the client_srv socket open...
	//	ev_fd_close(w);
		return;
	}

	if(msg_fns[P2P_MSG_IN.type].func == NULL) {
		printf("unknown msg type\n");
		return;
	}

	msg_fns[P2P_MSG_IN.type].func(EV_A_ w);
}

int client_conn_req_fn(EV_P_ ev_io *w)
{
//TODO: handle client conn req msg on peer listening port
// send reply with: 1. file_id 2. peer ip 3. peer data trans port 4. file_bitmap
// setup data trans socket on peer to wait client data trans req
}

int client_keepalive_fn(EV_P_ ev_io *w)
{
//TODO: handle client keepalive detect msg on peer listening port
//reply keepalive msg with: 1. file_id 2. peer upload capacity 3. file_bitmap
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
		P2P_MSG_IN.cid != ID ||
		P2P_MSG_IN.len == 0) {
		ev_fd_close(w);
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
