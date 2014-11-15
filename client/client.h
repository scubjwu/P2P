#ifndef _CLIENT_H
#define _CLIENT_H

#define G_SRV_IP_ADDR	"10.0.0.1"
#define G_CONFIG_FILE	"/etc/PP2P/client.config"
#define UNIX_SOCK_PATH	"/tmp/PP2P.sock"
#define PEER_KEEPALIVE_TINTER	20	
#define PIECE_SIZE				0x20000	// 128KB
#define WB_BUFF_LEN				0x40000	// 256KB. Just be safe...
#define KEEPALIVE_TIMEOUT		3		// 1 min
#define PEER_DEAD				999
#define DEFAULT_QUEUE_LEN		32
#define FILE_NAME_LEN			256
#define DOWNLOAD_THRESHOLD	128
#define SHARE_RATE				20

#define cli_cmd_header_len		(2 * sizeof(unsigned))
#define msg_header_len	(sizeof(double) + 5 * sizeof(unsigned int) + sizeof(size_t))

struct cli_cmd_t {
	unsigned type;
	unsigned len;
	char cmd[CLI_MSG_LEN];
};

struct pmsg_t {
	unsigned int magic;
	unsigned int error;
	unsigned int type;
	unsigned int cid;	//local ID - send; remote ID - recv
	unsigned int pid;	//remote ID - send; local ID - recv
	size_t len;
	double version;
	char content[DATA_LEN];
};

struct peer_list_t {
	unsigned int cid;
	unsigned int port;
	char ip[IPV4_ADDR_LEN];
};

struct peer_info_t {
	struct list_head list;
	
	struct download_job_t *job;
	
	unsigned int peer_id;
	unsigned char *peer_filemap;
	unsigned int new_piece;

//assign file pieces into this queue for trans req.
	FIFO *piece_queue;

//once send out piece trans req, put the corresponding piece into the pending list. 
//Mark the piece as done after recv all pieces of this piece.
//if the pending list is full, then dynamically determine if we need choke the piece trans req.
	off_t *pending_list;
	unsigned int plist_len;	//total list len
	unsigned int plist_cur;	//used list len

	unsigned int choke;		// 1: stop to sending data_tran_req
	
	//add 1 if keepalive msg is sent out; reset to 0 if keepalive msg is recevied
	//if the value of alive is higher than a certain threshold, then remove this peer...
	//if the value of alive equals to PEER_DEAD, then do not reset its value. Just let the peer timeout and be removed
	unsigned int alive;	

	//the total download pieces this peer has been downloaded from the network = peer.job->c_download
	size_t p_download;
	//total pieces this peer has been loaded to the network = peer.job->c_upload
	size_t p_upload;
	//total pieces this peer has been trans to the client
	size_t peer_trans_cnt;

	ev_io peerinfo_io;
	ev_io peer_transreq_io;
	ev_io peer_transrep_io;
	ev_timer peerinfo_timer;
};

struct download_job_t {
	struct list_head list;

	char file_name[FILE_NAME_LEN];
	char file_id[MD5_LEN];

	int fd;
	off_t size;

	unsigned int map_len;
	char *file_map;

	struct piece_info_t *pc;
	size_t pc_len;		//total length of pc
	size_t pc_cur;		//current pos of unassigned pc 

	unsigned int piece_update;	// 1: piece array need to update;
	pthread_mutex_t assign_lock;
	pthread_cond_t assign_req;
	pthread_cond_t assign_rep;

	size_t c_download;	//total pieces download by client
	size_t c_upload;			//total pieces uploaded by client
	
	unsigned int peer_num;
	struct list_head peer_list;
};

struct piece_info_t {
	off_t index;
	int assign;
	unsigned int count;		//for rarest first algorithm
};

#endif
