#ifndef _CLIENT_H
#define _CLIENT_H

#define G_SRV_IP_ADDR	"10.0.0.1"
#define G_CONFIG_FILE	"/etc/PP2P/client.config"
#define UNIX_SOCK_PATH	"/tmp/PP2P.sock"
#define PEER_KEEPALIVE_TINTER	30	
#define PIECE_SIZE				0x8000	// 32k
#define CHUNK_SIZE				0x200000	// 2mb - 64 pieces
#define KEEPALIVE_TIMEOUT		6		// 3 min
#define DEFAULT_QUEUE_LEN		4

#define cli_cmd_header_len		(2 * sizeof(unsigned))
#define msg_header_len	(sizeof(double) + 3 * sizeof(unsigned int) + sizeof(int))

struct cli_cmd_t {
	unsigned type;
	unsigned len;
	char cmd[CLI_MSG_LEN];
};

struct pmsg_t {
	unsigned int magic;
	unsigned int type;
	unsigned int cid;
	int len;
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
	volatile char *peer_filemap;

//assign file chunks into this queue for trans req.
	unsigned int *chunk_queue;
	unsigned int Cqueue_len;
	unsigned int Cq_cur;

//once send out chunk trans req, put the corresponding chunk into the pending queue. 
//Mark the chunk as done after recv all pieces of this chunk.
//if the pending queue is full, then dynamically determine if we need choke the chunk trans req.
	unsigned int *pending_queue;
	unsigned int Pqueue_len;
	unsigned int Pq_cur;
	
	//set to 1 if keepalive msg is sent out; reset to 0 if keepalive msg is recevied
	//if the value of alive is higher than a certain threshold, then remove this peer...
	unsigned int alive;	

	//the total download chunks from this peer for the job
	unsigned int download;

	ev_io peerinfo_io;
	ev_io peerdata_io;
	ev_timer peerinfo_timer;
};

struct conn_rep_t {
	char ip[IPV4_ADDR_LEN];
	unsigned int port_d;
};

struct peer_keepalive_t {
	char file_id[MD5_LEN];
	unsigned int upload;
};

struct chunk_info_t {
	unsigned int index;
	unsigned int status;	//1: assigned
	unsigned int count;		//for rarest first algorithm
};

struct download_job_t {
	struct list_head list;

	char file_id[MD5_LEN];

	unsigned int map_len;
	char *file_map;

	struct chunk_info_t *chunk;
	unsigned int chunk_update;	// 1: chunk array need to update;
	pthread_mutex_t assign_lock;
	pthread_cond_t assign_req;
	pthread_cond_t assign_rep;

	unsigned int upload;	//for choke algorithm
	
	unsigned int peer_num;
	struct list_head peer_list;
};

#endif
