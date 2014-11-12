#ifndef _CLIENT_H
#define _CLIENT_H

#define G_SRV_IP_ADDR	"10.0.0.1"
#define G_CONFIG_FILE	"/etc/PP2P/client.config"
#define UNIX_SOCK_PATH	"/tmp/PP2P.sock"
#define PEER_KEEPALIVE_TINTER	30	

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
	struct download_job_t *job;
	
	unsigned int peer_id;
	char *peer_filemap;
	
	ev_io peerinfo_io;
	ev_io peerdata_io;
	ev_timer peerinfo_timer;
};

struct download_job_t {
	struct list_head list;

	char file_id[MD5_LEN];

	unsigned int map_len;
	char *file_map;
	
	unsigned int peer_num;
	struct peer_info_t peers[];
};

#endif
