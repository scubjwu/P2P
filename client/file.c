#include "includes.h"

#include <openssl/md5.h>

#include "file.h"

extern char SHARE_DIR[256];
extern int errno;

struct _byte {
	unsigned a1 : 1;
	unsigned a2 : 1;
	unsigned a3 : 1;
	unsigned a4 : 1;
	unsigned a5 : 1;
	unsigned a6 : 1;
	unsigned a7 : 1;
	unsigned a8 : 1;
};

unsigned int bitcount(unsigned char c)
{
	struct _byte *tmp = (struct _byte *)&c;
	return (tmp->a1 + tmp->a2 + tmp->a3 + tmp->a4 + tmp->a5 + tmp->a6 + tmp->a7 + tmp->a8);
}

ssize_t file_write(int fd, const void *buf, size_t count, off_t off)
{
	ssize_t ret;

	do {
		ret = pwrite(fd, buf, count, off);
	} while (ret == -1 && errno == EINTR);
	
	return ret;
}

ssize_t file_read(int fd, void *buf, size_t count, off_t off)
{
	ssize_t ret;

	do {
		ret = pread(fd, buf, count, off);
	} while (ret == -1 && errno == EINTR);
	
	return ret;
}

void chunk_md5(unsigned char *data, unsigned long len, unsigned char *res)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	MD5_CTX mdContext;
	
	MD5_Init(&mdContext);
	MD5_Update(&mdContext, data, len);
	MD5_Final(c, &mdContext);
	
	memcpy(res, c, MD5_DIGEST_LENGTH * sizeof(unsigned char));
}

void file_md5(int fd, unsigned char *res)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned char buf[DATA_LEN];
	MD5_CTX mdContext;
	size_t cnt;

	MD5_Init(&mdContext);
	while((cnt = read(fd, buf, sizeof(unsigned char) * DATA_LEN)) != 0)
		MD5_Update(&mdContext, buf, cnt);
	MD5_Final(c, &mdContext);

	memcpy(res, c, MD5_DIGEST_LENGTH * sizeof(unsigned char));
}

off_t file_size(FILE *f)
{
	int fd = fileno(f);
	struct stat sbuf;
	
	if(fstat(fd, &sbuf) < 0) {
		perror("fstat");
		return -1;
	}

	return sbuf.st_size;
}

space_t available_space(const char *path)
{
	struct statfs buf;
	if(statfs(path, &buf) < 0) {
		perror("statfs");
		return -1;
	}

	return (buf.f_bfree * buf.f_bsize);
}

int file_alloc(char *name, int *fd, off_t size)
{
	FILE *f;
	char path[512] = {0};
	sprintf(path, "%s/%s_p2p.tmp", SHARE_DIR, name);
	f = fopen(path, "w+");
	if(f == NULL) {
		perror("open file error");
		return -1;
	}

	*fd = fileno(f);
	if(ftruncate(*fd, size) == -1) {
		perror("ftruncate");
		*fd = 0;
		return -1;
	}
	
	return 0;
}

/*
void set_bit_true(unsigned char *bitmap, unsigned int pos)
{
	int index = pos / 8;
	int loc = pos & 7;
	
	bitmap[index] |= (1 << loc);
}

void set_bit_false(unsigned char *bitmap, unsigned int pos)
{
	int index = pos / 8;
	int loc = pos & 7;
	
	bitmap[index] ^= (1 << loc);
}

int main(void)
{
	FILE *f = fopen("./c.txt", "r");
	unsigned char md5[MD5_DIGEST_LENGTH];
	int i;
	file_md5(fileno(f), md5);

	for(i=0; i<MD5_DIGEST_LENGTH; i++)
		printf("%02x", md5[i]);
	printf("\n");

	if(file_size(f) + 0x200000 < available_space("/")) {
		printf("file size (B): %ld\n", file_size(f));
		printf("space (MB): %ld\n", available_space("/")/1024/1024);
	}

	fclose(f);
	return 0;
}
*/

