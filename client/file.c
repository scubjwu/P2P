#include "includes.h"

#include <openssl/md5.h>

#include "file.h"

extern char SHARE_DIR[256];

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

void chunk_md5(unsigned char *data, unsigned long len, unsigned char *res)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	MD5_CTX mdContext;
	
	MD5_Init(&mdContext);
	MD5_Update(&mdContext, data, len);
	MD5_Final(c, &mdContext);
	
	memcpy(res, c, MD5_DIGEST_LENGTH * sizeof(unsigned char));
}

void file_md5(FILE *f, unsigned char *res)
{
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned char buf[DATA_LEN];
	MD5_CTX mdContext;
	size_t read;

	MD5_Init(&mdContext);
	while((read = fread(buf, sizeof(unsigned char), DATA_LEN, f)) != 0)
		MD5_Update(&mdContext, buf, read);
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
	int f;
	char path[512] = {0};
	sprintf(path, "%s/%s_p2p.tmp", SHARE_DIR, name);
	f = open(path, O_CREAT | O_RDWR);
	if(f == -1) {
		perror("open file error");
		return -1;
	}

	if(ftruncate(f, size) == -1) {
		perror("ftruncate");
		return -1;
	}

	*fd = f;
	return 0;
}

ssize_t fileinfo_wb(int fd, const void *buf, size_t count, off_t off)
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

unsigned int bitcount(unsigned char c)
{
	struct _byte *tmp = (struct _byte *)&c;
	return (tmp->a1 + tmp->a2 + tmp->a3 + tmp->a4 + tmp->a5 + tmp->a6 + tmp->a7 + tmp->a8);
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
	file_md5(f, md5);

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

