#include "includes.h"

#include <openssl/md5.h>

#include "file.h"

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

