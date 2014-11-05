#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

#define CHUNK_S	16384

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
	unsigned char buf[CHUNK_S];
	MD5_CTX mdContext;
	size_t read;

	MD5_Init(&mdContext);
	while((read = fread(buf, sizeof(unsigned char), CHUNK_S, f)) != 0)
		MD5_Update(&mdContext, buf, read);
	MD5_Final(c, &mdContext);

	memcpy(res, c, MD5_DIGEST_LENGTH * sizeof(unsigned char));
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

	fclose(f);
	return 0;
}

