#ifndef _FILE_H
#define _FILE_H

typedef long unsigned int space_t;

#define get_bit(bitmap, pos)	\
	((bitmap[pos / 8] & (1 << (pos & 7))) == 0 ? 0 : 1)

#define set_bit_true(bitmap, pos)	\
	bitmap[pos / 8] |= (1 << (pos & 7))

#define set_bit_false(bitmap, pos)	\
	bitmap[pos / 8] ^= (1 << (pos & 7))

void chunk_md5(unsigned char *data, unsigned long len, unsigned char *res);
void file_md5(int fd, unsigned char *res);
off_t file_size(FILE *f);
space_t available_space(const char *path);
int file_alloc(char *name, int *fd, off_t size);
unsigned int bitcount(unsigned char c);
ssize_t file_write(int fd, const void *buf, size_t count, off_t off);
ssize_t file_read(int fd, void *buf, size_t count, off_t off);

#endif
