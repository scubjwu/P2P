#ifndef _FIFO_H
#define _FIFO_H

typedef void *fifo_data_t;
	
typedef struct fifo_t {
	fifo_data_t *data;	/* the buffer holding the data */
	unsigned int size;	/* the size of the allocated buffer */
	unsigned int in;	/* data is added at offset (in % size) */
	unsigned int out;	/* data is extracted from off. (out % size) */
} FIFO;

#define FIFO_FULL(fifo)	(fifo->size - fifo->in + fifo->out == 0)
#define FIFO_EMPTY(fifo)	(fifo->in - fifo->out == 0)

FIFO *fifo_alloc(unsigned int size);
FIFO *fifo_realloc(FIFO *src, unsigned int size);
void fifo_free(FIFO *fifo, int deep);
int _fifo_put(FIFO *fifo, fifo_data_t put);
int _fifo_get(FIFO *fifo, fifo_data_t *get);

#endif
