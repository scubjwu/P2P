#include "includes.h"

#include "list.h"

//the list acts like stack not fifo

static inline void _list_add(struct list_head *new, struct list_head *prev, struct list_head *next)
{	
	new->next = next;	
	new->prev = prev;	
	prev->next = new;	
	next->prev = new;
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{	
	next->prev = prev;	
	prev->next = next;
}

void list_add(struct list_head *new, struct list_head *head)
{	
	_list_add(new, head, head->next);
}

int list_empty(const struct list_head *head)
{	
	return head->next == head;
}

void list_del(struct list_head *entry)
{	
	__list_del(entry->prev, entry->next);	
	entry->prev = (void *)0x00200200;
}

