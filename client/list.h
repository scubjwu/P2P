#ifndef _LIST_H
#define _LIST_H

struct list_head {	
	struct list_head *next, *prev;
};

#define list_entry(ptr, type, member) 	\
	container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)					\
	for (pos = list_entry((head)->next, typeof(*pos), member);		\
		prefetch(pos->member.next), &pos->member != (head); 	\
		pos = list_entry(pos->member.next, typeof(*pos), member))		 

#define list_for_each_read(pos, head) 			\
	for ((pos) = (pos)->next; 					\
		prefetch((pos)->next), (pos) != (head); 	\
		(pos) = (pos)->next)


#define INIT_LIST_HEAD(list)	\
	do {						\
		(list)->next = list;		\
		(list)->prev = list;		\
	}while(0)

void list_add(struct list_head *new, struct list_head *head);
int list_empty(const struct list_head *head);
void list_del(struct list_head *entry);

#endif
