#ifdef DEBUG
#include "threads/thread.h"

void print_listContent(struct list *ready_list)
{
    if (list_begin(&ready_list) != list_end(&ready_list))
    {
        printf("Printing ready_list of size : %ld\n", list_size(&ready_list));
    }

    struct list_elem *e;
    for (e = list_begin(&ready_list); e != list_end(&ready_list);
         e = list_next(e))
    {
        struct thread *f = list_entry(e, struct thread, elem);
        printf("%s\n", f->name);
    }
}
#endif