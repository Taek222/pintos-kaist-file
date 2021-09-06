#ifdef DEBUG
#include "threads/thread.h"

void print_listContent(struct list *target_list)
{
    if (list_begin(&target_list) != list_end(&target_list))
    {
        printf("Printing list of size : %ld\n", list_size(target_list));
    }

    struct list_elem *e;
    for (e = list_begin(target_list); e != list_end(target_list);
         e = list_next(e))
    {
        struct thread *f = list_entry(e, struct thread, elem);
        printf("%s\n", f->name);
    }
}
#endif