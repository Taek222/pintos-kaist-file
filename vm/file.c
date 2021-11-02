/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

// used in lazy allocation - from process.c
// 나중에 struct file_page에 vm_initializer *init 같은거 만들어서 uninit의 init 함수 (lazy_load_segment) 넘겨주는 식으로 리팩토링
static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct lazy_load_info * lazy_load_info = (struct lazy_load_info *)aux;
	struct file * file = lazy_load_info->file;
	size_t page_read_bytes = lazy_load_info->page_read_bytes;
	size_t page_zero_bytes = lazy_load_info->page_zero_bytes;
	off_t offset = lazy_load_info->offset;

	file_seek(file, offset);

	//vm_do_claim_page(page);
	ASSERT (page->frame != NULL); 	//이 상황에서 page->frame이 제대로 설정돼있는가?
	void * kva = page->frame->kva;
	if (file_read(file, kva, page_read_bytes) != (int)page_read_bytes)
	{
		//palloc_free_page(page); // #ifdef DBG Q. 여기서 free해주는거 맞아?
		free(lazy_load_info);
		return false;
	}

	memset(kva + page_read_bytes, 0, page_zero_bytes);
	free(lazy_load_info);
	return true;
}

/* Do the mmap */
// similar design with load_segment - map consecutive pages until length runs out
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	// ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	// ASSERT(ofs % PGSIZE == 0);


	void *start_addr = addr; // return value or in case of fail - free from this addr
	struct thread *t = thread_current();

	// file_seek(file, offset); // change offset itself
	
	// allocate at least one page
	// throw off data that sticks out 
	do{
		// Fail : pages mapped overlaps other existing pages
		if(spt_find_page(&t->spt, addr) != NULL){
			void *free_addr = start_addr; // get page from this user vaddr and destroy them
			while(free_addr < addr){
				// free allocated uninit page
				struct page *page = spt_find_page(&t->spt, free_addr);
				destroy(page); // uninit destroy - free aux
				free(page->frame);
				free(page);

				free_addr += PGSIZE;
			}
			return NULL;
		}

		size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		// file info to load onto memory once fault occurs
		struct lazy_load_info *lazy_load_info = malloc(sizeof(struct lazy_load_info));
		lazy_load_info->file = file;
		lazy_load_info->page_read_bytes = page_read_bytes;
		lazy_load_info->page_zero_bytes = page_zero_bytes;
		lazy_load_info->offset = offset;
		void *aux = lazy_load_info;
		if (!vm_alloc_page_with_initializer(VM_FILE, addr,
											writable, lazy_load_segment, aux))

		offset += page_read_bytes;
		length -= page_read_bytes;
		addr += PGSIZE;
	}while(length > PGSIZE);

	return start_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
