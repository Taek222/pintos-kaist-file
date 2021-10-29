/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"


#define DBG
#ifdef DBG
void hash_action_func_print (struct hash_elem *e, void *aux){
	struct page *page = hash_entry(e, struct page, hash_elem);
	printf("%p - ", page->va);
}
#endif

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		bool (*initializer)(struct page *, enum vm_type, void *);
		switch(type){
			// # ifdef DEBUG 
			// case VM_UNINIT:
			// 	initializer = uninit_initialize;
			// 	break;
			case VM_ANON: case VM_ANON|VM_MARKER_0:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
		}
		
		struct page *new_page = malloc(sizeof(struct page));
		// new_page->va = upage;
		// vm_do_claim_page(new_page); // #ifdef DBG - false일때 처리?
		uninit_new (new_page, upage, init, type, aux, initializer);

		new_page->writable = writable;

		/* TODO: Insert the page into the spt. */
		spt_insert_page(spt, new_page); // should always return true - checked that upage is not in spt

	#ifdef DBG
		printf("Inserted new page into SPT - va : %p / writable : %d\n", new_page->va, writable);
	#endif

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;

	/* TODO: Fill this function. */
	struct page dummy_page; dummy_page.va = va; // dummy for hashing
	struct hash_elem *e;
	e = hash_find(&spt->spt_hash, &dummy_page.hash_elem);

	if(e == NULL)
		return NULL;
	
	return page = hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */

	// checks that the virtual address does not exist in the given supplemental page table.
	// Q. 그래서 만약 이미 SPT에 page 있으면 넣지 마? 아니면 replace해?
	// > succ 있는거 보니까, 이미 있으면 넣지 말고 false return 하는 것 같음
	struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);
	if(e != NULL) // page already in SPT
		return succ; // false, fail

	// page not in SPT
	hash_insert (&spt->spt_hash, &page->hash_elem);	
	return succ = true;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	void * kva = palloc_get_page(PAL_USER);
	if (kva == NULL){
		// Todo... eviction
		/*
		Frame eviction은 어떻게 이루어질까?
		> frame 얻기 위한 palloc 실패 시 
		→ Replacement policy에 따라 frame table에서 가장 안 쓰이는 frame 하나 집어서, 기존 page와의 연결 끊고 새로운 page 연결

		연결 끊긴 기존 page는 swap table에 저장 (swapped-out)
		
		struct frame은 한 번 만들면, page만 갈아끼우는 방식으로 재사용될 것 같음
		그니까, 한번 할당한 frame kernel kva를 free 하는건 아닌 것 같음.

		Q. swapped-out page에 파일의 어느 위치까지 읽었는지 offset같은거 저장해야 하지 않을까?
		> struct file_page 같은데에 새로운 member 만들어야 할 듯?

		-- 확실하진 않지만 일단 디자인이 이럼 --
		*/
	}

	struct frame *frame = malloc(sizeof(struct frame)); // #ifdef DEBUG - what if this fails?
	frame->kva = kva;
	// frame->page = malloc(sizeof(struct page));

	ASSERT (frame != NULL);
	// ASSERT (frame->page == NULL); // #ifdef DEBUG
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	// 27Oct21 - Introduction - Handling page fault 참고
	// Step 1. Locate the page that faulted in the supplemental page table
	void * fpage_uvaddr = (uint64_t)addr - ((uint64_t)addr%PGSIZE); // round down to nearest PGSIZE
	struct page *fpage = spt_find_page(spt, fpage_uvaddr);
	
	// Invalid access - Not in SPT / kernel vaddr / write request to read-only page
	if(fpage == NULL || is_kernel_vaddr(addr) || (write && !fpage->writable)){
		#ifdef DBG
		printf("Invalid access on vm_try_handle_fault - %p\n", addr);
		#endif

		return false;
	}
	//how to validate fault from this information?

#ifdef DBG
	printf("-- Fault on page with va %p --\n", fpage->va);

	// print va's of pages saved in SPT
	printf("Current hash : \n");
	hash_apply(&spt->spt_hash, hash_action_func_print);
	printf("\n");
#endif

	// Step 2~4.
	bool gotFrame = vm_do_claim_page (fpage);

	#ifdef DBG
	if (gotFrame) printf("!! got frame mapped on %p !!\n\n", fpage->va);
	else printf("XX frame map fail on %p XX\n\n", fpage->va);
	#endif

	return gotFrame;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
// Prerequisite : struct page assigned to va and saved on the SPT
bool
vm_claim_page (void *va UNUSED) {

	/* TODO: Fill this function */
	// 22Oct21 - va (user vaddr?) 에 해당하는 struct page 가져와서 vm_do_claim_page 호출

	ASSERT(is_user_vaddr(va)) // 체크용
	// struct thread *cur = thread_current();
	// void * kvaddr = pml4_get_page(cur->pml4, va);

	// search SPT for page correspoinding to va
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page * page = spt_find_page (spt, va);
	if (page == NULL){
		// #ifdef DEBUG
		// page corresponding to va doesn't exist!
		return false;
	}
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// page와 frame에 저장된 실제 physical memory 주소 (kernel vaddr) 관계를 page table에 등록
	struct thread *cur = thread_current();

	// bool writable = is_writable((uint64_t *)frame->kva); // #ifdef DBG
	bool writable = page->writable;

	pml4_set_page(cur->pml4, page->va, frame->kva, writable);
	// add the mapping from the virtual address to the physical address in the page table.

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
// Docs - Hash Table 코드 참고
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

bool page_less (const struct hash_elem *a_,
           		const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}

void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
