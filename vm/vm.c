/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <string.h>
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
	list_init (&frame_table);
	// lock_init(&swap_lock);


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
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	if (spt_find_page (spt, upage) == NULL) {
		struct page *new_page = (struct page *)malloc(sizeof(struct page));
		switch (VM_TYPE(type))
		{
		case VM_ANON:
			uninit_new(new_page,upage,init,type,aux,anon_initializer);
			break;
		case VM_FILE:
			uninit_new(new_page,upage,init,type,aux,file_backed_initializer);
			break;
		default:
			break;
		}
		new_page->writable = writable;
		return spt_insert_page(spt,new_page);
	}
	return false;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
 // 인자로 넘겨진 보조 페이지 테이블에서로부터 가상 주소(va)와 대응되는 페이지 구조체를 찾아서 반환합니다. 실패했을 경우 NULL를 반환합니다.
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
	struct page *page = NULL;
	page = (struct page *)malloc(sizeof(struct page));
	/* TODO: Fill this function. */
	struct hash_elem *e;
	page->va = pg_round_down(va);
	e = hash_find (&spt->spt_hash, &page->hash_elem);
	free(page);
	
	return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
// 인자로 주어진 보조 페이지 테이블에 페이지 구조체를 삽입합니다. 이 함수에서 주어진 보충 테이블에서 가상 주소가 존재하지 않는지 검사해야 합니다.
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
					 struct page *page UNUSED)
{
	int succ = false;
	/* TODO: Fill this function. */
	struct hash_elem *result = hash_insert(&spt->spt_hash, &page->hash_elem);
	if (result == NULL){
		succ = true;
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->spt_hash,&page->hash_elem);
	vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	 /* TODO: The policy for eviction is up to you. */
	struct frame *victim = list_entry(list_pop_front(&frame_table),struct frame,frame_elem);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	if (victim == NULL) {
		return NULL;
	}
	swap_out(victim->page);
	// if (!swap_out(victim->page)){
	// 		// exit(-1);
	// 		return NULL;
	// 	}
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	// struct frame *frame = palloc_get_page(PAL_USER);
	struct frame *frame = malloc(sizeof(struct frame));
	// struct frame *frame = calloc(1,sizeof(struct frame));

	frame->page = NULL;
	frame->kva = palloc_get_page(PAL_USER);


	// todo: swap-out
	if (frame->kva == NULL) {
		// lock_acquire(&swap_lock);
		
		struct frame *out_frame = vm_evict_frame();
		// if (out_frame == NULL){
		// 	return NULL;
		// }
				
		frame->kva = palloc_get_page(PAL_USER);
		// if(frame->kva == NULL){
		// 	printf("Fail allocate frame !!!!!!!!!!\n");
		// }
		// frame->kva = out_frame->kva;
	}
	list_push_back(&frame_table,&frame->frame_elem);
	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	vm_alloc_page(VM_ANON,addr,1);
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
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	// write 어디서 고려?
	if (is_kernel_vaddr(addr)){
		return false;
	}
	if (!not_present ){
		return false;
	}
	void * rsp = user ? f->rsp : thread_current()->user_rsp;

	if (rsp - 8 <= addr || rsp < addr){
		if (addr >= (USER_STACK - STACK_SIZE) && addr <= USER_STACK){
			vm_stack_growth(pg_round_down(addr));
		}
	}
	
	struct page *page = spt_find_page(spt,pg_round_down(addr));
	
	if (page == NULL){
		return false;
	}
	
	return vm_claim_page(page->va);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = spt_find_page(&thread_current()->spt,va);
	/* TODO: Fill this function */
	if (page == NULL){
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
	struct thread *cur = thread_current();
	pml4_set_page(cur->pml4,page->va,frame->kva,page->writable);
	
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
		
	struct hash_iterator i;

	hash_first (&i, &src->spt_hash);
	while (hash_next (&i))
	{
		struct page *f = hash_entry (hash_cur (&i), struct page, hash_elem);
		enum vm_type f_cur_type = f->operations->type;
		enum vm_type f_real_type = f->uninit.type;
		void *upage = f->va;
		bool writable = f->writable;
		vm_initializer *init = f->uninit.init;
		void *aux = f->uninit.aux;

		if (f_cur_type == VM_UNINIT){
			if( !vm_alloc_page_with_initializer (f_real_type,upage,writable,init,aux)){
				return false;
			}
		}
		else {
			if(!vm_alloc_page(f_real_type,upage,writable)){
				return false;
			}
			if(!vm_claim_page(upage)){
				return false;
			}
			// file 분기
			struct page *child_page = spt_find_page(dst,upage);
			memcpy(child_page->frame->kva,f->frame->kva,PGSIZE);
			
		}
		// else {
		// 	if(!vm_alloc_page(f_real_type,upage,writable)){
		// 		return false;
		// 	}
		// 	if (f_cur_type == VM_ANON){
		// 		if(!vm_claim_page(upage)){
		// 			return false;
		// 		}
		// 		struct page *child_page = spt_find_page(dst,upage);
		// 		memcpy(child_page->frame->kva,f->frame->kva,PGSIZE);

		// 	}
		// 	// else if (f_cur_type == VM_FILE){
		// 	else {
		// 		if(!vm_claim_file_page(upage,f->frame)){
		// 			// struct page *child_page = spt_find_page(dst,upage);
		// 			// child_page->frame = f->frame;
		// 			// child_page->frame->kva = f->frame->kva;
		// 			// memcpy(child_page->frame->kva,f->frame->kva,PGSIZE);

		// 			return false;
		// 		}
		// 	}
		// }
	}
	return true;
}
static bool 
vm_claim_file_page (void *va UNUSED,struct frame *frame UNUSED) {
	struct page *page = spt_find_page(&thread_current()->spt,va);
	/* TODO: Fill this function */
	if (page == NULL){
		return false;
	}
	// page->frame = frame;
	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *cur = thread_current();
	pml4_set_page(cur->pml4,page->va,frame->kva,page->writable);
	
	return swap_in (page, frame->kva);
}

void spt_dealloc(struct hash_elem *e,void *aux){
	struct page *page = hash_entry(e, struct page, hash_elem);
	
	destroy (page);
	free (page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */


	// hash_destroy(&spt->spt_hash,&spt_dealloc);
	hash_clear(&spt->spt_hash,&spt_dealloc);
	// free(spt->spt_hash.buckets);


}
/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}
/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a->va < b->va;
}