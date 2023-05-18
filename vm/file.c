/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

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

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	uint32_t read_bytes = file_length(file) < length ? file_length(file) : length;
	uint32_t zero_bytes = read_bytes % PAGE_SIZE == 0 ? 0 : PAGE_SIZE - (read_bytes % PAGE_SIZE);
	void * init_addr = addr;
	// struct file *re_file = file_reopen(file);
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(addr) == 0);
	ASSERT(offset % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// void *aux = NULL;
		// struct aux *aux = palloc_get_page(PAL_USER);
		// struct aux *auxs = calloc(1,sizeof(struct aux));
		struct aux *auxs = (struct aux *)malloc(sizeof(struct aux));

		auxs->file = file;
		auxs->ofs = offset;
		auxs->read_bytes = page_read_bytes;
		auxs->zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer (VM_FILE, addr,
					writable, lazy_load_segment, auxs))
			return NULL;
		struct page *page = spt_find_page(&thread_current()->spt,addr);
		page->map_file = file;
		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return init_addr;

}

/* Do the munmap */
void
do_munmap (void *addr) {
	uint64_t cur_pml4 = thread_current()->pml4;
	struct page *page = spt_find_page(&thread_current()->spt,addr);
	if (page == NULL){
		return;
	}
	struct file *file = &page->map_file;
	if (!file){
		return ;
	}
	uint32_t read_bytes = file_length(file);
	
	while(read_bytes > 0){
		uint32_t page_read_bytes = read_bytes < PAGE_SIZE ? read_bytes : PAGE_SIZE;
		
		if (pml4_is_dirty(cur_pml4, addr)) {
			lock_acquire(&filesys_lock);
			int write_byte = file_write(file, addr, read_bytes);
			lock_release(&filesys_lock);
			pml4_set_dirty(cur_pml4,addr,0);
		}
		page->va = NULL;
		addr -= PAGE_SIZE;
		read_bytes -= page_read_bytes;
		spt_remove_page(&thread_current()->spt,page);
		pml4_clear_page(cur_pml4,addr);

	}

}
