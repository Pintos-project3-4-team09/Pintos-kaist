/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "kernel/bitmap.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *bitmap_table;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
/* Pintos uses disks this way:
0:0 - boot loader, command line args, and operating system kernel
0:1 - file system
1:0 - scratch
1:1 - swap */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1,1);
	disk_sector_t total_size = disk_size(swap_disk);
	bitmap_table = bitmap_create(total_size);


}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	// printf("swap_idx : %d \n", anon_page->swap_idx);
	bitmap_scan_and_flip(bitmap_table,anon_page->swap_idx,8,true);
	for (int i = 0; i < 8; i++){
		disk_read(swap_disk, page->anon.swap_idx + i ,kva+(DISK_SECTOR_SIZE * i));
	}
	pml4_set_page(thread_current()->pml4, page->va, kva, page->writable);
	// if (anon_page->swap_idx == 29000){
	// 	printf("@@@@@@@@@@@@@@@@@@\n");
	// }
	// page->anon.swap_idx = 0;
	// if (lock_held_by_current_thread(&swap_lock)){
	// 	lock_release(&swap_lock);
	// }
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	size_t start = bitmap_scan_and_flip(bitmap_table,0,8,false);
	if (start == BITMAP_ERROR){
		
		return false;

	}
	for (int i = 0; i < 8; i++){
		disk_write(swap_disk, start+i, page->frame->kva + (DISK_SECTOR_SIZE * i));
	}
	pml4_clear_page(thread_current()->pml4, page->va);
	page->anon.swap_idx = start;
	palloc_free_page(page->frame->kva);
	free(page->frame);
	page->frame = NULL;

	return true;
	
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
