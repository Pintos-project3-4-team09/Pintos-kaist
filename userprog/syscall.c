#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <devices/input.h>
#include "threads/palloc.h"


void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void halt(void);
void exit(int status);
tid_t fork(const char *thread_name, struct intr_frame *f);
tid_t exec(const char *cmd_line);
void close(int fd);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

static struct file *find_file_by_fd(int fd);
int add_file_to_fdt(struct file *file);
void remove_file(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi,f);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = process_wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;

	default:
		exit(-1);
		break;
	}
	// thread_exit();
}
// SYS_HALT,                   /* Halt the operating system. */
// SYS_EXIT,                   /* Terminate this process. */
// SYS_FORK,                   /* Clone current process. */
// SYS_EXEC,                   /* Switch current process. */
// SYS_WAIT,                   /* Wait for a child process to die. */
// SYS_CREATE,                 /* Create a file. */
// SYS_REMOVE,                 /* Delete a file. */
// SYS_OPEN,                   /* Open a file. */
// SYS_FILESIZE,               /* Obtain a file's size. */
// SYS_READ,                   /* Read from a file. */
// SYS_WRITE,                  /* Write to a file. */
// SYS_SEEK,                   /* Change position in a file. */
// SYS_TELL,                   /* Report current position in a file. */
// SYS_CLOSE,                  /* Close a file. */

void check_address(void *addr)
{
	struct thread *cur = thread_current();
	// 가상 주소가 있는지, 유저 영역인지, 하드 웨어에 멥핑되어 있는지
	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

tid_t exec(const char *cmd_line){
	check_address(cmd_line);
	// file name이 cleanup으로 날아가니까 복사
	int size = strlen(cmd_line)+1; // null 까지
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL){
		exit(-1);
	}
	strlcpy(fn_copy, cmd_line,size);

	if(process_exec(fn_copy) == -1 ){
		return -1;
	}

	NOT_REACHED();
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int open(const char *file)
{
	check_address(file);
	struct file *file_obj = filesys_open(file);
	if (file_obj == NULL)
	{
		return -1;
	}
	int fd = add_file_to_fdt(file_obj);
	if (fd == -1)
	{
		file_close(file_obj);
	}
	return fd;
}

int filesize(int fd)
{
	struct file *openfile = find_file_by_fd(fd);
	if (openfile == NULL)
	{
		return -1;
	}
	return file_length(openfile);
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	if (fd == 1)
	{
		return -1;
	}
	// fd가 0 이면 키보드 입력을 버퍼에 저장 후 크기를 리턴
	if (fd == 0)
	{
		lock_acquire(&filesys_lock);
		int byte = input_getc();
		lock_release(&filesys_lock);
		return byte;
	}
	struct file *file = thread_current()->fd_table[fd];
	// fd가 0이 아니고 파일 열리면 파일 크기만큼 읽고 저장 후 크기 리턴
	if (file)
	{
		lock_acquire(&filesys_lock);
		int read_byte = file_read(file, buffer, size);
		lock_release(&filesys_lock);
		return read_byte;
	}
	return -1;
}

int write(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	// stdin
	if (fd == 0)
	{
		return -1;
	}
	// stdout
	if (fd == 1)
	{
		lock_acquire(&filesys_lock);
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}
	struct file *file = thread_current()->fd_table[fd];
	if (file)
	{
		lock_acquire(&filesys_lock);
		int write_byte = file_write(file, buffer, size);
		lock_release(&filesys_lock);
		return write_byte;
	}
	return -1;
}
void seek(int fd, unsigned position)
{
	struct file *cur_file = thread_current()->fd_table[fd];
	if (cur_file)
	{
		file_seek(cur_file, position);
	}
}
unsigned tell(int fd)
{
	struct file *cur_file = thread_current()->fd_table[fd];
	if (cur_file)
	{
		return file_tell(cur_file);
	}
}

void close(int fd)
{
	struct file *openfile = find_file_by_fd(fd);
	if (openfile == NULL)
		return;
	remove_file(fd);
}

// file 위치 찾기
static struct file *find_file_by_fd(int fd)
{

	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
	{
		return NULL;
	}
	return cur->fd_table[fd];
}

int add_file_to_fdt(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fd_table;

	// 1. fd가 리미트 보다 작고
	// 2. fdt에 값이 있다면 루프
	// fdt[i]값이 NULL일 때 탈출
	while ((cur->fd_idx < FDCOUNT_LIMIT) && fdt[cur->fd_idx])
	{
		cur->fd_idx++;
	}
	if (cur->fd_idx >= FDCOUNT_LIMIT)
		return -1;

	fdt[cur->fd_idx] = file;

	return cur->fd_idx;
}

void remove_file(int fd)
{
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fd_table[fd] = NULL;
}

// switch (phdr.p_type) {
// 			case PT_NULL:
// 			case PT_NOTE:
// 			case PT_PHDR:
// 			case PT_STACK:
// 			default:
// 				/* Ignore this segment. */
// 				break;
// 			case PT_DYNAMIC:
// 			case PT_INTERP:
// 			case PT_SHLIB:
// 				goto done;
// 			case PT_LOAD:
// 				if (validate_segment (&phdr, file)) {
// 					bool writable = (phdr.p_flags & PF_W) != 0;
// 					uint64_t file_page = phdr.p_offset & ~PGMASK;
// 					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
// 					uint64_t page_offset = phdr.p_vaddr & PGMASK;
// 					uint32_t read_bytes, zero_bytes;
// 					if (phdr.p_filesz > 0) {
// 						/* Normal segment.
// 						 * Read initial part from disk and zero the rest. */
// 						read_bytes = page_offset + phdr.p_filesz;
// 						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
// 								- read_bytes);
// 					} else {
// 						/* Entirely zero.
// 						 * Don't read anything from disk. */
// 						read_bytes = 0;
// 						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
// 					}
// 					if (!load_segment (file, file_page, (void *) mem_page,
// 								read_bytes, zero_bytes, writable))
// 						goto done;
// 				}
// 				else
// 					goto done;
// 				break;
// 		}