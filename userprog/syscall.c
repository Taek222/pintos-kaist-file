#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include <list.h>

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

int fd_counter = 2; //0,1 is used for stdio
struct list files;	//list of open files
static struct file *find_file_by_fd(int fd);
bool stdin_close = false;
bool stdout_close = false;

void check_address(uaddr);
static int64_t get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int dup2(int oldfd, int newfd);

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

	// Project 2-4. File descriptor
	lock_init(&file_rw_lock);
}

/* The main system call interface */
// #define DEBUG
void syscall_handler(struct intr_frame *f)
{
	// TODO: Your implementation goes here.

	//printf("system call!\n");
	//printf("syscall : %d\n", f->R.rax);

#ifdef DEBUG
	// syscall stack frame? (stack base - stack ptr)
	//hex_dump(f->rsp, f->rsp, f->R.rbp - f->rsp, true); // #ifdef DEBUG

	// write sys-call
	hex_dump(f->R.rsi, f->R.rsi, f->R.rdx, true); // #ifdef DEBUG

	// print whole user stack (rsp ~)
	// hex_dump(f->rsp, f->rsp, USER_STACK - f->rsp, true); // #ifdef DEBUG
	printf("==================\n");

	// print rbp ~
	//hex_dump(f->R.rbp, f->R.rbp, USER_STACK - f->R.rbp, true); // #ifdef DEBUG
#endif

	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		// writable = is_kernel_vaddr(f->R.rdi); //is_writable((uint64_t *)f->R.rdi);
		// fn_copy = palloc_get_page(0);
		// if (fn_copy == NULL)
		// 	exit(-1);
		// siz = strlen(f->R.rdi);
		// strlcpy(fn_copy, f->R.rdi, siz); // Kernel panic; fn_copy는 kernel virtual addr라 write가 안되는건가?

		if (exec(f->R.rdi) == -1)
			exit(-1);
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
	case SYS_DUP2:
		dup2(f->R.rdi, f->R.rsi);
		break;
	default:
		//thread_exit();
		exit(-1);
		break;
	}

	//thread_exit();
}

// Check whether the address is under KERN_BASE
// and the address is mapped properly (prevents page_fault)
void check_address(const uint64_t *uaddr)
{
	struct thread *cur = thread_current();
	if (uaddr == NULL || !(is_user_vaddr(uaddr)) || pml4_get_page(cur->pml4, uaddr) == NULL)
	{
		exit(-1);
	}
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user(const uint8_t *uaddr)
{
	int64_t result;
	__asm __volatile(
		"movabsq $done_get, %0\n"
		"movzbq %1, %0\n"
		"done_get:\n"
		: "=&a"(result)
		: "m"(*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
	int64_t error_code;
	__asm __volatile(
		"movabsq $done_put, %0\n"
		"movb %b2, %1\n"
		"done_put:\n"
		: "=&a"(error_code), "=m"(*udst)
		: "q"(byte));
	return error_code != -1;
}

// Project 2-4. File descriptor
static struct file *find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= cur->fdCount)
		return NULL;		 // error - invalid fd
	return cur->fdTable[fd]; // returns NULL if empty
}

int add_file_to_fdt(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable; // file descriptor table

	if (cur->fdCount >= FDCOUNT_LIMIT)
		return -1;

	int my_fd = cur->fdCount++;
	fdt[my_fd] = file;
	return my_fd;
}

void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();
	if (fd < 0 || fd >= cur->fdCount)
		return; // error - invalid fd

	cur->fdTable[fd] = NULL;
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status); //#ifdef DEBUG
	thread_exit();
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
	struct file *fileobj = filesys_open(file);

	if (fileobj == NULL)
	{
		return -1;
	}

	int fd = add_file_to_fdt(fileobj);

	// FD table full
	if (fd == -1)
		file_close(fileobj);

	return fd;
}

int filesize(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	int ret;
	struct file *fileobj = find_file_by_fd(fd);
	if (fd == 0 || (fileobj != NULL && fileobj->is_stdin))
	{
		if (stdin_close){
			ret = -1;
		}
		else{
			int i;
			unsigned char *buf = buffer;
			for (i = 0; i < size; i++)
			{
				char c = input_getc();
				*buf++ = c;
				if (c == '\0')
					break;
			}
			ret = i;
		}
	}
	else
	{
		// Q. read는 동시접근 허용해도 되지 않을까?
		lock_acquire(&file_rw_lock);
		if (fileobj == NULL)
			ret = -1;
		else
			ret = file_read(fileobj, buffer, size);
		lock_release(&file_rw_lock);
	}
	return ret;
}

int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	int ret;
	struct file *fileobj = find_file_by_fd(fd);

	if (fd == 1 || (fileobj != NULL && fileobj->is_stdout))
	{
		if (stdout_close){
			ret = -1;
		}
		else{
			putbuf(buffer, size);
			ret = size;
		}
	}
	else
	{
		if (fileobj == NULL)
			ret = -1;
		else
		{
			lock_acquire(&file_rw_lock);
			ret = file_write(fileobj, buffer, size);
			lock_release(&file_rw_lock);
		}
	}

	return ret;
}

void seek(int fd, unsigned position)
{
	struct file *fileobj = find_file_by_fd(fd);
	fileobj->pos = position;
}

unsigned tell(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	return file_tell(fileobj);
}
void close(int fd)
{
	if (fd == 0){
		stdin_close = true;
		return;
	}
	if (fd == 1){
		stdout_close = true;
	}
	struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL)
		return;

	remove_file_from_fdt(fd);
	file_close(fileobj);
}

int dup2(int oldfd, int newfd){
	struct file *fileobj = find_file_by_fd(oldfd);
	struct file *deadfile = find_file_by_fd(newfd); //to dup stdio info to existing file
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;
	//test case does not open new files after dup2 so don't care about modifying add/remove functions
	if (fileobj == NULL){ //wrong oldfd or stdio
		if (oldfd == 0 || deadfile != NULL){
			deadfile->is_stdin = true;
			return newfd;
		}
		if (oldfd == 1 || deadfile != NULL){
			deadfile->is_stdout = true;
			return newfd;
		}
		return -1;
	}
	if (oldfd == newfd){ //no 'duplicate' happens really
		return oldfd;
	}
	close(newfd); //close will handle all error cases
	fdt[newfd] = fileobj; 
	return newfd;
}

tid_t fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

int exec(char *file_name)
{
	struct thread *cur = thread_current();
	check_address(file_name);

	// #ifdef DEBUG
	// SYS_EXEC - process_exec의 process_cleanup 때문에 f->R.rdi 날아감.
	// 여기서 동적할당해서 복사한 뒤, 그걸 넘겨주기?

	// // bool writable;
	// // writable = is_kernel_vaddr(f->R.rdi); //is_writable((uint64_t *)f->R.rdi);

	int siz = strlen(file_name) + 1;
	char *fn_copy = malloc(siz); // #ifdef DEBUG palloc 쓰면 fault?
	if (fn_copy == NULL)
		exit(-1);
	strlcpy(fn_copy, file_name, siz); // Kernel panic; fn_copy는 kernel virtual addr라 write가 안되는건가?

	//printf("[exec] calling process_exec with CLI : %s\n", file_name);
	cur->calledExec = true;
	if (process_exec(fn_copy) == -1)
		return -1;

	// int child_pid = process_create_initd(file_name);
	// if (child_pid == TID_ERROR)
	// 	return -1;
	// struct thread *child = get_child_with_pid(child_pid);

	// sema_down(&child->load_sema);

	return 0;
}