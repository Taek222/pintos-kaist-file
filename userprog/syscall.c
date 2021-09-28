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

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void check_address(uaddr);
static int64_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

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
}

/* The main system call interface */
#define DEBUG
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.

	printf("system call!\n");
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
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
	case SYS_WRITE:
		halt(); // #ifdef DEBUG FOR TESTING
		// args-single이나 halt나 exit이나 출력을 위해 write syscall을 사용하므로 잘 작동하는지 테스트
		break;
	default:
		thread_exit();
		break;
	}

	thread_exit();
}

/* Just check whether the address is under KERN_BASE */
void check_address(uaddr)
{
	if (!(is_user_vaddr(uaddr))){
		exit(-1);
	}
}

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}

void halt (void)
{
	power_off();
}

void exit (int status)
{
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

bool create (const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
	return filesys_remove(file);
}