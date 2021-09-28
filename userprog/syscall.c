#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

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
	case SYS_WRITE:
		halt(); // #ifdef DEBUG FOR TESTING
		// args-single이나 halt나 exit이나 출력을 위해 write syscall을 사용하므로 잘 작동하는지 테스트
		break;
	default:
		break;
	}

	thread_exit();
}

void halt(void)
{
	power_off();
}