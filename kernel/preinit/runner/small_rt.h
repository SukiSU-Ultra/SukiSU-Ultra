#pragma once

#include <sys/syscall.h>

// hint: -Wl,--entry=__start
#ifndef asm
#define asm __asm__
#endif

// syscall de-wrappers
#if defined(__aarch64__)
__attribute__((always_inline, noipa))
static long __syscall_raw(long n, long a, long b, long c, long d, long e, long f)
{
	register long 
		x8 asm("x8") = n,
		x0 asm("x0") = a,
		x1 asm("x1") = b,
		x2 asm("x2") = c,
		x3 asm("x3") = d,
		x4 asm("x4") = e,
		x5 asm("x5") = f;

	asm volatile("svc #0"
		:"=r"(x0)
		:"r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		:"memory");

	return x0;
}

#elif defined(__arm__)
__attribute__((always_inline, noipa))
static long __syscall_raw(long n, long a, long b, long c, long d, long e, long f)
{
	register long
		r7 asm("r7") = n,
		r0 asm("r0") = a,
		r1 asm("r1") = b,
		r2 asm("r2") = c,
		r3 asm("r3") = d,
		r4 asm("r4") = e,
		r5 asm("r5") = f;

	asm volatile("svc #0"
		: "=r"(r0)
		: "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
		: "memory");

	return r0;
}

#elif defined(__x86_64__)
__attribute__((always_inline, noipa))
static long __syscall_raw(long n, long a, long b, long c, long d, long e, long f)
{
	long ret;
	asm volatile(
		"mov %5, %%r10\n"
		"mov %6, %%r8\n"
		"mov %7, %%r9\n"
		"syscall"
		: "=a"(ret)
		: "a"(n), "D"(a), "S"(b), "d"(c), "r"(d), "r"(e), "r"(f)
		: "rcx", "r11", 
		"memory");

	return ret;
}

#elif defined(__i386__)
__attribute__((always_inline, noipa))
static long __syscall_raw(long n, long a, long b, long c, long d, long e, long f)
{
	long _eax = (long)(n);
	long _arg6 = (long)(f);
	__asm__ volatile (
		"pushl	%[_arg6]\n\t"
		"pushl	%%ebp\n\t"
		"movl	4(%%esp),%%ebp\n\t"
		"int	$0x80\n\t"
		"popl	%%ebp\n\t"
		"addl	$4,%%esp\n\t"
		: "+a"(_eax)
		: "b"(a),
		  "c"(b),
		  "d"(c),
		  "S"(d),
		  "D"(e),
		  [_arg6]"m"(_arg6)
		: "memory", "cc"
	);
	return _eax;
}
#endif

int __snall_rt_errno;

__attribute__((noinline))
static long __syscall_gate(long n, long a, long b, long c, long d, long e, long f)
{
	long ret = __syscall_raw(n, a, b, c, d, e, f);
	if (ret < 0 && ret >= -4095) {
		__snall_rt_errno = (int)(-ret);
		return -1;
	}
	return ret;
}
#define errno __snall_rt_errno

#define __syscall_0(name) 			__syscall_gate(name, 0, 0, 0, 0, 0, 0)
#define __syscall_1(name, a) 			__syscall_gate(name, a, 0, 0, 0, 0, 0)
#define __syscall_2(name, a, b)			__syscall_gate(name, a, b, 0, 0, 0, 0)
#define __syscall_3(name, a, b, c)		__syscall_gate(name, a, b, c, 0, 0, 0)
#define __syscall_4(name, a, b, c, d)		__syscall_gate(name, a, b, c, d, 0, 0)
#define __syscall_5(name, a, b, c, d, e)	__syscall_gate(name, a, b, c, d, e, 0)
#define __syscall_6(name, a, b, c, d, e, f)	__syscall_gate(name, a, b, c, d, e, f)

#define __syscall_arg_n(_1, _2, _3, _4, _5, _6, _7, N, ...) N
#define __syscall_count_args(...) __syscall_arg_n(__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0)
#define __syscall_concat(a, b) a##b
#define __syscall_exp(func, arg) __syscall_concat(func, arg)

// usage: syscall(SYS_getuid), syscall(SYS_newuname, &buf)
#define __syscall(...) __syscall_exp(__syscall_, __syscall_count_args(__VA_ARGS__))(__VA_ARGS__)

extern int main(int argc, char **argv, char **envp);
__attribute__((used))
void prep_main(long *sp)
{
	long argc = *sp;
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1; // we need to offset it by the number of argc's!

	long exit_code = main(argc, argv, envp);
	__syscall(SYS_exit, exit_code);
	__builtin_unreachable();
}

// arch specific small entry points
#if defined(__aarch64__)
__attribute__((naked))
void __start(void) {
	asm volatile(
		"mov x0, sp\n"
		"b prep_main\n"
	);
}

#elif defined(__arm__)
__attribute__((naked))
void __start(void) {
	asm volatile(
		"mov r0, sp\n"
		"b prep_main\n"
    );
}

#elif defined(__x86_64__)
__attribute__((naked, section(".text.start"))) 
void __start(void) {
	asm volatile(
		"mov %rsp, %rdi\n"
		"jmp prep_main\n"
	);
}
#elif defined(__i386__)
__attribute__((naked, section(".text.start"))) 
void __start(void) {
	asm volatile(
		"movl %esp, %eax\n"
		"pushl %eax\n"
		"call prep_main\n"
	);
}
#endif

