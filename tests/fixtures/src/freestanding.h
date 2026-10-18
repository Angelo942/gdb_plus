// Just enough of a C library to build the fixtures for foreign architectures without a cross libc:
// a _start, raw syscalls and the few functions the fixtures call. Compiled with
//   clang --target=<triple> -ffreestanding -nostdlib -static -DFREESTANDING
// The binaries run under qemu-user (tests/integration/conftest.py, target axis).
//
// Output functions write each call with a single write() like glibc does with an unbuffered stdout,
// so the tests that count write syscalls see the same events on every architecture.
#ifndef FREESTANDING_H
#define FREESTANDING_H

#include <stdarg.h>
#include <stddef.h>

#if defined(__x86_64__)
#define SYS_mprotect 10
#define SYS_read 0
#define SYS_write 1
#define SYS_getpid 39
#define SYS_kill 62
#define SYS_exit_group 231
#elif defined(__i386__) || defined(__arm__)
#define SYS_mprotect 125
#define SYS_read 3
#define SYS_write 4
#define SYS_getpid 20
#define SYS_kill 37
#define SYS_exit_group 252
#if defined(__arm__)
#undef SYS_exit_group
#define SYS_exit_group 248
#endif
#elif defined(__aarch64__) || defined(__riscv)
#define SYS_mprotect 226
#define SYS_read 63
#define SYS_write 64
#define SYS_getpid 172
#define SYS_kill 129
#define SYS_exit_group 94
#elif defined(__mips__) && _MIPS_SIM == _ABIO32
#define SYS_mprotect 4125
#define SYS_read 4003
#define SYS_write 4004
#define SYS_getpid 4020
#define SYS_kill 4037
#define SYS_exit_group 4246
#elif defined(__mips__) && _MIPS_SIM == _ABI64
#define SYS_mprotect 5010
#define SYS_read 5000
#define SYS_write 5001
#define SYS_getpid 5038
#define SYS_kill 5060
#define SYS_exit_group 5205
#else
#error "unsupported architecture"
#endif

#define stdin ((void *)0)
#define stdout ((void *)1)
#define _IONBF 2

static long raw_syscall(long n, long a, long b, long c) {
#if defined(__x86_64__)
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return ret;
#elif defined(__i386__)
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory");
    return ret;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
#elif defined(__arm__)
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
    return r0;
#elif defined(__riscv)
    register long a7 __asm__("a7") = n;
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2) : "memory");
    return a0;
#elif defined(__mips__)
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a1 __asm__("$5") = b;
    register long a2 __asm__("$6") = c;
    register long a3 __asm__("$7");
    __asm__ volatile("syscall"
                     : "+r"(v0), "=r"(a3)
                     : "r"(a0), "r"(a1), "r"(a2)
                     : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory");
    return a3 ? -v0 : v0;
#endif
}

static long raw_syscall4(long n, long a, long b, long c, long d) {
#if defined(__x86_64__)
    long ret;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx", "r11", "memory");
    return ret;
#elif defined(__i386__)
    long ret;
    __asm__ volatile("int $0x80" : "=a"(ret) : "a"(n), "b"(a), "c"(b), "d"(c), "S"(d) : "memory");
    return ret;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
#elif defined(__arm__)
    register long r7 __asm__("r7") = n;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2), "r"(r3) : "memory");
    return r0;
#elif defined(__riscv)
    register long a7 __asm__("a7") = n;
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long a3 __asm__("a3") = d;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2), "r"(a3) : "memory");
    return a0;
#elif defined(__mips__)
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a1 __asm__("$5") = b;
    register long a2 __asm__("$6") = c;
    register long a3 __asm__("$7") = d;
    __asm__ volatile("syscall"
                     : "+r"(v0), "+r"(a3)
                     : "r"(a0), "r"(a1), "r"(a2)
                     : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory");
    return a3 ? -v0 : v0;
#endif
}

static long syscall(long n, ...) {
    va_list list;
    va_start(list, n);
    long a = va_arg(list, long), b = va_arg(list, long), c = va_arg(list, long);
    va_end(list);
    return raw_syscall(n, a, b, c);
}

// The compiler may emit calls to these for struct copies and array initialisers, even at -O0
void *memset(void *destination, int value, size_t size) {
    unsigned char *d = destination;
    while (size--)
        *d++ = (unsigned char)value;
    return destination;
}

void *memcpy(void *destination, const void *source, size_t size) {
    unsigned char *d = destination;
    const unsigned char *s = source;
    while (size--)
        *d++ = *s++;
    return destination;
}

size_t strlen(const char *string) {
    size_t n = 0;
    while (string[n])
        n++;
    return n;
}

char *strcpy(char *destination, const char *source) {
    char *d = destination;
    while ((*d++ = *source++))
        ;
    return destination;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b)
        a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}

static char **environ_pointer;

char *getenv(const char *name) {
    size_t length = strlen(name);
    for (char **entry = environ_pointer; entry && *entry; entry++) {
        size_t i = 0;
        while (i < length && (*entry)[i] == name[i])
            i++;
        if (i == length && (*entry)[i] == '=')
            return *entry + length + 1;
    }
    return NULL;
}

// A bump allocator with a glibc-like size header, so that dbg.alloc() has a "malloc" to call
static unsigned char heap_arena[0x4000] __attribute__((aligned(16)));
static size_t heap_used;

void *malloc(size_t size) {
    size_t chunk = (size + sizeof(size_t) + 15) & ~(size_t)15;
    if (heap_used + chunk + 16 > sizeof(heap_arena))
        return NULL;
    unsigned char *pointer = heap_arena + heap_used + 16;
    ((size_t *)pointer)[-1] = chunk | 1;
    heap_used += chunk;
    return pointer;
}

void free(void *pointer) {
    (void)pointer;
}

int setvbuf(void *stream, char *buffer, int mode, size_t size) {
    return 0;
}

// Decimal without a division: 32 bit arm has no divide instruction and we don't link a libgcc
static size_t format_unsigned(char *out, unsigned long value) {
    static const unsigned long powers[] = {
#if __SIZEOF_LONG__ == 8
        10000000000000000000UL, 1000000000000000000UL, 100000000000000000UL, 10000000000000000UL,
        1000000000000000UL, 100000000000000UL, 10000000000000UL, 1000000000000UL, 100000000000UL, 10000000000UL,
#endif
        1000000000UL, 100000000UL, 10000000UL, 1000000UL, 100000UL, 10000UL, 1000UL, 100UL, 10UL, 1UL};
    size_t n = 0;
    int started = 0;
    for (size_t i = 0; i < sizeof(powers) / sizeof(powers[0]); i++) {
        char digit = '0';
        while (value >= powers[i]) {
            value -= powers[i];
            digit++;
        }
        if (digit != '0' || started || powers[i] == 1) {
            out[n++] = digit;
            started = 1;
        }
    }
    return n;
}

// %d %ld %x %lx %s only
int printf(const char *format, ...) {
    char out[0x200];
    size_t n = 0;
    va_list list;
    va_start(list, format);
    for (const char *f = format; *f && n < sizeof(out) - 32; f++) {
        if (*f != '%') {
            out[n++] = *f;
            continue;
        }
        f++;
        int is_long = 0;
        if (*f == 'l') {
            is_long = 1;
            f++;
        }
        if (*f == 'd') {
            long value = is_long ? va_arg(list, long) : va_arg(list, int);
            if (value < 0) {
                out[n++] = '-';
                value = -value;
            }
            n += format_unsigned(out + n, (unsigned long)value);
        } else if (*f == 'x') {
            unsigned long value = is_long ? va_arg(list, unsigned long) : va_arg(list, unsigned int);
            int shift = (is_long ? (int)sizeof(long) : (int)sizeof(int)) * 8 - 4;
            int started = 0;
            for (; shift >= 0; shift -= 4) {
                int digit = (value >> shift) & 0xf;
                if (digit || started || shift == 0) {
                    out[n++] = "0123456789abcdef"[digit];
                    started = 1;
                }
            }
        } else if (*f == 's') {
            const char *string = va_arg(list, const char *);
            while (*string && n < sizeof(out) - 1)
                out[n++] = *string++;
        } else {
            out[n++] = *f;
        }
    }
    va_end(list);
    syscall(SYS_write, 1, out, n);
    return (int)n;
}

int puts(const char *string) {
    char out[0x200];
    size_t n = strlen(string);
    if (n > sizeof(out) - 1)
        n = sizeof(out) - 1;
    memcpy(out, string, n);
    out[n++] = '\n';
    syscall(SYS_write, 1, out, n);
    return (int)n;
}

// One byte at a time, so that nothing after the newline is consumed
char *fgets(char *line, int size, void *stream) {
    int n = 0;
    while (n < size - 1) {
        char c;
        if (syscall(SYS_read, 0, &c, 1) != 1)
            break;
        line[n++] = c;
        if (c == '\n')
            break;
    }
    if (n == 0)
        return NULL;
    line[n] = 0;
    return line;
}

int atoi(const char *string) {
    int sign = 1, value = 0;
    if (*string == '-') {
        sign = -1;
        string++;
    }
    while (*string >= '0' && *string <= '9')
        value = value * 10 + (*string++ - '0');
    return sign * value;
}

int getpid(void) {
    return (int)syscall(SYS_getpid);
}

// signal() through rt_sigaction. Without SA_RESTORER the kernel (or qemu) provides the return trampoline.
#if defined(__mips__)
#define SIGUSR1 16
#define SIGUSR2 17
#if _MIPS_SIM == _ABI64
#define SYS_rt_sigaction 5013
#else
#define SYS_rt_sigaction 4194
#endif
#define SIGSET_BYTES 16
struct kernel_sigaction {
    unsigned int flags;
    void (*handler)(int);
    unsigned long mask[SIGSET_BYTES / sizeof(unsigned long)];
};
#else
#define SIGUSR1 10
#define SIGUSR2 12
#if defined(__arm__)
#define SYS_rt_sigaction 174
#elif defined(__i386__)
#define SYS_rt_sigaction 174
#elif defined(__x86_64__)
#define SYS_rt_sigaction 13
#else
#define SYS_rt_sigaction 134
#endif
#define SIGSET_BYTES 8
struct kernel_sigaction {
    void (*handler)(int);
    unsigned long flags;
#if !defined(__riscv)
    void (*restorer)(void);
#endif
    unsigned char mask[SIGSET_BYTES];
};
#endif
#define SIGSEGV 11
typedef void (*sighandler_t)(int);

sighandler_t signal(int number, sighandler_t handler) {
    struct kernel_sigaction action;
    memset(&action, 0, sizeof(action));
    action.handler = handler;
    action.flags = 0x10000000; // SA_RESTART
    raw_syscall4(SYS_rt_sigaction, number, (long)&action, 0, SIGSET_BYTES);
    return 0;
}

int raise(int number) {
    return (int)syscall(SYS_kill, (long)syscall(SYS_getpid), number);
}

// gdb_plus.syscall() needs it under QEMU to make the code writable
int mprotect(void *address, size_t length, int protection) {
    return (int)syscall(SYS_mprotect, address, length, protection);
}

int kill(int pid, int signal) {
    return (int)syscall(SYS_kill, pid, signal);
}

__attribute__((noreturn)) void _exit(int status) {
    for (;;)
        syscall(SYS_exit_group, status);
}

int main(int argc, char **argv);

__attribute__((noreturn, used)) void c_start(long *stack) {
    int argc = (int)stack[0];
    char **argv = (char **)(stack + 1);
    environ_pointer = argv + argc + 1;
    _exit(main(argc, argv));
}

// The kernel (or qemu) leaves argc at the stack pointer: hand it to c_start and keep the ABI's alignment.
// mips and riscv also need gp: the linker turns accesses to small globals into gp relative ones
__asm__(".text\n.global _start\n_start:\n"
#if defined(__x86_64__)
        "xor %rbp, %rbp\nmov %rsp, %rdi\nand $-16, %rsp\ncall c_start\n"
#elif defined(__i386__)
        "xor %ebp, %ebp\nmov %esp, %eax\nand $-16, %esp\nsub $12, %esp\npush %eax\ncall c_start\n"
#elif defined(__aarch64__)
        "mov x29, #0\nmov x30, #0\nmov x0, sp\nbl c_start\n"
#elif defined(__arm__)
        "mov fp, #0\nmov lr, #0\nmov r0, sp\nbic sp, sp, #7\nbl c_start\n"
#elif defined(__riscv)
        ".option push\n.option norelax\nla gp, __global_pointer$\n.option pop\nmv a0, sp\nandi sp, sp, -16\ncall c_start\n"
#elif defined(__mips__) && _MIPS_SIM == _ABIO32
        ".set push\n.set noreorder\nla $28, _gp\nmove $4, $29\naddiu $29, $29, -32\njal c_start\nnop\n.set pop\n"
#elif defined(__mips__)
        ".set push\n.set noreorder\ndla $28, _gp\nmove $4, $29\ndaddiu $29, $29, -32\njal c_start\nnop\n.set pop\n"
#endif
);

#endif
