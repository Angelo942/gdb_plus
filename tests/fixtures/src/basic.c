// General purpose target: functions to break on, call, step over and finish,
// globals to read and write, a syscall to hook and a blocking read to interrupt.
// Compiled as `basic` (PIE), `basic_nopie`, `basic_i386` and `basic_<arch>` (freestanding, under QEMU).
// Also built with -DFREESTANDING for the architectures we have no cross libc for (see freestanding.h).
#ifdef FREESTANDING
#include "freestanding.h"
#else
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#endif
#include "labels.h"

char buffer[0x100] = "buffer content";
long counter = 0;
const char *greeting = "Hello gdb_plus";
unsigned char table[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

__attribute__((noinline)) long add(long a, long b) {
    return a + b;
}

// Weighted so that the order of the arguments matters: many_args(0, 1, ..., 9) == 330
__attribute__((noinline)) long many_args(long a0, long a1, long a2, long a3, long a4,
                                         long a5, long a6, long a7, long a8, long a9) {
    return 1 * a0 + 2 * a1 + 3 * a2 + 4 * a3 + 5 * a4 + 6 * a5 + 7 * a6 + 8 * a7 + 9 * a8 + 10 * a9;
}

__attribute__((noinline)) long inner(long x) {
    return x * 2;
}

__attribute__((noinline)) long outer(long x) {
    return inner(x) + 1;
}

__attribute__((noinline)) void tick(void) {
    counter++;
}

__attribute__((noinline)) long string_length(const char *string) {
    return strlen(string);
}

// Used by bruteforce: only 42 is the right answer
__attribute__((noinline)) int check_secret(int guess) {
    return guess == 42;
}

__attribute__((noinline)) long say_hi(void) {
    return syscall(SYS_write, 1, "syscall says hi\n", 16);
}

__attribute__((noinline)) int ask_pid(void) {
    return (int)syscall(SYS_getpid);
}

__attribute__((noinline)) void use_heap(void) {
    char *pointer = malloc(0x20);
    strcpy(pointer, "heap data");
    free(pointer);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    LABEL(main_start);
    long result = add(1, 2);
    result += many_args(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    result += outer(20);
    for (int i = 0; i < 5; i++)
        tick();
    say_hi();
    use_heap();
    printf("pid %d\n", ask_pid());
    puts("ready");

    char line[0x40] = {0};
    if (fgets(line, sizeof(line), stdin) == NULL)
        strcpy(line, "(eof)\n");
    LABEL(after_input);
    printf("result %ld counter %ld\n", result, counter);
    printf("line %s", line);
    printf("argv %s\n", argc > 1 ? argv[1] : "(none)");
    printf("env %s\n", getenv("GDB_PLUS_TEST") ? getenv("GDB_PLUS_TEST") : "(none)");
    LABEL(main_end);
    return 0;
}
