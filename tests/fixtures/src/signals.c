// Signal handlers and faults.
//   ./signals          raise SIGUSR1 once, then print how many times each handler ran
//   ./signals crash    dereference NULL in crash()
#ifdef FREESTANDING
#include "freestanding.h"
#else
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#endif
#include "labels.h"

volatile int usr1_count = 0;
volatile int usr2_count = 0;

__attribute__((noinline)) void on_usr1(int signum) {
    usr1_count++;
}

__attribute__((noinline)) void on_usr2(int signum) {
    usr2_count++;
}

// A place where the test can stop and inject signals with dbg.signal()
__attribute__((noinline)) void quiet_spot(void) {
    LABEL(quiet_spot_body);
    __asm__ volatile("nop\nnop\nnop\nnop");
}

__attribute__((noinline)) void crash(void) {
    volatile int *pointer = NULL;
    *pointer = 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGUSR1, on_usr1);
    signal(SIGUSR2, on_usr2);
    if (argc > 1 && strcmp(argv[1], "crash") == 0)
        crash();
    raise(SIGUSR1);
    quiet_spot();
    printf("usr1 %d usr2 %d\n", usr1_count, usr2_count);
    return 0;
}
