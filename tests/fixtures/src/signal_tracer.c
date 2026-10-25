// A parent that drives its child with PTRACE_SINGLESTEP and PTRACE_CONT while the child sends signals to itself, and
// decides with the data argument of its next request what happens to each signal. The output only contains values
// that don't depend on addresses or pids, so it is an oracle for dbg.emulate_ptrace(): the program must print the same
// thing when both processes are debugged.
//
// Kernel behaviour it pins (signal-delivery-stop, man 2 ptrace):
//   - a signal the child sends itself stops it before the next instruction runs, also while it is single-stepped:
//     the step over the syscall reports its SIGTRAP first, the signal comes with the next step
//   - the tracer's next request delivers the signal it passes as data, not the one that stopped the child:
//     0 discards it, SIGUSR1 runs the handler (a single step stops on its first instruction)
//   - delivering SIGSTOP stops the child again (group-stop), and waitpid reports it once more
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "labels.h"

static volatile sig_atomic_t handled;

__attribute__((noinline)) void handler(int sig) {
    handled++;
}

// kill(getpid(), sig) with raw syscalls, so that the tracer only steps a handful of instructions
__attribute__((noinline)) void raw_kill(int sig) {
    __asm__ volatile(
        "mov $39, %%eax\n\t"
        "syscall\n\t"                       // getpid()
        "mov %%eax, %%edi\n\t"
        "mov %0, %%esi\n\t"
        "mov $62, %%eax\n\t"
        "syscall\n\t"                       // kill(getpid(), sig)
        :
        : "r"(sig)
        : "rax", "rdi", "rsi", "rcx", "r11", "memory");
}

static pid_t child;

static void fail(const char *why) {
    printf("FAIL %s\n", why);
    kill(child, SIGKILL);
    exit(1);
}

static void get_regs(struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, child, NULL, regs) != 0) fail("GETREGS");
}

static void request(int what, int sig) {
    if (ptrace(what, child, NULL, (void *)(long)sig) != 0) fail("ptrace request");
}

static int wait_status(void) {
    int status = 0;
    if (waitpid(child, &status, 0) != child) fail("waitpid");
    return status;
}

// Single-step the child until a signal other than the trap of the step stops it, and print how far that stop is from
// the previous one
static void step_until_signal(const char *name) {
    struct user_regs_struct regs;
    for (int steps = 1; steps <= 1000; steps++) {
        get_regs(&regs);
        unsigned long long rip = regs.rip;
        request(PTRACE_SINGLESTEP, 0);
        int status = wait_status();
        if (!WIFSTOPPED(status)) fail("child did not stop");
        if (WSTOPSIG(status) != SIGTRAP) {
            get_regs(&regs);
            printf("%s: status %#x rip_moved %lld\n", name, status, (long long)(regs.rip - rip));
            return;
        }
    }
    fail("no signal after 1000 steps");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        signal(SIGUSR1, handler);
        raw_kill(SIGSTOP);                  // handshake: the tracer takes over
        raw_kill(SIGUSR1);                  // stepped onto, discarded
        raw_kill(SIGUSR1);                  // stepped onto, delivered
        raw_kill(SIGUSR1);                  // continued onto, discarded
        raw_kill(SIGUSR1);                  // continued onto, delivered
        raw_kill(SIGSTOP);                  // continued onto, delivered: group-stop
        printf("child: handled %d\n", handled);
        _exit(0);  // 0: gdb_plus does not track the exit code of an emulated tracee (waitpid reports 0 too)
    }

    struct user_regs_struct regs;
    unsigned long long rip;
    int status = wait_status();
    printf("handshake: status %#x\n", status);

    // 1. Step onto a signal and discard it: the next step runs an instruction instead of the handler
    step_until_signal("step");
    get_regs(&regs);
    rip = regs.rip;
    request(PTRACE_SINGLESTEP, 0);
    status = wait_status();
    get_regs(&regs);
    printf("step discarded: status %#x executed %d\n", status, regs.rip != rip);

    // 2. Step onto a signal and deliver it: the step stops on the first instruction of the handler
    step_until_signal("step");
    request(PTRACE_SINGLESTEP, SIGUSR1);
    status = wait_status();
    get_regs(&regs);
    printf("step delivered: status %#x in_handler %d\n", status, regs.rip == (unsigned long long)handler);

    // 3. Continue onto a signal and discard it
    request(PTRACE_CONT, 0);
    status = wait_status();
    printf("cont: status %#x\n", status);
    request(PTRACE_CONT, 0);

    // 4. Continue onto a signal and deliver it
    status = wait_status();
    printf("cont: status %#x\n", status);
    request(PTRACE_CONT, SIGUSR1);

    // 5. Deliver SIGSTOP: the child stops again
    status = wait_status();
    printf("cont: status %#x\n", status);
    request(PTRACE_CONT, SIGSTOP);
    status = wait_status();
    printf("group stop: status %#x\n", status);
    request(PTRACE_CONT, 0);

    status = wait_status();
    printf("exit: exited %d code %d\n", WIFEXITED(status), WEXITSTATUS(status));
    return 0;
}
