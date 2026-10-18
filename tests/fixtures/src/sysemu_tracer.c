// A parent that drives its child with PTRACE_SYSEMU_SINGLESTEP and collects stops with both
// waitpid() and waitid(), the way the LineCTF 2023 "Anti Hacker" loader does. The output only
// contains values that don't depend on addresses or pids, so it is an oracle for
// dbg.emulate_ptrace(): the program must print the same thing when both processes are debugged.
//
// Kernel behaviour it pins (x86-64, kernel/entry/common.c):
//   - SYSEMU_SINGLESTEP onto `syscall` stops at syscall entry WITHOUT running the syscall:
//     status 0x857f (TRACESYSGOOD), rip past the syscall, rax = -ENOSYS, orig_rax = number
//   - SINGLESTEP from that stop reports the syscall exit as a SIGTRAP stop and runs NO instruction
//   - SYSEMU_SINGLESTEP from that stop reports nothing and just steps the next instruction
//   - waitid() reports ptrace stops as CLD_TRAPPED and the exit as CLD_EXITED
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "labels.h"

#ifndef PTRACE_SYSEMU_SINGLESTEP
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif

#define HC_EMULATED 0x4042  // the tracer returns 0x1337
#define HC_SKIPPED  0x4043  // the tracer leaves -ENOSYS
#define HC_DONE     0x4049  // the tracer lets the child run freely

long hypercall_result, getpid_result, skipped_result;

__attribute__((noinline)) void child_region(void) {
    __asm__ volatile(
        "mov $39, %%eax\n\t"
        "syscall\n\t"                       // getpid()
        "mov %%eax, %%edi\n\t"
        "mov $19, %%esi\n\t"
        "mov $62, %%eax\n\t"
        "syscall\n\t"                       // kill(getpid(), SIGSTOP): the tracer takes over
        "mov $0x4042, %%eax\n\t"
        "syscall\n\t"                       // HC_EMULATED: emulated by the tracer
        "mov %%rax, %0\n\t"
        "mov $39, %%eax\n\t"
        "syscall\n\t"                       // getpid(): the tracer runs it natively
        "mov %%rax, %1\n\t"
        "mov $0x4043, %%eax\n\t"
        "syscall\n\t"                       // HC_SKIPPED
        "nop\n\t"
        "mov %%rax, %2\n\t"
        "mov $0x4049, %%eax\n\t"
        "syscall\n\t"                       // HC_DONE
        : "=m"(hypercall_result), "=m"(getpid_result), "=m"(skipped_result)
        :
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

static void set_regs(struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, child, NULL, regs) != 0) fail("SETREGS");
}

static void request(int what) {
    if (ptrace(what, child, NULL, NULL) != 0) fail("ptrace request");
}

static int wait_status(void) {
    int status = 0;
    if (waitpid(child, &status, 0) != child) fail("waitpid");
    return status;
}

static siginfo_t wait_info(void) {
    siginfo_t info = {0};
    if (waitid(P_PID, child, &info, WEXITED | WSTOPPED) != 0) fail("waitid");
    if (info.si_pid != child) fail("waitid si_pid");
    return info;
}

// SYSEMU-step until the child reaches a syscall. Returns the number of requests it took.
static int sysemu_until_syscall(struct user_regs_struct *regs, int *status) {
    for (int steps = 1; steps <= 100; steps++) {
        request(PTRACE_SYSEMU_SINGLESTEP);
        *status = wait_status();
        if (!WIFSTOPPED(*status)) fail("child did not stop");
        if (((*status >> 8) & 0xff) == (SIGTRAP | 0x80)) {
            get_regs(regs);
            return steps;
        }
        if (WSTOPSIG(*status) != SIGTRAP) fail("unexpected signal while stepping");
    }
    fail("no syscall after 100 steps");
    return 0;
}

static void print_sysemu_stop(const char *name, struct user_regs_struct *regs, int steps, int status) {
    long before = ptrace(PTRACE_PEEKTEXT, child, (void *)(regs->rip - 2), NULL);
    printf("%s: steps %d status %#x nr %#llx rax %lld past_syscall %d\n", name, steps, status,
           regs->orig_rax, (long long)regs->rax, (before & 0xffff) == 0x050f);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        child_region();
        printf("child: hypercall %#lx getpid_ok %d skipped %ld\n",
               hypercall_result, getpid_result == getpid(), skipped_result);
        _exit(0);  // 0: gdb_plus does not track the exit code of an emulated tracee (waitpid reports 0 too)
    }

    int status = wait_status();
    printf("stopped %d signal %d\n", WIFSTOPPED(status), WSTOPSIG(status));
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) != 0) fail("SETOPTIONS");

    struct user_regs_struct regs;
    unsigned long long rip;
    int steps;

    // 1. Emulated syscall: SINGLESTEP + waitid, then inject the result (loader @ 0x4ee1)
    steps = sysemu_until_syscall(&regs, &status);
    print_sysemu_stop("emulated", &regs, steps, status);
    rip = regs.rip;
    request(PTRACE_SINGLESTEP);
    siginfo_t info = wait_info();
    get_regs(&regs);
    printf("emulated: exit report si_code %d si_status %#x rip_moved %lld\n",
           info.si_code, info.si_status, (long long)(regs.rip - rip));
    regs.rax = 0x1337;
    set_regs(&regs);

    // 2. Native syscall: rewind, SINGLESTEP + waitid (exit report), SINGLESTEP + waitpid (loader @ 0x47ef)
    steps = sysemu_until_syscall(&regs, &status);
    print_sysemu_stop("native", &regs, steps, status);
    regs.rip -= 2;
    regs.rax = regs.orig_rax;
    set_regs(&regs);
    rip = regs.rip;
    request(PTRACE_SINGLESTEP);
    info = wait_info();
    get_regs(&regs);
    printf("native: exit report si_code %d si_status %#x rip_moved %lld\n",
           info.si_code, info.si_status, (long long)(regs.rip - rip));
    request(PTRACE_SINGLESTEP);
    status = wait_status();
    get_regs(&regs);
    printf("native: executed status %#x rip_moved %lld rax_is_child %d\n",
           status, (long long)(regs.rip - rip), (pid_t)regs.rax == child);

    // 3. SYSEMU_SINGLESTEP straight out of a SYSEMU stop: no exit report, the nop runs
    steps = sysemu_until_syscall(&regs, &status);
    print_sysemu_stop("skipped", &regs, steps, status);
    rip = regs.rip;
    request(PTRACE_SYSEMU_SINGLESTEP);
    status = wait_status();
    get_regs(&regs);
    printf("skipped: next request status %#x rip_moved %lld\n", status, (long long)(regs.rip - rip));

    // 4. Let the child finish on its own and collect the exit with waitid
    steps = sysemu_until_syscall(&regs, &status);
    print_sysemu_stop("done", &regs, steps, status);
    regs.rax = 0;
    set_regs(&regs);
    request(PTRACE_CONT);
    info = wait_info();
    printf("exit: si_code %d si_status %d\n", info.si_code, info.si_status);
    return 0;
}
