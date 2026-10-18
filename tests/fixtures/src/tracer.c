// A parent that debugs its own child with ptrace. The output is the same with or
// without a debugger, so it is an oracle for dbg.emulate_ptrace().
//   ./tracer          ... PTRACE_CONT at the end
//   ./tracer detach   ... PTRACE_DETACH at the end
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "labels.h"

long shared_value = (long)0x1122334455667788ULL;  // truncated in tracer_i386: the oracle is the same binary

__attribute__((noinline)) void child_body(void) {
    printf("child sees %lx\n", shared_value);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int detach = argc > 1 && strcmp(argv[1], "detach") == 0;

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        child_body();
        _exit(0);
    }

    int status = 0;
    waitpid(child, &status, 0);
    printf("stopped %d signal %d\n", WIFSTOPPED(status), WSTOPSIG(status));

    long peek = ptrace(PTRACE_PEEKDATA, child, &shared_value, NULL);
    printf("peek %lx\n", peek);
    ptrace(PTRACE_POKEDATA, child, &shared_value, (void *)0x4242);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    ptrace(PTRACE_SETREGS, child, NULL, &regs);

    if (detach)
        ptrace(PTRACE_DETACH, child, NULL, NULL);
    else
        ptrace(PTRACE_CONT, child, NULL, NULL);

    waitpid(child, &status, 0);
    printf("exited %d\n", WIFEXITED(status));
    return 0;
}
