// fork(): the child runs child_work() and exits with 3, the parent waits for it.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "labels.h"

__attribute__((noinline)) void child_work(void) {
    puts("child");
}

__attribute__((noinline)) void parent_work(void) {
    puts("parent");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    LABEL(before_fork);
    pid_t pid = fork();
    if (pid == 0) {
        child_work();
        _exit(3);
    }
    parent_work();
    int status = 0;
    waitpid(pid, &status, 0);
    printf("child exited %d\n", WEXITSTATUS(status));
    return 0;
}
