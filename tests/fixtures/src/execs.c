// execve() into /bin/echo. Used to check catchpoints across an exec.
#include <stdio.h>
#include <unistd.h>
#include "labels.h"

__attribute__((noinline)) void before_exec(void) {
    puts("before exec");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    before_exec();
    char *argv[] = {"echo", "after exec", NULL};
    execv("/bin/echo", argv);
    perror("execv");
    return 1;
}
