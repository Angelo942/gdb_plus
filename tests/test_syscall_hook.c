#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>

int main() {
    const char *filename = "data.txt";
    const char *message = "Hello from syscall!\n";
    size_t len = 20; // Length of the message

    // Open or create the file with write permissions
    int fd = syscall(SYS_open, filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("syscall open");
        return 1;
    }

    // Write to the file
    ssize_t written = syscall(SYS_write, fd, message, len);
    if (written < 0) {
        perror("syscall write");
        syscall(SYS_close, fd);
        return 1;
    }

    // Close the file
    if (syscall(SYS_close, fd) < 0) {
        perror("syscall close");
        return 1;
    }

    return 0;
}
