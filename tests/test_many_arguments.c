#include <stdio.h>

// Define the format string as a global variable
const char *format = "%x, %x, %x, %x, %x, %x, %x, %x, %x, %x\n";

int main() {
    printf(format, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    return 0;
}