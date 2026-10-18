// Export the current address as a global symbol, so that tests can do dbg.until("name")
// instead of hard coding addresses that change with every compiler version.
// Only use it once per function (the fixtures are compiled with -O0, so code is never duplicated).
#define LABEL(name) __asm__ volatile(".globl " #name "\n" #name ":")
