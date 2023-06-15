GDB+ 6.3.4: Bruteforce util
* single thread bruteforce

GDB+ 6.3.3: Expand ptrace emulation
* hotfix transfer breakpoints while migrating
* reduce race conditions in for ptrace emulation
* correct debug_from when event is set

* single function for ptrace emulation that handles both tracee and tracer.
	- process isn't limited at being a slave or a master
* signal handler 

GDB+ 6.3.2: hotfix ptrace emulation
* hotfix copy libc to child process
* hotfix correct(ish) finish when inside libc
* hotfix nested continue_until with the same destination
	- For now use a second callback instead of a finish (or even worse a continue_until) 
	- We will think later how to correctly handle the order of stacked breakpoints on the same address
* hotfix turn off set_split_on_fork
* hotfix correct running property

* standardise how inferiors are handled
	- inferiors can be specified only to read and write memory. Split the debugger or use switch_inferior if you have to perform other actions.
* util functions to read and write ints, longs, and strings
	- write functions take an pointer and a value or list of values. If pointer is None the address is allocated in the heap (or in the bss if heap=False). The function returns a pointer to the data
	- by default read functions return a single value. If the argument n > 1 the function returns an array
	- the null bytes for the strings are added when writing and removed when reading
* set correct status for waitpid while emulating ptrace
* Define gdbscript to execute when splitting a new Debugger
* inner_debugger write and read from /proc/pid/mem
* util step_until_call

GDB+ 6.3.1: hotfix libdebug
* Make libdebug optional since it can't be added as a dependency (thanks PyPI)

GDB+ 6.3.0: **Let's go faster**
* Can use gdb or libdebug ad debugger
	- gdb can be used manually, but will be slower to script
	- libdebug has less fetures and more bugs
Notes:
* countinue_until doesn't run the program if you already are at the specified address and the parameter `loop` isn't passed `True`
* call() should only be used from outside the function you want to call