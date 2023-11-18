DBG+ 6.4.2:
* handle NOPTRACE for emulate_ptrace and split_on_fork
* NOP instructions
* hotfix disable lock.log with NOPTRACE
* hotfix Removed buffer overflow in `__convert_args`
* Assert that malloc is present before trying to allocate on heap
* Option to connect to remote server while debugging localy
* Migrate to logging library 
* read pointers based on context
* context manager

DBG+ 6.4.1: syscalls
* Set handlers for syscalls
* Emulate ptrace through syscalls instead of function calls
* Support signals with libdebug
* Return self when possible to simplify debugging from Ipython
* Remove advanced_continue_and_wait_split

GDB+ 6.4.0: **ARM**
* Can "partially" debug aarch64 programs running under qemu. With all the limitations that come from the emulator
	- For now qemu has problems identifying the pid of the process and when it forks, so you can only debug single-thread, single-process applications for now.
	- you can not reattach to a process, so no `debug_from`
	- You can not find the base of your binary or overwrite the code so no patches nor syscalls
* hardware breakpoints

GDB+ 6.3.4: Bruteforce util
* single thread bruteforce
* multithread bruteforce
* support new version of libdebug

GDB+ 6.3.3: Expand ptrace emulation
* single function for ptrace emulation that handles both tracee and tracer.
	- process isn't limited at being a slave or a master
* signal handler 

GDB+ 6.3.2: hotfix ptrace emulation
* standardise how inferiors are handled
	- inferiors can be specified only to read and write memory. Split the debugger or use switch_inferior if you have to perform other actions.
* util functions to read and write ints, longs, and strings
	- write functions take an pointer and a value or list of values. If pointer is None the address is allocated in the heap (or in the bss if heap=False). The function returns a pointer to the data
	- by default read functions return a single value. If the argument n > 1 the function returns an array
	- the null bytes for the strings are added when writing and removed when reading
* set status for waitpid while emulating ptrace
* Define gdbscript to execute when splitting a new Debugger
* inner_debugger write and read from /proc/pid/mem
* util step_until_call

GDB+ 6.3.1: hotfix libdebug
* Make libdebug optional since it can't be added as a dependency (thanks PyPI)

GDB+ 6.3.0: **Let's go faster**
* Can use gdb or libdebug ad debugger
	- gdb can be used manually, but will be slower to script
	- libdebug has less fetures and more bugs