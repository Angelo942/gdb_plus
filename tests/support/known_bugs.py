"""
Reasons of the known_gap markers that several modules share: one root cause, one string. The bugs of libdebug_legacy
(the legacy libdebug, to be deprecated) come with the fix to apply in libdebug_legacy/libdebug.py.
"""

# libdebug_legacy, Debugger._retore_breakpoints(): rip is moved back whenever rip-1 is a breakpoint, also after the hidden
# step of cont(), when no int3 is in memory. From a breakpoint on a 1-byte instruction (push rbp) the step lands on bp+1
# and is moved back to bp: the process executes the instruction twice and hits the breakpoint again, forever when a
# callback continues. Fix: rewind only over an int3 that is in memory (_set_breakpoints() saves the original byte there,
# the value is None otherwise):
#     if self.rip not in self.breakpoints and self.breakpoints.get(self.rip-1) is not None:
#         self.rip -= 1
LIBDEBUG_REWIND = "libdebug_legacy's _retore_breakpoints() moves rip back after the hidden step of cont() off a breakpoint on a 1-byte instruction (push rbp): the breakpoint is hit again"

# The exit of the process with the legacy libdebug: two bugs, c() returns only once both are fixed.
# 1. libdebug_legacy, Debugger._wait_process(): _retrieve_maps() and _find_new_tids() run before the WIFEXITED check.
#    Once the process is gone /proc/<pid>/maps and /proc/<pid>/task/ don't exist, and the wait thread dies with
#    FileNotFoundError before it calls handle_exit(). Fix: skip them when the process exited:
#        if not WIFEXITED(status):
#            self._retrieve_maps()
#            self._find_new_tids()
# 2. gdb_plus, LibdebugBackend.setup(): handle_exit is Controller.exit_handler(event), which reads the inferior of gdb's
#    ExitedEvent, and libdebug calls it without arguments (TypeError).
LIBDEBUG_EXIT = "c() never returns when the process exits: libdebug_legacy's _wait_process() reads /proc/<pid>/maps after the exit, and LibdebugBackend.setup() installs Controller.exit_handler(event), which libdebug calls without an event (debugger/engines/libdebug.py:setup)"
