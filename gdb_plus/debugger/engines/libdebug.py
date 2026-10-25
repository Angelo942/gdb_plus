from __future__ import annotations

import os
import signal
from typing import TYPE_CHECKING

from pwn import context, log, unpack
from pwnlib.elf.datatypes import AT_CONSTANTS

from gdb_plus.utils import DEBUG, PriorityEvent, DoneEvent, set_done_if_panic, Breakpoint, SIGNALS, SIGNALS_from_num
from gdb_plus.debugger._base import lock_decorator, context_decorator
from gdb_plus.debugger.engines.base import Backend

if TYPE_CHECKING:
    from typing import Callable
    from gdb_plus.debugger.debugger import Debugger

class LibdebugBackend(Backend):
    """The engine is legacy libdebug: dbg.libdebug."""
    def __init__(self, dbg: Debugger) -> None:
        super().__init__(dbg)
        # The signal the next resume delivers (queue_signal). libdebug resumes with no signal unless it is told one
        self.pending_signal = 0
    def delete_breakpoint(self, breakpoint: Breakpoint) -> None:
        dbg = self.dbg
        dbg.libdebug.del_bp(breakpoint.native_breakpoint)
    def alloc(self, n: int) -> int:
        dbg = self.dbg
        return dbg.call("malloc", [n])
    def dealloc(self, pointer: int) -> None:
        dbg = self.dbg
        dbg.call("free", [pointer])
    def stopped_pid(self) -> int:
        dbg = self.dbg
        return dbg.pid # Handle thread
    def stop_signal(self) -> int:
        dbg = self.dbg
        return dbg.libdebug.stop_status >> 0x8
    def running(self) -> bool:
        dbg = self.dbg
        return not dbg.libdebug._test_execution()
    def jump(self, address: int) -> None:
        dbg = self.dbg
        dbg.instruction_pointer = address
    # How to handle multiple processes ?
    def write_to_pid(self, address: int, data: bytes, *, pid: int | None = None) -> None:
        if pid is not None:
            ...
    def resume_process(self, step: bool) -> None:
        dbg = self.dbg
        signal, self.pending_signal = self.pending_signal, 0
        if step:
            dbg.libdebug.step(signal=signal)
        else:
            dbg.libdebug.cont(blocking=False, signal=signal)
    @set_done_if_panic
    def cont(self, force: bool, wait: bool, done: DoneEvent, signal: int) -> None:
        # Continue in libdebug is already stepping [21/05/23]
        # Maybe keep the step if force = True [22/O5/23]
        #self.step(force=force)
        ## I hit a breakpoint
        #if self.instruction_pointer in self.breakpoints or self.instruction_pointer == self._last_breakpoint_deleted:
        #    return
        # I don't need the thread, right ? And this way I can lock the step [12/06/23]
        dbg = self.dbg
        with dbg.control.action_lock.log("_continue_libdebug"):
            event = dbg.execute_action(lambda: dbg.libdebug.cont(blocking=False, signal=signal), sender="continue")
        dbg.control.priority_wait(comment="continue", priority=event)
        done.interrupted = (event.reason or "").startswith("interrupted")
    def start_continue(self, force: bool, wait: bool, done: DoneEvent, signal: int) -> None:
        dbg = self.dbg
        context.Thread(target=dbg.control.priority.inherit(self.cont, done), args=(force, wait, done, signal), name=f"[{dbg.pid}] continue", daemon=True).start()
    @set_done_if_panic
    def continue_until(self, address: int, done: DoneEvent, force: bool) -> None:
        dbg = self.dbg
        dbg.cont(wait=True, force=force)
        if dbg.instruction_pointer != address:
            log.warn(f"[{dbg.pid}] stopped at {dbg.reverse_lookup(dbg.instruction_pointer)} with status {hex(dbg.libdebug.stop_status)} instead of {dbg.reverse_lookup(address)}")
            # Not tested yet [22/07/23]. I just want to avoid having the debugger crash while emulating ptrace because the process is sent a SIGSTOP
            log.error("error in continue until")
        done.set()
    def start_continue_until(self, address: int, done: DoneEvent, force: bool, breakpoint: Breakpoint) -> None:
        dbg = self.dbg
        context.Thread(target=dbg.control.priority.inherit(self.continue_until, done), args=(address, done, force), name=f"[{dbg.pid}] continue_until", daemon=True).start()
    def native_breakpoint(self, address: int, hw: bool = False) -> int:
        dbg = self.dbg
        return dbg.libdebug.breakpoint(address, hw=hw)
    def breakpoint(self, address: int, legacy_callback: Callable[[Debugger], bool | int | None] | None, callback: Callable[[Debugger], bool | int | None] | None, temporary: bool, user_defined: bool, hw: bool) -> Breakpoint:
        if legacy_callback is not None:
            callback = legacy_callback
        return Breakpoint(self.native_breakpoint(address, hw=hw), address, callback, temporary, user_defined, hw)
    def saved_ip(self, link_register: str | None) -> int:
        dbg = self.dbg
        return dbg._find_rip()     
    def step(self, signal: int | str, timeout: float | None, internal: bool) -> tuple[PriorityEvent | None, bool]:
        dbg = self.dbg
        signal, self.pending_signal = signal or self.pending_signal, 0
        event = dbg.execute_action(lambda: dbg.libdebug.step(signal=signal), sender="step", internal=internal, step=True)
        finished = dbg.control.priority_wait(comment="step", priority=event, timeout=timeout)
        return event, finished
    def signal(self, n: int | str, step: bool, timeout: float | None) -> None:
        dbg = self.dbg
        if type(n) is str:
            n = n.upper()
            n = SIGNALS[n]
        if DEBUG: dbg.logger.debug("sending signal 0x%x -> %s", n, SIGNALS_from_num[n])
        if step:
            dbg.step(signal=n)
        else:
            dbg.c(signal=n)
    def queue_signal(self, n: int) -> None:
        self.pending_signal = n
    # libdebug has no `info auxv`, but the kernel gives us the raw vector: pairs of (type, value) words [23/10/26]
    def auxiliary_vector(self) -> dict[str, int]:
        dbg = self.dbg
        with open(f"/proc/{dbg.pid}/auxv", "rb") as fd:
            data = fd.read()
        words = [unpack(data[i:i+context.bytes]) for i in range(0, len(data), context.bytes)]
        auxiliary_vector = {}
        for av_type, av_value in zip(words[::2], words[1::2]):
            auxiliary_vector[AT_CONSTANTS.get(av_type, str(av_type))] = av_value
        return auxiliary_vector
    def stop_reason(self) -> str:
        dbg = self.dbg
        # TODO handle it correctly. Is Ox5 only used for step or also breakpoints ? Do we have access to libdebug's stepped variable ? (I would prefer that one at least) [05/06/23]
        # SIGTRAP (0x5) is also used for breakpoints [20/06/25]
        # GDB would prioritize BREAKPOINT over SINGLE STEP. Catchpoints are treated as BREAKPOINT, but don't fire if we step
        if dbg.control.stepped:
            return "SINGLE STEP"
        # Check 0x5 as step or breakpoint ?
        else:
            return SIGNALS_from_num[dbg.stop_signal]
    def detach(self, quit: bool, block: bool) -> None:
        dbg = self.dbg
        dbg.control.closed.set() # In gdb it's set by the callback on exit
        dbg.libdebug.detach()
        if not block:
            os.kill(dbg.pid, signal.SIGCONT)
    def read_register(self, name: str) -> int:
        dbg = self.dbg
        # BUG libdebug can not parse lower registers [19/11/23]
        res = getattr(dbg.libdebug, name)
        return res
    def write_register(self, name: str, value: int) -> None:
        dbg = self.dbg
        setattr(dbg.libdebug, name, value % 2**context.bits) # I don't remember if libdebug accepts negative values
    # INT3 while enumerating ptrace doesn't set ptrace_has_stopped [24/12/23]
    # The handler is not called at all! Is it because libdebug thinks it's an internal interruption ?
    # No, without emulate_ptrace() we get to the "why did I stop"...
    # But if I only set ptrace_emulated = True then everything works...
    @lock_decorator
    @context_decorator
    def handle_stop(self) -> None:
        """
        Actions that the debugger performs every time the process is interrupted
        Handle temporary breakpoints and callbacks
        """
        # If we detach there will be a step to shutdown waitpid, but libdebug will have detached before we can execute the handler, so let's just skip it.
        dbg = self.dbg
        if dbg._detached:
            if DEBUG: dbg.logger.debug("libdebug stopped waitpid")
            return

        # Current inferior will change to the inferior who stopped last
        ip = dbg.instruction_pointer
        breakpoints = dbg.control.breakpoints[ip]

        if DEBUG: dbg.logger.debug("[%d] stopped at address: 0x%x with status: 0x%x", dbg.libdebug.cur_tid, ip, dbg.libdebug.stop_status)
        
        if dbg._stop_reason in SIGNALS and SIGNALS[dbg._stop_reason] in dbg.control.handled_signals:
            should_stop = dbg.control.handled_signals[SIGNALS[dbg._stop_reason]](dbg)
            if should_stop == False:
                dbg._hidden_continue()
            else:
                if not dbg.ptrace.take_stop():
                    dbg.control.set_stop(f"signal {dbg._stop_reason} handled")
            return
        # I hope I won't touch a breakpoint at the same time
        # Usually if I hit a breakpoint it should stop again. At least with step we have the step and then the sigchld 
        # Will be a problem while stepping, but amen
        elif dbg.libdebug.stop_status == 0x117f:
            log.warn("the child stopped and libdebug caught it. Let's continue waiting for Mario to change the options...")
            # We have problems with the wait after the step...
            #self.libdebug.cont(blocking=False)
            #return
        
        if len(breakpoints) == 0:
            if dbg.control.stepped or dbg.control.interrupted:
                taken = False
                if dbg.stop_signal not in [0x5, 0x2, 0x13]:
                    log.warn(f"I wanted to step or interrupt, but stopped due to signal: {dbg._stop_reason}")
                    # Before clearing stepped: a step stopped by a signal must still end (see take_stop)
                    taken = dbg.ptrace.take_stop()
                dbg.control.stepped = False
                dbg.control.interrupted = False
                if taken:
                    return
            # This should now be handled by libdebug [08/06/23]
            # AND SIGTRAP COULD ALSO BE DUE TO A INT3 EMULATING PTRACE [24/12/23]
            #elif self.libdebug.stop_status == 0x57f:
            #    # Look into how to handle steps in libdebug [21/05/23]
            #
            #    log.warn("I suppose libdebug just stepped so let's pretend nothing happened")
            #    return
            else:
                # Once to let know there may be a problem, but not spamming when it is part of the challenge.
                if dbg.ptrace.take_stop():
                    return
                log.warn_once(f"why did I stop ??? [{hex(dbg.libdebug.stop_status)}]")
            dbg.control.set_stop("no breakpoint")
            return            
        
        dbg.control.handle_breakpoints(breakpoints)
    def setup(self) -> None:
        # libdebug calls handle_stop in its own thread, so the context of the stop is opened there
        dbg = self.dbg
        def handle_stop() -> None:
            stop = dbg.control.priority.stop_detected("libdebug stop")
            dbg.control.priority.enter(stop)
            try:
                self.handle_stop()
            finally:
                dbg.control.priority.leave(stop)
        dbg.libdebug.handle_stop = handle_stop

        dbg.libdebug.handle_exit = dbg.control.exit_handler
        
        dbg.control.closed.clear()
        dbg.control.kill_threads.clear()
    def send_command(self, command: str | Callable[[], object]) -> None:
        dbg = self.dbg
        if command != "":
            # The legacy libdebug returns from the command only once the process stops, and has no interrupt() to lose
            dbg.control.priority.task_resumed()
            command()
            return
        super().send_command(command)
