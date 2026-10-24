from __future__ import annotations

import os
import signal
from threading import Event
from typing import TYPE_CHECKING

from pwn import context, log, sleep

from gdb_plus.utils import DEBUG, PriorityEvent, Interrupted, DoneEvent, set_done_if_panic, Breakpoint, SIGNALS, SIGNALS_from_num
from gdb_plus.debugger._base import _NEW_LIBDEBUG_REGISTERS, lock_decorator, context_decorator, _logger
from gdb_plus.debugger.engines.base import Backend
from gdb_plus.debugger.engines.libdebug import LibdebugBackend

if TYPE_CHECKING:
    from typing import Callable
    from gdb import Inferior
    from libdebug.data.breakpoint import Breakpoint as LibdebugBreakpoint
    from gdb_plus.debugger.debugger import Debugger

class NewLibdebugBackend(Backend):
    """The engine is new libdebug: dbg.new_libdebug."""
    def delete_breakpoint(self, breakpoint: Breakpoint) -> None:
        # Doesn't allow for proper deletion.
        breakpoint.native_breakpoint.disable()
    alloc = LibdebugBackend.alloc
    dealloc = LibdebugBackend.dealloc
    def stopped_pid(self) -> int:
        dbg = self.dbg
        return dbg.new_libdebug.pid
    def stop_signal(self) -> int:
        dbg = self.dbg
        # TODO handle threads
        return dbg.new_libdebug.threads[0]._signal_number
    def running(self) -> bool:
        dbg = self.dbg
        return dbg.new_libdebug.running
    def internal_wait(self) -> None:
        dbg = self.dbg
        dbg.new_libdebug._resumed.wait()
        dbg.new_libdebug.wait()
        dbg.new_libdebug._resumed.clear()
    jump = LibdebugBackend.jump
    def write(self, address: int, data: bytes, inferior: Inferior | None, pid: int | None) -> int | None:
        dbg = self.dbg
        dbg.new_libdebug.mem.write(address, data)
        return address
    def read(self, address: int, size: int, inferior: Inferior | None, pid: int | None) -> bytes:
        dbg = self.dbg
        return dbg.new_libdebug.mem.read(address, size)
    def kick(self) -> None:
        dbg = self.dbg
        dbg.new_libdebug.interrupt()
    def resume_process(self, step: bool) -> None:
        dbg = self.dbg
        if step:
            dbg.new_libdebug.step()
        else:
            dbg.new_libdebug.c() # TODO check if this is valid [20/06/25]
        dbg.new_libdebug._resumed.set()
    @set_done_if_panic
    def cont(self, force: bool, wait: bool, done: DoneEvent, signal: int) -> None:
        dbg = self.dbg
        with dbg.control.action_lock.log("_continue_new_libdebug"):
            if signal:
                dbg.new_libdebug.signal = signal
            event = dbg.execute_action(lambda: dbg.new_libdebug.cont(), sender="continue")
        dbg.control.priority_wait(comment="continue", priority=event)
        done.interrupted = (event.reason or "").startswith("interrupted")
    def start_continue(self, force: bool, wait: bool, done: DoneEvent, signal: int) -> None:
        dbg = self.dbg
        context.Thread(target=dbg.control.priority.inherit(self.cont, done), args=(force, wait, done, signal), name=f"[{dbg.pid}] continue", daemon=True).start()
    @set_done_if_panic
    def continue_until(self, address: int, done: DoneEvent, force: bool, breakpoint: Breakpoint | None = None) -> None:
        dbg = self.dbg
        inner = dbg.cont(wait=False, force=force)
        inner.wait()
        if inner.interrupted:
            # Ended by interrupt(): remove the temporary breakpoint, otherwise it would stop the next action of the script
            dbg._forget_breakpoint(address, breakpoint)
            raise Interrupted("continue_until")
        if dbg.instruction_pointer != address:
            log.warn(f"[{dbg.pid}] stopped at {dbg.reverse_lookup(dbg.instruction_pointer)} instead of {dbg.reverse_lookup(address)}")
            log.error("error in continue until")
        done.set()
    def start_continue_until(self, address: int, done: DoneEvent, force: bool, breakpoint: Breakpoint) -> None:
        dbg = self.dbg
        if address == dbg.instruction_pointer:
            if DEBUG: dbg.logger.debug("new_libdebug needs to step to loop.")
            dbg.si()
        context.Thread(target=dbg.control.priority.inherit(self.continue_until, done), args=(address, done, force, breakpoint), name=f"[{dbg.pid}] continue_until", daemon=True).start()
    def native_breakpoint(self, address: int, hw: bool = False) -> LibdebugBreakpoint:
        dbg = self.dbg
        return dbg.new_libdebug.breakpoint(address, hardware=hw)
    def breakpoint(self, address: int, legacy_callback: Callable[[Debugger], bool | int | None] | None, callback: Callable[[Debugger], bool | int | None] | None, temporary: bool, user_defined: bool, hw: bool) -> Breakpoint:
        dbg = self.dbg
        if legacy_callback is not None:
            callback = legacy_callback
        if address in dbg.new_libdebug.breakpoints:
            bp = dbg.new_libdebug.breakpoints[address]
            bp.enable()
        else:
            bp = self.native_breakpoint(address, hw=hw)
        return Breakpoint(bp, address, callback, temporary, user_defined, hw)
    def saved_ip(self, link_register: str | None) -> int:
        dbg = self.dbg
        try:
            address = dbg.new_libdebug.backtrace()[-1]
            assert address != dbg.instruction_pointer
        except:
            address = dbg._find_rip()
        return address
    def step(self, signal: int | str, timeout: float | None, internal: bool) -> tuple[PriorityEvent | None, bool]:
        dbg = self.dbg
        if signal:
            dbg.new_libdebug.signal = signal
        event = dbg.execute_action(lambda: dbg.new_libdebug.step(), sender="step", internal=internal, step=True)
        finished = dbg.control.priority_wait(comment="step", priority=event, timeout=timeout)
        return event, finished
    def signal(self, n: int | str, step: bool, timeout: float | None) -> None:
        dbg = self.dbg
        dbg.new_libdebug.signal
        if step:
            dbg.step()
        else:
            dbg.c()
    auxiliary_vector = LibdebugBackend.auxiliary_vector
    def stop_reason(self) -> str:
        dbg = self.dbg
        signal = dbg.stop_signal
        if signal == 0x5 and dbg.instruction_pointer in dbg.new_libdebug.breakpoints:
            return "BREAKPOINT"
        elif signal == 0x5 and dbg.control.stepped:
            return "SINGLE STEP"
        else:
            return SIGNALS_from_num[signal]
    def detach(self, quit: bool, block: bool) -> None:
        dbg = self.dbg
        dbg.control.kill_threads.set()
        dbg.control.closed.set()
        dbg.new_libdebug._resumed.set() # Force wait to finish and close loop_stop_handler_new_libdebug
        sleep(0.1) # Let wait be called to close thread before killing process (prevent RuntimeError in libdebug)
        if quit:
            dbg.new_libdebug.kill()
        else:
            dbg.new_libdebug.detach()
            if block:
                os.kill(dbg.pid, signal.SIGSTOP)
                log.warn_once("new libdebug doesn't support detach with block. The program may have executed some code before stopping again")
    def stop_splitting(self) -> None:
        dbg = self.dbg
        dbg.new_libdebug._internal_debugger.follow_children = False
    def start_splitting(self, interrupt: bool, script: str) -> None:
        dbg = self.dbg
        # Already true by default, but amen
        dbg.new_libdebug._internal_debugger.follow_children = True
        if interrupt:
            log.warn_once("new_libdebug will not tell you when the children are created! You can not interrupt.")
    def read_register(self, name: str) -> int:
        dbg = self.dbg
        res = getattr(dbg.new_libdebug.regs, _NEW_LIBDEBUG_REGISTERS.get(name, name))
        return res
    def write_register(self, name: str, value: int) -> None:
        dbg = self.dbg
        setattr(dbg.new_libdebug.regs, _NEW_LIBDEBUG_REGISTERS.get(name, name), value % 2**context.bits) # doesn't support negative values
    @lock_decorator
    @context_decorator
    def handle_stop(self) -> None:
        """
        Actions that the debugger performs every time the process is interrupted except when exiting
        Handle temporary breakpoints and callbacks

        New_libdebug assumes that we stopped because of a breakpoint.
        """
        # Current inferior will change to the inferior who stopped last
        dbg = self.dbg
        ip = dbg.instruction_pointer
        breakpoints = dbg.control.breakpoints[ip]

        if DEBUG: _logger.debug("[%d] stopped at address: %s for %s", dbg.pid, dbg.reverse_lookup(ip), dbg._stop_reason)
            
        # We need to define a callback that sets stop reason for each signal if we want to use this [19/06/25]
        # if self._stop_reason in SIGNALS and SIGNALS[self._stop_reason] in self._handled_signals:
        #     should_stop = self._handled_signals[SIGNALS[self._stop_reason]](self)
        #     if should_stop == False:
        #         self._hidden_continue()
        #     else:
        #         if self._ptrace_emulated:
        #             if DEBUG: self.logger.debug("stop will be handle by waitpid")
        #             self._ptrace_has_stopped.set()
        #         else:
        #             self._set_stop(f"signal {self._stop_reason} handled")
        #     return  

        # Do we want to let libdebug handle catchpoints ? [19/06/25]
        # if (callback := self._event_breakpoints.get(self._details_breakpoint_stopped, None)) is not None:
        #     if DEBUG: self.logger.debug("stopped for catchpoint")
        #     name = list(self._event_table.keys())[list(self._event_table.values()).index(self._details_breakpoint_stopped)]
        #     # Syscalls have to be handled differently because we break both when calling it and when returning
        #     if name.startswith("syscall "):
        #         if self._syscall_return == False: 
        #             # Make sure we don't miss the return
        #             # Put above to avoid race condition after the jump
        #             self._raise_priority("handling syscall")
        #             should_skip = callback(self, entry=True)
        #             if should_skip is not None and should_skip & SKIP_SYSCALL:
        #                 self.jump(self.instruction_pointer)
        #                 if not should_skip & SHOULD_STOP:
        #                     self._hidden_continue()
        #                 else:
        #                     # Wait I must stop for the user, not the emulator...
        #                     # I should tell any wait() that I stopped, but not waitpid...
        #                     # if self._ptrace_emulated:
        #                     #     self._ptrace_has_stopped.set()
        #                     #else:
        #                     #    # TODO TEST IT [26/07/23]
        #                     self._set_stop("stopped after skipping syscall")
        #                 self._lower_priority("syscall skipped")    
        #                 return
        #             # hit the return
        #             self._syscall_return = True
        #             self.c()
        #             should_stop = callback(self, entry=False)
        #             self._lower_priority("syscall handled")
        #             self._syscall_return = False
        #             if should_stop == False:
        #                 self._hidden_continue()
        #             else:
        #                 self._set_stop("returned from syscall")
        #         else:
        #             self._set_stop("returned from syscall")
        #         return
        #     else:
        #         self._raise_priority("handling event")
        #         should_stop = callback(self)
        #         should_stop = True if should_stop is None else should_stop
        #         self._lower_priority("event handled")
        #         if should_stop:
        #             should_continue = False
        #             self._set_stop("event callback returned True or None")
        #         else:
        #             if DEBUG: self.logger.debug("[%d] callback returned False", self.pid)
        #             self._hidden_continue()
        #         return

        if len(breakpoints) == 0:
            if dbg.control.interrupted:
                dbg.control.interrupted_stop()
            elif dbg.control.stepped:
                dbg.control.stepped = False
                dbg.control.set_stop("stepped")
            elif dbg._stop_reason in SIGNALS:
                if not dbg.ptrace.take_stop():
                    dbg.control.set_stop(f"signal: {dbg._stop_reason}")
            else:
                log.warn_once("Unknown stop reason in libdebug!")
                if DEBUG: dbg.logger.debug("stopped for an unknown reason")
                dbg.control.enforce_stop("manual interaction")
            return

        dbg.control.spawn_handler(dbg.control.handle_breakpoints, breakpoints, name=f"[{dbg.pid}] handle breakpoint {hex(ip)}")
    def setup(self) -> None:
        dbg = self.dbg
        dbg.new_libdebug._resumed = Event()
        
        dbg.control.closed.clear()
        dbg.control.kill_threads.clear()

        def loop_handler() -> None:
            while True:
                dbg._internal_wait()
                if DEBUG: dbg.logger.debug("new_libdebug stopped somewhere.")
                
                if dbg.control.kill_threads.is_set() or dbg.control.closed.is_set():
                    if DEBUG: dbg.logger.debug("exiting loop handler")
                    break
                stop = dbg.control.priority.stop_detected("new_libdebug stop")
                dbg.control.spawn_handler(self.handle_stop, name=f"[{dbg.pid}] stop_handler_new_libdebug", handler_context=stop)
        context.Thread(target=loop_handler, name=f"[{dbg.pid}] loop_stop_handler_new_libdebug", daemon=True).start()
    def send_command(self, command: str | Callable[[], object]) -> None:
        dbg = self.dbg
        if command != "":
            command()
            dbg.new_libdebug._resumed.set()
            return
        super().send_command(command)
    def repr(self) -> str | None:
        dbg = self.dbg
        # libdebug's repr reads the registers: it would wait forever for a running process
        if not dbg.new_libdebug.running:
            return dbg.new_libdebug.__repr__()
