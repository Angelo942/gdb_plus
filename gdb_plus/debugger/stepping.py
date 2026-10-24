from __future__ import annotations

from threading import Event
from typing import TYPE_CHECKING

from pwn import context, log

from gdb_plus.utils import DEBUG, DoneEvent, set_done_if_panic
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, lock_decorator, context_decorator

if TYPE_CHECKING:
    from typing import Callable
    from gdb_plus.debugger.debugger import Debugger

class SteppingMixin(DebuggerBase):
    """
    Run the process instruction by instruction: step / si, next / ni, finish, and the step_until_* and
    next_until_call loops.
    """
    def _step(self, signal: int | str = 0x0, timeout: float | None = None, *, internal: bool = False) -> bool:
            address = self.instruction_pointer

            if DEBUG: self.logger.debug("stepping from 0x%x", self.instruction_pointer)
            self.control.stepped = True
            try:
                event, finished = self._backend.step(signal, timeout, internal)

                if not finished:
                    if DEBUG: self.logger.warning("Tried to stepped into a syscall. Interrupting...")
                    # Stop the process for this step only, without touching the other actions. The stop goes to the interrupt,
                    # so the step then removes its own event
                    self._interrupt_inner()
                    self.control.priority.lower_priority(event, "step interrupted")
            finally:
                self.control.stepped = False
            return address != self.instruction_pointer

    # Next may break again on the same address, but not step
    # Why isn't force = True the default behaviour ? [29/04/23]
    # I don't use force=True by default because there are instructions that keep the instruction pointer at the same address even if executed [05/05/23]
    # You need force=True on continue to avoid double call to callbacks [30/05/23]
    @lock_decorator
    def step(self, repeat: int = 1, *, force: bool = False, signal: int | str = 0x0, timeout: float | None = None) -> Debugger:
        """
        execute a single instruction

        Argument:
            repeat: step n times
            force : if the stack frame has been tampered with gdb may stay stuck on the current instruction. Use force to handle this bug in gdb
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self

        if repeat <= 0:
            return self

        # Should only be the first step, right ? [08/05/23]
        if force:
            self._broken_step()
            repeat -= 1

        for _ in range(repeat):
            if not self._step(signal, timeout=timeout):
                log.warn("You stepped, but the address didn't change. This may be due to a bug in gdb. If this wasn't the intended behaviour use force=True in the function step or continue you just called")

        return self

    si = step

    # I should catch SIGSTOP, but not other exceptions
    def _broken_step(self) -> None:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return
        old_ip = self.instruction_pointer
        callback = None

        # Remove callback to avoid calling it twice (Nice, this wasn't possible with legacy_callbacks) (I'm not sure if we could simply disable a breakpoint for a turn)
        saved_callbacks = []
        for breakpoint in self.control.breakpoints[old_ip]:
            saved_callbacks.append(breakpoint.callback)
            breakpoint.callback = None
        try:
            with context.silent:
                # Let's talk... Usually the problem is with SIGSTOP, right ? There are cases where we jump on a signal, so we won't always have a SINGLE STEP.
                #n = self.step_until_condition(lambda self: self.instruction_pointer != old_ip or self._stop_reason == "SINGLE STEP", limit=5)
                # I don't understand how you can have a stop for single step without changing, but it happens [12/06/23]
                n = self.step_until_condition(lambda self: self.instruction_pointer != old_ip or self._stop_reason not in ["SIGSTOP", "SINGLE STEP", "BREAKPOINT"], limit=5, timeout=5) # 0.2 is too low when splitting processes # 2 is too low when handling some breakpoints
        finally:
            # Also when a step raises (Interrupted): the callbacks of this address must survive
            for breakpoint, callback in zip(self.control.breakpoints[old_ip], saved_callbacks):
                breakpoint.callback = callback
        if n == -1:
            raise Exception("Could not force step!")
        if n > 0:
            if DEBUG: self.logger.warning("Bug still present. Had to force %d time(s)", n)

    # For backward compatibility
    exit_broken_function = _broken_step

    # Should I implement a wait = False here to in case an input is needed ? [28/04/23] (In the meanwhile handle it in the callback)
    # TODO handle timeout
    def step_until_address(self, location: int | str, callback: Callable[[Debugger], object] | None = None, limit: int = 10_000) -> int | None:
        """
        step until a particular address is reached.
        Useful to analyse self modifying functions.
        
        Arguments:
            location: address or symbol to reach
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        address = self._parse_address(location)
        for i in range(limit):
            if callback is not None:
                callback(self)
            if self.instruction_pointer == address:
                return i
                break
            self.step()
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the address you are looking for...")
            return -1

    # May be wrong for RISC-V
    # TODO handle timeout
    def step_until_ret(self, callback: Callable[[Debugger], object] | None = None, limit: int = 10_000) -> int | None:
        """
        step until the end of the function

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            if callback is not None:
                callback(self)
            if self.next_inst.mnemonic == "ret":
                return i
                break
            self.step()
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the end of the function...")
            return -1

    def step_until_condition(self, condition: Callable[[Debugger], bool], limit: int = 10_000, timeout: float | None = None) -> int | None:
        """
        Step until condition(self) returns True or limit exceeded
        The condition will be tested after the first step
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            self.step(timeout=timeout)
            if condition(self):
                return i

        # Why not raise exception ? [10/05/23]
        log.warn_once(f"I made {limit} steps and haven't found what you are looking for...")
        return -1

    # TODO handle timeout
    def step_until_call(self, callback: Callable[[Debugger], object] | None = None, limit: int = 10_000) -> int | None:
        """
        step until a call to a function
        will look inside the function if the first instruction is already a call

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            self.step()
            if callback is not None:
                callback(self)
            if self.next_inst.is_call:
                return i
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the end of the function...")
            return -1

    @set_done_if_panic
    def _next(self, repeat: int, done: DoneEvent, hw: bool) -> None:
        for _ in range(repeat):
            next_inst = self.next_inst
            if next_inst.is_call:
                self.continue_until(next_inst.return_address, hw=hw)
            else:
                self.step()
        done.set()

    # May not want to wait if you are going over a functions that need user interaction
    @context_decorator
    def next(self, wait: bool = True, repeat: int = 1, hw: bool = False) -> Debugger | Event:
        if not self.debugging:
            done = DoneEvent()
            done.set()
            log.warn_once(DEBUG_OFF)
            return done

        self.control.priority.check_can_resume("next")
        done = DoneEvent(self.control.priority)
        context.Thread(target=self.control.priority.inherit(self._next, done), args=(repeat, done, hw), name=f"[{self.pid}] next", daemon=True).start()
        if wait:
            done.wait()
            return self
        else:
            done.wait_resumed()
            return done

    ni = next

    def next_until_call(self, callback: Callable[[Debugger], object] | None = None, limit: int = 10_000) -> int | None:
        """
        step until the end of the function
        will continue over the first function if called when already before a call

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            self.next()
            if callback is not None:
                callback(self)
            if self.next_inst.is_call:
                return i
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the end of the function...")
            return -1

    @set_done_if_panic
    def _finish(self, repeat: int, force: bool, done: DoneEvent | None, hw: bool) -> None:
        # Should be possible to take immediately the corresponding stack frame instead of using a loop [28/04/23]
        for _ in range(repeat):
            ip = self._saved_ip
            if DEBUG: self.logger.debug("finish found next ip : 0x%x", ip)
            if ip == 0:
                raise Exception("stack frame is broken or we are not in a function")
            if ip == self.instruction_pointer:
                log.warn(f"wait, we already are at the address {hex(ip)}!")
                log.warn("Trying experimental finish. Use dbg.execute('finish') if this doesn't work")
                ip = self._find_rip()
            self.continue_until(ip, force=force, hw=hw)
        if done is not None:
            done.set()

    # May be dependent on the stack frame and cause problems after a jump [27/04/23]
    @context_decorator
    def finish(self, *, wait: bool = True, repeat: int = 1, force: bool = False, hw: bool = False) -> Debugger | Event:
        if not self.debugging:
            done = DoneEvent()
            done.set()
            log.warn_once(DEBUG_OFF)
            return done

        self.control.priority.check_can_resume("finish")
        done = DoneEvent(self.control.priority)
        context.Thread(target=self.control.priority.inherit(self._finish, done), args=(repeat, force, done, hw), name=f"[{self.pid}] finish", daemon=True).start()
        if wait:
            done.wait()
            return self
        else:
            done.wait_resumed()
            return done
