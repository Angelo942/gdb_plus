from __future__ import annotations

from threading import Event
from typing import TYPE_CHECKING

from pwn import context, log, sleep

from gdb_plus.utils import DEBUG, PriorityEvent, SUSPENDED, DoneEvent, Breakpoint
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, INTERRUPT_SENT, INTERRUPT_HIT_BREAKPOINT, lock_decorator, context_decorator

if TYPE_CHECKING:
    from typing import Callable
    from gdb_plus.debugger.debugger import Debugger

class ControlFlowMixin(DebuggerBase):
    """
    Let the process run until something stops it (c / cont, continue_until, jump, ret) and stop it (interrupt).
    resume() lets the actions that interrupt() suspended go on. _hidden_continue() resumes the process after a stop
    the debugger handled by itself.
    """
    # For commands that will make the process run and should handle priority
    def execute_action(self, command: str | Callable[[], object], sender: str | None = None, *, internal: bool = False, step: bool = False) -> PriorityEvent | None:
        """
        Wrapper around execute to handle commands that will require a wait.
        Returns the PriorityEvent to pass to _priority_wait(): the stop that follows the command is handed to it.
        While an interrupt() is in effect (see PriorityManager.begin_action): a callback, or a task it started, sends the
        command only after resume(); a task of the script started before the interrupt raises Interrupted; the script
        raises Suspended.
        internal: the command is a step the stop handler needs to finish handling the current stop (the jump that skips a
                  syscall): it is sent even if interrupt() suspended that stop.
        step: the command executes a single instruction (resume() executes it again if interrupt() stops it)
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        name = sender if sender is not None else str(command)
        event = self.control.priority.begin_action(name, resumes=command != "", internal=internal, step=step)
        self.control.callback_return_overwritten = False # Not needed for gdb since it's set by events.cont, but this keeps a better readability
        try:
            self._backend.send_command(command)
        except BaseException:
            self.control.priority.cancel_action(event, name)
            raise
        self.control.priority.task_resumed()
        return event

    # Simplify continue after callback so that it can still work after migrating inside the callback
    # It has to do everything like execute action continue, except raising the priority
    @lock_decorator
    def _hidden_continue(self, force: bool = False) -> None:
        # The step is not needed if we set handle SIGSTOP nopass
        #address = self.instruction_pointer
        #if force:
        #    self.step(force=True)
        #    if address == self.instruction_pointer:
        #        log.debug(f"[{self.pid}] I think I stopped my step for a good reason so I won't continue")
        #        return
        refused = self.control.priority.auto_resume()
        if refused == SUSPENDED:
            # interrupt() suspended this stop: nobody is woken, resume() will resume the process
            if DEBUG: self.logger.debug("not resuming: %s", refused)
            return
        if refused is not None:
            # The process must stay stopped (interrupt() called by a callback, or another breakpoint at this address stops):
            # give the stop to the action waiting for it instead of resuming
            if DEBUG: self.logger.debug("not resuming: %s", refused)
            self.control.set_stop(refused)
            return
        if DEBUG: self.logger.debug("hidden continue")
        sleep(0.02)
        self._resume_process()

    def _resume_process(self, step: bool = False) -> None:
        """
        Send the command that resumes the process without creating a PriorityEvent: the actions already waiting receive the
        next stop. Shared by the auto-resumes of the stop handlers (_hidden_continue) and by resume(). The caller has
        already counted the process as running (PriorityManager.auto_resume() / PriorityManager.resume()).
        step: execute a single instruction instead of continuing
        """
        self.control.callback_return_overwritten = False
        self._backend.resume_process(step)

        
    # TODO make the option to have "until" be non blocking with an event when we reach the address [28/04/23] In other words migrate wait=False to wait=Event()
    @context_decorator
    def c(self, *, wait: bool = True, force: bool = False, signal: int = 0x0) -> Debugger | Event | None:
        """
        Continue execution of the process

        Arguments:
            wait: Should block your script until the next interruption ?
            until: Continue until a specified location. Your script will wait if you have to play with gdb manually.

            force: gdb may bug and keep you at the same address after a jump or if the stack frame as been edited. If you notice this problem use force to bypass it. If you don't worry about a callback being called twice don't bother
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self.control.priority.check_can_resume("continue")
        # I have to use an event instead of priority_wait() because I may have to stop after the step [22/05/23]
        # The continue counts as a task from now until its thread ends: wait() and interrupt() see it before the thread resumes the process
        done = DoneEvent(self.control.priority)

        self._backend.start_continue(force, wait, done, signal)

        if wait:
            done.wait()
            return self
        else:
            #pass
            # I would like to return done too, but I'm sure the average user will try dbg.wait instead of done.wait 
            # dbg.wait() would bring priority to -1, but it is still more intuitive than done.wait() so I will try to change _continue_* to allow the user to use wait() [29/07/23 21:30]
            # Nope, too many problems with priority so I get back to the event. Later we will think about separating wait and priority_wait [29/07/23 21:40]
            # Return once the thread resumed the process: an interrupt() right after this call finds it running
            done.wait_resumed()
            return done

    cont = c

    def _forget_breakpoint(self, address: int, breakpoint: Breakpoint | None) -> None:
        "Delete the temporary breakpoint of an action that interrupt() ended, if it is still there"
        if breakpoint is not None and breakpoint in self.control.breakpoints[address]:
            self.delete_breakpoint(breakpoint)

    
            
    # I'm worried about how to handle the lock in this case [12/06/23] I want to block until I send the continue
    # I would like to keep the same priority for step and continue [18/06/23]
    @context_decorator
    def continue_until(self, location: int | str, /, *, wait: bool = True, force: bool = False, loop: bool = False, hw: bool = False) -> Debugger | Event:
        """
        Continue until a specific address
        can be blocking or non blocking thanks to wait
        It the function is called from the address you want to reach the intended behaviour is to do nothing and return. Set loop=True to continue anyway
        
        Arguments:
            location: Where to stop the execution. Can be a relative address, absolute address or symbol name.
            wait: Wait for the program to reach the destination or return a event set when done.
            until: Continue until a specified location. Your script will wait if you have to play with gdb manually.

            force: gdb may bug and keep you at the same address after a jump or if the stack frame as been edited. If you notice this problem use force to bypass it. If you don't worry about a callback being called twice don't bother
        """
        with self.control.action_lock.log("continue_until"):
            if not self.debugging:
                done = DoneEvent()
                done.set()
                log.warn_once(DEBUG_OFF)
                return done

            self.control.priority.check_can_resume("continue_until")
            # The action counts as a task from now until its thread ends: wait() and interrupt() see it before the thread resumes the process
            done = DoneEvent(self.control.priority)
            address = self._parse_address(location)
            if address != self.instruction_pointer or loop:
                breakpoint = self.b(address, temporary=True, user_defined=False, hw=hw)
                if DEBUG: self.logger.debug("continuing until %s", self.reverse_lookup(address))

                self._backend.start_continue_until(address, done, force, breakpoint)

            else:
                log.warn(f"I'm already at {self.reverse_lookup(address)}")
                log.warn_once("Be careful that the default behaviour changed. Use loop=True if you want to continue anyway")
                done.set()



        if wait:
            done.wait()
            return self
        else:
            done.wait_resumed()
            return done

    until = continue_until

    def _kick(self) -> None:
        "Send the signal that stops the running process"
        self.control.interrupted = True
        if DEBUG: self.logger.debug("interrupting [pid:%d]", self.pid)
        self._backend.kick()

    def _catch_pending_sigint(self) -> int:
        """
        The process stopped for something else (a breakpoint) before our SIGINT arrived: the signal is still pending and would stop the next action.
        Step until gdb reports it, without calling again the callbacks of the current address.
        """
        return self._backend.catch_pending_sigint()

    def _interrupt_inner(self) -> int:
        """
        Stop the running process with a SIGINT and wait for that stop, for split() and step(timeout=).
        Unlike interrupt(), the other actions keep waiting and the process may be resumed afterwards.
        Returns 0 if the process wasn't running, otherwise INTERRUPT_SENT (| INTERRUPT_HIT_BREAKPOINT)
        """
        event = self.control.priority.claim_if_running("interrupt")
        if event is None:
            return 0
        self._kick()
        self.control.priority_wait(comment="interrupt", priority=event)
        res = INTERRUPT_SENT
        if self.control.interrupted:
            res |= self._catch_pending_sigint()
        return res

    # Breakpoint callbacks should be handled before the interruption to simplify the logic and I guess that if we reach a breakpoint and still send a SIGINT the signal will arrive later
    # how do I interrupt in case of remote debugging ?
    # TODO support libdebug [19/06/25]
    @lock_decorator
    @context_decorator
    def interrupt(self, *, strict: bool = False, timeout: float = 10) -> int | bool | None:
        """
        Stop the process. When interrupt() returns the process is stopped and nothing will resume it by itself.
        - Your actions in progress end: a c(wait=False), until(wait=False), next(wait=False) or finish(wait=False) is done
          (done.interrupted is True) and dbg.priority goes back down. You continue with any action, like c().
        - The callbacks don't know about it. If one is in the middle of an action (a finish(), an until(), a step over a
          syscall of a catchpoint) or starts one, that action is suspended: dbg.priority still counts it, the process can't
          be resumed (Suspended) and resume() lets it go on. When the callback is done the process stays stopped: the
          action of the script it belonged to is over. A call() is suspended the same way.
        - A callback that is running is waited for (up to timeout, then a warning is printed). If it returns False, the
          process stays stopped.
        Called from a callback, the process stays stopped once the callbacks of this stop are done: the stop goes to the
        action waiting for it, and there is nothing to resume.
        strict is ignored (kept for compatibility).

        Returns False if nothing was running, otherwise INTERRUPT_SENT (| INTERRUPT_HIT_BREAKPOINT if the process stopped for a breakpoint first)
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        manager = self.control.priority
        if self.libdebug is not None:
            if not manager.busy():
                return False # Nothing to stop: same answer as the other backends
            raise NotImplementedError(f"interrupt is not implemented for libdebug")

        if not context.native and (self.local_debugging or self.pid is None):
            log.warn_once("Interrupting process under QEMU may not work!")

        if manager.in_handler():
            manager.request_stop()
            return self._interrupt_inner() or INTERRUPT_SENT

        if not manager.hold():
            # Another thread is interrupting: wait for it to finish
            manager.wait_idle(timeout)
            return INTERRUPT_SENT
        try:
            if not manager.busy():
                return False
            if not manager.suspend(self._kick, timeout, set_aside=self._set_aside):
                log.warn(f"[{self.pid}] interrupt(): some callbacks are still running after {timeout}s")
            res = INTERRUPT_SENT
            if self.control.interrupted:
                res |= self._catch_pending_sigint()
            return res
        finally:
            manager.release()

    manual = interrupt

    @lock_decorator
    @context_decorator
    def resume(self) -> bool:
        """
        Let the actions of the callbacks (and the call()) that interrupt() suspended go on, as if the process had never been
        stopped: they receive their stops where they expected them. The process is resumed with the command the interrupt
        stopped (a continue, or a step blocked in a syscall), or by the callback that was waiting to act. Unlike c() it
        doesn't start a new action. Once the callbacks are done the process stays stopped.

        Returns False if there was nothing to resume: interrupt() didn't have to suspend anything
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return False

        manager = self.control.priority
        if not manager.suspended:
            log.warn("resume(): there is no interrupt() to undo")
            return False
        if manager.busy():
            log.warn("resume(): the process runs (it was resumed from gdb?). Wait for it to stop first")
            return False
        command = manager.resume(put_back=self._put_back)
        if command is None:
            return True
        try:
            self._resume_process(step=command == "step")
        except BaseException:
            # The command failed: the process didn't move
            manager.stopped_externally()
            raise
        return True

    def _set_aside(self) -> dict[str, object]:
        """
        Called by PriorityManager.suspend() once the suspended layer waits. Its stop handler may be in the middle of a step
        (the step over a syscall of a catchpoint): its flags must not apply to the other stops until resume(), like the ones
        of the steps of _catch_pending_sigint(). Returns them and resets them; _put_back() restores them.
        """
        state: dict[str, object] = {"stepped": self.control.stepped, "syscall_return": self.control.syscall_return}
        self.control.stepped = False
        self.control.syscall_return = False
        return state

    def _put_back(self, state: dict[str, object]) -> None:
        "Called by PriorityManager.resume() before the suspended layer goes on: restore the flags _set_aside() took"
        self.control.stepped = state["stepped"]
        self.control.syscall_return = state["syscall_return"]

    # How to handle a jump no wait without destroying the priority queue ? [17/04/23]
    # Don't let it as an option... [17/04/23]
    def jump(self, location: int | str) -> Debugger | None:
        """
        Jump to specified location
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        #log.warn_once("jump is deprecated. Overwrite directly the instruction pointer instead")
        address = self._parse_address(location)

        # I end up allowing it because to skip a syscall I have to jump, but gdb thinks I'm already at the next instruction [26/07/23]
        #if address == self.instruction_pointer:
        #    if DEBUG: self.logger.debug("not jumping because I'm already at %s", self.reverse_lookup(address))
        #    return
        
        if DEBUG: self.logger.debug("jumping to %s", self.reverse_lookup(address))
        self._backend.jump(address)
        return self

        
    # Now can return from anywhere in the function
    # Works only for standard functions (push rbp; mov rbp, rsp; ...; leave; ret;). May crash if used in the libc
    # Can't I use _saved_ip now ? [28/04/23]
    def ret(self, value: int | None = None) -> Debugger:
        """
        Exit from current function without executing it. 

        Warning: Experimental and depends on the stack frame
        """
        raise Exception("Not implemented yet")
        if self.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
            pass
        elif self.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
            self.pop() # Remove the base pointer # No need to place it back in rbp
        else:
            self.stack_pointer = self.base_pointer
            self.base_pointer = self.pop()
        ret_address = self.pop()
        self.jump(ret_address)
        if value is not None:
            self.return_value = value
        return self
