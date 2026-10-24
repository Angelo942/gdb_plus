from __future__ import annotations

from pwn import context, log, sleep

from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, IMPORTANT_DEBUG_OFF

class StopsMixin(DebuggerBase):
    """
    What happens when the process stops. A stop handler, on a thread of the debugger and holding _action_lock,
    classifies the stop, runs the breakpoint callbacks, then either resumes the process or wakes the action waiting
    for this stop (_set_stop, through the PriorityManager). Also what the script can ask about the last stop:
    _stop_reason, stop_signal, running, wait().
    """


        #context.Thread(target=self._handle_breakpoints, args=(breakpoints,)).start()

    # Taken from GEF to handle slave interruption
    @property
    def _stop_reason(self) -> str:
        # We need a loop because we noticed if you continue manually from gdb and then call interrupt, the interrupt will continue before the process really stopped. 
        # If it's a general problem with gdb is better to keep it here, if it comes out only in interrupt let's move it to there
        # Right now I don't like that if the program is running, info program fails and we get NOT RUNNING instead. It's confusing.
        counter = 0
        while counter < 5:
            if self.running:
                sleep(0.1)
            counter += 1
        return self._backend.stop_reason()

    @property
    def stop_signal(self) -> int:
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return None
        return self._backend.stop_signal()

    @property
    def _details_breakpoint_stopped(self) -> int | None:
        """
        If the program stopped at a breakpoint, return the id of that breakpoint
        This can be used to identify caught syscall
        """
        res = self.gdb.execute("info program", to_string=True).splitlines()
        if not res:
            raise Exception("NOT RUNNING")

        # For some reason `catch load` has """It stopped at breakpoint -2.\nIt stopped at breakpoint 2.""" [21/07/24]
        for line in res[::-1]:
            line = line.strip()
            #It stopped at breakpoint 2.
            if line.startswith("It stopped at breakpoint "):
                return int(line.split(".")[0][len("It stopped at breakpoint "):])
        else:
            log.warn("process didn't stop for a breakpoint")

    def wait(self, timeout: float | None = None, legacy: bool = False) -> bool:
        """
        Wait until the process is stopped and every action in flight has been handled: yours (c(wait=False)...), the ones of the callbacks
        and the commands typed in gdb. The actions suspended by interrupt() don't count: they only go on after resume().
        Never changes the priority.
        Returns False on timeout. legacy is ignored (kept for compatibility)
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return True

        if self.control.priority.in_handler():
            log.warn("wait() inside a callback would wait for the callback itself. Returning immediately")
            return False
        return self.control.priority.wait_idle(timeout)

    def _internal_wait(self) -> None:
        "Blocking wait for interruption detection"
        return self._backend.internal_wait()

    # problems when I haven't executed anything
    # Inside a callback checking running doesn't make sense since in that instant the program is interrupted, but we define it as running for interrupt() to still stop the program when we finish the callback. 
    @property
    def running(self) -> bool:
        if not self.debugging:
            return False
        with context.silent:
            return self._backend.running()

    @property
    def priority(self) -> int:
        "Number of actions waiting for a stop of the process, the ones suspended by interrupt() included"
        return self.control.priority.priority

    #def __hidden_stop(self, name="someone", /):
    #    if self.gdb is not None:
    #        pid = self.current_inferior.pid
    #    elif self.libdebug is not None:
    #        pid = self.pid # Handle thread
    #    else:
    #        ...
    #    if self._myStopped.is_set():
    #        log.debug(f"[{pid}] stopped has been hidden_cleared by {name}")
    #        self._myStopped.hidden_clear()

    # For now is handled by simple wait [06/03/23]
    def _wait_exit(self) -> None:
        self.control.closed.wait()
