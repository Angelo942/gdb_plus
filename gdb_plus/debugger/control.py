from __future__ import annotations

from collections import defaultdict
from threading import Event
from typing import TYPE_CHECKING

from pwn import context, log

from gdb_plus.utils import DEBUG, unexpected, PriorityManager, MyLock, PriorityEvent, HandlerContext, Breakpoint
from gdb_plus.debugger._base import DEBUG_OFF, _RESTART_SYSCALL, context_decorator, GdbDiedError

if TYPE_CHECKING:
    from typing import Any, Callable
    from gdb import ExitedEvent
    from gdb_plus.debugger.debugger import Debugger

class Controller:
    """
    How the process goes from one stop to the next, the same for every engine: who receives each stop (the
    PriorityManager), the lock held by every action that lets the process run and by the stop handlers, the flags of
    the stop being handled, the tables of the breakpoints, catchpoints and handled signals, and what a stop handler does
    once it knows why the process stopped: run the callbacks, deliver the stop or leave it to nobody.
    dbg.control, created by DebuggerBase._init_state(). The stop policy of each engine is its Backend.handle_stop; the
    actions that let the process run are methods of the Debugger (ControlFlowMixin, SteppingMixin).
    Lock order: action_lock is taken before the backend is called, and the backends take no lock of their own (their
    lock_decorator is this same lock). Breakpoint callbacks receive the Debugger.
    """
    def __init__(self, dbg: Debugger) -> None:
        self.dbg = dbg
        # Set once the process is gone: the waiters check it to know that nothing will stop again
        self.closed = Event()
        # Set to end the threads that wait for the stops of the engine (detach, close)
        self.kill_threads = Event()
        # Held by the actions that let the process run and by the stop handlers. out_of_breakpoint is set when nobody holds it
        self.out_of_breakpoint = Event()
        self.action_lock = MyLock(self.out_of_breakpoint, owner=dbg)
        # NOTE: Do we want to save temporary breakpoints too ? [17/04/23]
        self.breakpoints: defaultdict[int, list[Breakpoint]] = defaultdict(list)
        self.handled_signals: dict[int, Callable[[Debugger], bool | None]] = {}
        # Which thread receives each stop of the process (see PriorityManager)
        self.priority = PriorityManager()
        # To know that I'm responsible for the interruption even if there is no callback
        self.stepped = False
        # To know that continue should resume the execution even if we hit a breakpoint
        self.callback_return_overwritten = False
        self.interrupted = False
        self.event_table: dict[str, int] = {}
        self.event_breakpoints: dict[int, Callable[..., bool | int | None]] = {}
        self.syscall_return = False
    # context_decorator reads these on the object whose method it decorates
    @property
    def _initialized(self) -> bool:
        return self.dbg._initialized
    @property
    def _context_params(self) -> dict[str, Any]:
        return self.dbg._context_params
    def handle_breakpoints(self, breakpoints: list[Breakpoint]) -> None:
        """
        Execute callbacks and determine if the execution should resume.
        """
        dbg = self.dbg
        should_continue = True
        callback_return_overwritten = True
        stepped = self.stepped # Save it in this scope to make sure that no action performed by a callback can change it. It's just unfortunate that I can not detect it yet for manual interactions. 
        # I don't set stop after each breakpoint to avoid letting a script continue while another callback is running [06/06/23]
        set_stop = []
        address = dbg.instruction_pointer
        if DEBUG: dbg.logger.debug("0x%x: %d %s", address, len(breakpoints), breakpoints)
        # Invert list of breakpoints to make callback resolution in LIFO order
        for breakpoint in breakpoints[::-1]:
            if breakpoint.temporary:
                dbg.delete_breakpoint(breakpoint)

            if breakpoint.callback is None:
                should_continue = False
                callback_return_overwritten &= False
                # Must be set for each breakpoint for the library functions to work [05/06/23]
                # Check that the priorities can't be broken by a breakpoint set by the user... [05/06/23]
                set_stop.append(f"No callback")
            else:
                should_stop = breakpoint.callback(dbg)
                should_stop = True if should_stop is None else should_stop
                if should_stop:
                    should_continue = False
                    callback_return_overwritten &= False
                    set_stop.append(f"callback returned True or None")

                else:
                    should_continue &= True
                    if DEBUG: dbg.logger.debug("[%d] callback returned False", dbg.pid)
                    # if self._stop_reason == "SINGLE STEP": # Simple version. If the user is stepping the breakpoint should never make the program continue [05/06/23]
                    if stepped: # _stop_reason will never return SINGLE_STEP if there is a breakpoint. [28/06/25]
                        if DEBUG: dbg.logger.debug("[%d] Callback 0x%x would continue, but we don't because you stepped.", dbg.pid, dbg.instruction_pointer)
                        should_continue = False
                        callback_return_overwritten &= True
                        set_stop.append(f"callback overwritten by step rule.")

        # I just don't want to have an also in that if stepped so i check here instead if we have should_continue set to false... Change if you think it's clearer, but I like the idea of touching that property only if we are sure instead of setting it to true by accidente [28/06/25]
        self.callback_return_overwritten = callback_return_overwritten and not should_continue


        # Each breakpoint that asked to stop gives one stop. The first one goes now to the last action waiting, the others replace the
        # next auto-resumes so that they reach the actions below it (see PriorityManager.expect_more_stops)
        if set_stop:
            if DEBUG: dbg.logger.debug("stops at this address: %d", len(set_stop))
            self.priority.expect_more_stops(len(set_stop) - 1)
            self.set_stop(set_stop[0])
        elif should_continue:
            dbg._hidden_continue()
    def spawn_handler(self, target: Callable[..., None], *args: object, name: str, handler_context: HandlerContext | None = None) -> None:
        """
        Start a thread that handles a stop, inside the HandlerContext of that stop (see PriorityManager).
        handler_context: the context opened when the stop was detected. Without it the new thread handles the same stop as
        the current thread (the thread of the breakpoint callbacks, started by the stop handler).
        """
        manager = self.priority
        if handler_context is None:
            handler_context = manager.current_context()
            if handler_context is None:
                handler_context = manager.open_context(name)
            else:
                manager.share(handler_context)
        def run() -> None:
            manager.enter(handler_context)
            try:
                target(*args)
            finally:
                manager.leave(handler_context)
        context.Thread(target=run, name=name, daemon=True).start()
    # 02/05/25
    # By default this callback is executed every time a process exits, but that includes both our program finishing, and inferior finishing and us detaching from a process
    # We want all of them to set gdb.stopped both to let know the debugger the process stopped, or to kill the loop thread when we detach
    # You may not want to do it when you detach from a child process that is already at a stop though so we should disable the callback before splitting 
    # If the main process exits then we should close the debugger
    @context_decorator
    def exit_handler(self, event: ExitedEvent) -> None:
        # Should I kill all children ? []
        # Waiiiiit, this is called even if we detach from the child in split()! [25/07/23] 
        # Yes, fuck [14/08/23]
        # NOTE Okay, we disable this handler before splitting processes, but we could also check that the pid of the event.inferior is not the one of the main debugger (would require to warn user that he can't detach main process) [08/07/24]
        # Under QEMU self.pid is the pid of the emulator while gdb calls the guest "process 1": the main process is the first inferior
        dbg = self.dbg
        if event.inferior.pid == dbg.pid or (not context.native and event.inferior.num == 1):
            if DEBUG: dbg.logger.debug("setting stop because process exited")
            # Set _closed before waking up the waiters: they check it to know that the process is gone
            self.closed.set()
            self.priority.deliver_all("process exited")
            dbg.ptrace.on_exit()
        else:
            if DEBUG: dbg.logger.debug("%s has been disconnected", event.inferior.pid)
            self.set_stop(f"inferior exited", exit=True)
    # This should only be used under the hood, but how do we let the other one to the user without generating problems ? [14/04/23]
    def priority_wait(self, comment: str = "?", priority: PriorityEvent | None = None, timeout: float | None = None) -> bool:
        dbg = self.dbg
        if not dbg.debugging:
            log.warn_once(DEBUG_OFF)
            return True

        if priority is None:
            unexpected(f"{comment} has nothing to wait for", log)
            return True
        finished = self.priority.wait(priority, comment, timeout=timeout)
        if dbg._backend.died:
            raise GdbDiedError(f"GDB died while waiting for {comment}")
        return finished
    def set_stop(self, comment: str = "", exit: bool = False) -> None:
        dbg = self.dbg
        pid = dbg._backend.stopped_pid()
        # We need a special case because when exiting self.instruction_pointer is not available  
        if not exit:
            if comment:
                if DEBUG: dbg.logger.debug("[%d] setting stopped in 0x%x for %s", pid, dbg.instruction_pointer, comment) # no reverse lookup ? [13/08/23]
            else:
                if DEBUG: dbg.logger.debug("[%d] setting stopped in 0x%x", pid, dbg.instruction_pointer)
        self.priority.pid = pid
        self.priority.deliver(comment)
    def enforce_stop(self, comment: str) -> None:
        """
        The process stopped for a reason no action asked for (a command typed in gdb).
        Nobody is woken up: the actions keep waiting for their own stop.
        """
        dbg = self.dbg
        self.priority.stopped_externally()
        if DEBUG: dbg.logger.debug("stopped for %s: nobody is woken up", comment)
    def syscall_restarts(self) -> bool:
        "The syscall the process just stepped over was stopped by a signal, and the kernel runs it again when the process resumes"
        dbg = self.dbg
        if self.closed.is_set():
            return False
        mask = 2**context.bits
        return dbg.return_value % mask in {-code % mask for code in _RESTART_SYSCALL}
    def interrupted_stop(self) -> None:
        """
        The SIGINT sent by _kick() stopped the process. Called by the stop handlers.
        If interrupt() suspended the actions running the process nobody is woken (see PriorityManager.absorb_interrupt),
        otherwise the stop goes to the action waiting for it, like any other stop.
        """
        dbg = self.dbg
        self.interrupted = False
        if self.priority.absorb_interrupt():
            if DEBUG: dbg.logger.debug("interrupted: the suspended actions keep waiting")
            return
        self.set_stop("interrupted")
