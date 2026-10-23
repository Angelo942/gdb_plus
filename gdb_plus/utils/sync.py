from __future__ import annotations
from collections import Counter
from contextlib import contextmanager
from threading import Condition, Event, Lock, RLock, current_thread, get_ident, local
from typing import TYPE_CHECKING
from time import monotonic
from pwn import log
from gdb_plus.utils.logger import DEBUG, _logger, unexpected
from inspect import signature
from functools import wraps

if TYPE_CHECKING:
    from threading import Thread
    from types import TracebackType
    from gdb_plus.gdb_plus import Debugger
    from typing import Callable, Iterator, ParamSpec
    P = ParamSpec("P")

# Returned by PriorityManager.auto_resume() when an interrupt() suspended the stop being handled
SUSPENDED = "suspended by interrupt()"

class Interrupted(Exception):
    """
    Raised in a thread of the script started before an interrupt() (the thread behind a c(wait=False)) when it tries to
    resume the process: interrupt() ended its action. The threads behind the blocking actions treat it as the end of the
    action (see set_done_if_panic: done.interrupted is set).
    """

class Suspended(RuntimeError):
    """
    Raised when the script tries to resume the process while interrupt() keeps an action of a callback suspended: its
    action would take the stops the suspended one waits for. Call resume() first.
    """

class PriorityEvent(Event):
    """
    One action waiting for the next stop of the process: a step, a continue, a jump...

    The action creates it through PriorityManager.begin_action() before sending the command that resumes the process,
    then waits on it. When the process stops, the PriorityManager removes it from its stack and sets it in a single
    step, so each event receives at most one stop.

    comment: what the action is, for the logs
    level: position in the stack when it was created, for the logs only
    seq: creation order, used to know if an event existed before a given stop (see HandlerContext.mark)
    layer: layer of the thread that created it (see PriorityManager)
    script: created by a thread of the script: interrupt() ends its action instead of suspending it
    kind: the command that resumes the process, "continue" or "step" (resume() repeats it if interrupt() stops it),
          "claim" for the stop claimed by an interrupt (see claim_if_running), "wait" if someone else resumes the process
    thread: the thread that created it
    reason: why it was set (the stop reason, "process exited"...)
    sleepers: threads of the debugger waiting on it, with their layer (see PriorityManager.blocked_on)
    """
    def __init__(self, comment: str, level: int, seq: int, layer: int, script: bool, kind: str) -> None:
        super().__init__()
        self.comment = comment
        self.level = level
        self.seq = seq
        self.layer = layer
        self.script = script
        self.kind = kind
        self.thread: Thread = current_thread()
        self.reason: str | None = None
        self.sleepers: dict[int, int] = {}

    def __repr__(self) -> str:
        return f"<PriorityEvent [{self.level}] {self.comment}>"

class HandlerContext:
    """
    The handling of one stop: the stop handler thread, the thread that runs the callbacks of the breakpoints,
    and the threads of the actions those callbacks start (a finish() inside a callback).

    It is opened by the thread that detects the stop, before the handler thread starts, and closed when the last
    handler thread using it ends. interrupt() waits until its threads are waiting (see PriorityManager._settled).

    mark: seq of the last PriorityEvent created before the stop. The stop can only belong to those events: the ones
          created later belong to actions of the callbacks.
    layer: layer of the action that was running the process before the stop. The callbacks act in that layer, so an
           interrupt() that suspends it suspends them too
    threads: handler threads still using the context
    stop_requested: a callback called interrupt(): the handler must not resume the process when the callbacks are done
    orphaned: the stop belonged to an action of the script that interrupt() ended. Nobody waits for it anymore, so the
              process stays stopped when the callbacks are done
    """
    def __init__(self, mark: int, layer: int, comment: str) -> None:
        self.mark = mark
        self.layer = layer
        self.comment = comment
        self.threads = 1
        self.stop_requested = False
        self.orphaned = False

    def __repr__(self) -> str:
        return f"<HandlerContext {self.comment} after {self.mark}>"

class Suspension:
    """
    What one interrupt() suspended, until resume() (see PriorityManager).

    pending: the command resume() sends to resume the process for the suspended layer ("continue" or "step"), or None if
             there is nothing to send: the process wasn't running for that layer, or a parked thread sends its own command
    saved: state of the Debugger that belongs to the suspended layer, set aside by suspend() and put back by resume()
    """
    def __init__(self) -> None:
        self.pending: str | None = None
        self.saved: dict[str, object] = {}

    def __repr__(self) -> str:
        return f"<Suspension pending={self.pending}>"

class ResumedEvent(Event):
    "Set once the thread of a task resumed the process for the first time, or when the task ended (see DoneEvent.wait_resumed)"
    def __init__(self) -> None:
        super().__init__()
        self.sleepers: dict[int, int] = {}

class PriorityManager:
    """
    Decides which thread receives each stop of the process, and what interrupt() does to the threads waiting for it.

    Several threads can wait for the process at the same time: the script, the thread behind a c(wait=False),
    a callback that runs finish() while the script waits in c()... Each action that resumes the process pushes a
    PriorityEvent on a stack before resuming it, and every stop is handed to the last event pushed (LIFO):
    the innermost action receives its stop first. A stop nobody waits for is dropped.

    Vocabulary:
    - action: something that resumes the process and waits for the next stop (step, continue, jump, signal)
    - auto-resume: the debugger resumes the process by itself after handling a stop (a callback returned False,
      a catchpoint, a handled signal). See auto_resume()
    - internal action: a step the stop handler needs to finish handling a stop, like the jump that skips a syscall.
      It is sent even while its layer is suspended
    - task: an action that runs in its own thread (c, continue_until, next, finish). It counts from the moment it is
      called until its thread ends (see DoneEvent)
    - running: the process is running according to us. It is set before the command that resumes the process is sent
      and cleared when the stop is detected, so that interrupt() can decide atomically whether it must send a SIGINT
    - thread of the script: the user's threads and the tasks they start (the thread behind a c(wait=False)). The other
      threads belong to the debugger: stop handlers, callbacks, the tasks they start, and call(). See _is_script()
    - layer: how many interrupt() were not resumed yet when something started. The threads of the script always act in
      the current layer, len(_suspensions), except the tasks, which act in the layer they were created in like the
      threads of the debugger. The layers below the current one are suspended.

    interrupt() (suspend()) stops the process with a SIGINT, then treats what is in progress in the current layer
    according to who started it:
    - the actions of the script end. Their events receive an "interrupted" stop, and a task of the script that tries to
      resume the process again gets Interrupted. A stop being handled that belonged to one of them is orphaned: when its
      callbacks are done the process stays stopped;
    - the actions of the threads of the debugger are suspended, and the callbacks don't know about it: their actions keep
      waiting for their stops (nobody receives the SIGINT), an action they start waits (parked) before sending its
      command, and the auto-resume of a stop they handle is postponed.
    If nothing is suspended, the interrupt leaves nothing behind. Otherwise resume() undoes it: it resends the command the
    SIGINT stopped, or the postponed auto-resume, or lets the parked action send its own command. Until then the script
    can't resume the process (Suspended): its actions would take the stops the suspended ones wait for.

    Every method takes the lock itself. The methods starting with an underscore expect the caller to hold it.
    """
    def __init__(self, pid: int = 0) -> None:
        self._cond = Condition(RLock())
        self._stack: list[PriorityEvent] = []
        self._seq = 0
        self._active: list[HandlerContext] = []
        self._local = local()
        self._suspensions: list[Suspension] = []
        # Per layer: threads of the debugger that are not waiting (see _settled), threads parked in begin_action, tasks
        self._awake: Counter[int] = Counter()
        self._parked: Counter[int] = Counter()
        self._tasks: Counter[int] = Counter()
        # Layer and kind of the last command that resumed the process
        self._run_layer = 0
        self._run_kind = "continue"
        self.pid = pid
        self.aborted: bool = False
        self.running: bool = False
        self.resumes: int = 0
        self.holder: Thread | None = None
        self.pending_stops: int = 0

    ########################## ACTIONS ##########################

    @property
    def priority(self) -> int:
        "Number of actions waiting for a stop, the suspended ones included"
        with self._cond:
            return len(self._stack)

    @property
    def suspended(self) -> int:
        "Number of interrupt() that resume() can undo"
        with self._cond:
            return len(self._suspensions)

    @property
    def tasks(self) -> int:
        "Number of tasks in progress, the suspended ones included"
        with self._cond:
            return sum(self._tasks.values())

    def _layer(self) -> int:
        "Layer of the current thread"
        layer = getattr(self._local, "layer", None)
        return len(self._suspensions) if layer is None else layer

    def _is_script(self) -> bool:
        "The current thread belongs to the script: it is not a stop handler or a callback, nor a task started by one or by call()"
        return getattr(self._local, "context", None) is None and not getattr(self._local, "own", False)

    def _push(self, comment: str, kind: str) -> PriorityEvent:
        """
        Create the event of a new action of the current thread and push it on the stack.
        Once gdb died the event is returned already set and is not pushed: nothing will ever stop the process again.
        """
        self._seq += 1
        event = PriorityEvent(comment, len(self._stack) + 1, self._seq, self._layer(), self._is_script(), kind)
        if DEBUG: _logger.info(f"[{self.pid}] raising priority [{event.level - 1}] -> [{event.level}] for {comment}")
        if self.aborted:
            self._hand(event, "aborted")
            return event
        self._stack.append(event)
        return event

    def _hand(self, event: PriorityEvent, reason: str) -> None:
        "Give event its stop and wake its thread. The caller has already removed it from the stack"
        event.reason = reason
        self._release(event)
        event.set()

    def _release(self, event: PriorityEvent | DoneEvent) -> None:
        "event is about to be set: the threads waiting on it count as awake again"
        for layer in event.sleepers.values():
            self._awake[layer] += 1
        event.sleepers.clear()

    def _resumed(self, kind: str, layer: int) -> None:
        "The process is about to run a command of this kind (\"continue\" or \"step\") for this layer"
        self.running = True
        self.resumes += 1
        self._run_layer = layer
        self._run_kind = kind
        self._cond.notify_all()

    def task_resumed(self) -> None:
        """
        Called once the command of an action has been sent: the task of the current thread, and the tasks waiting for it,
        have resumed the process (see DoneEvent.wait_resumed). Not earlier: an interrupt() that kicks the process before the
        command reached it would be lost with new_libdebug and with a remote gdb.
        """
        with self._cond:
            task = getattr(self._local, "task", None)
            while task is not None and not task.resumed.is_set():
                self._release(task.resumed)
                task.resumed.set()
                task = task.parent

    def _check_script(self, comment: str) -> None:
        "Refuse an action of a thread of the script while an interrupt() is in effect (see Interrupted and Suspended)"
        if not self._suspensions or self.aborted or not self._is_script():
            return
        if self._layer() < len(self._suspensions):
            raise Interrupted(f"{comment}: ended by interrupt()")
        raise Suspended(f"{comment}: interrupt() suspended an action of a callback. Call resume() first")

    def check_can_resume(self, comment: str) -> None:
        """
        Raise Suspended if the current thread is one of the script and interrupt() keeps an action of a callback suspended.
        For the actions that change the process before resuming it (breakpoints, registers): they check it first.
        """
        with self._cond:
            if self._suspensions and not self.aborted and self._is_script() and self._layer() >= len(self._suspensions):
                self._check_script(comment)

    def _park(self, layer: int) -> None:
        "Block the current thread while its layer is suspended. It counts as waiting meanwhile (see _settled)"
        if layer >= len(self._suspensions) or self.aborted:
            return
        if DEBUG: _logger.debug(f"[{self.pid}] parking an action of the suspended layer {layer}")
        self._parked[layer] += 1
        self._awake[layer] -= 1
        self._cond.notify_all()
        while layer < len(self._suspensions) and not self.aborted:
            self._cond.wait()
        self._parked[layer] -= 1
        self._awake[layer] += 1

    def raise_priority(self, comment: str | None) -> PriorityEvent:
        "Wait for the next stop without resuming the process: the user will resume it from gdb"
        with self._cond:
            return self._push(comment or "?", "wait")

    def begin_action(self, comment: str | None, *, resumes: bool = True, internal: bool = False, step: bool = False) -> PriorityEvent:
        """
        Called right before sending a command that resumes the process. The next stop is handed to the event returned.

        resumes: False if the command doesn't resume the process (we wait for the user to resume it from gdb)
        internal: a step the stop handler needs to finish handling the current stop (see the class docstring)
        step: the command executes a single instruction

        While an interrupt() is in effect a thread of the script is refused: Interrupted for a task started before it,
        Suspended otherwise. A thread of the debugger in a suspended layer blocks until resume() instead (with the event
        already on the stack), unless the action is internal. If the process exited meanwhile the event is returned
        already set. A resume from the script (not from a handler) also forgets the other breakpoints of the last stop
        (see expect_more_stops).
        """
        kind = ("step" if step else "continue") if resumes else "wait"
        with self._cond:
            if not internal:
                self._check_script(comment or "?")
            event = self._push(comment or "?", kind)
            if not internal:
                self._park(event.layer)
            if resumes and not self.aborted and not event.is_set():
                self._resumed(kind, event.layer)
                if getattr(self._local, "context", None) is None and not internal:
                    self.pending_stops = 0
            return event

    def claim_if_running(self, comment: str) -> PriorityEvent | None:
        """
        Push an event for the next stop, only if the process runs. Used to stop the process with a SIGINT without
        taking the stop of an action: the check and the push happen together with the detection of the stops.
        """
        with self._cond:
            if not self.running or self.aborted:
                return None
            return self._push(comment, "claim")

    def lower_priority(self, event: PriorityEvent, comment: str) -> bool:
        """
        Remove an event whose action gives up (a step that timed out).
        Returns True if it was still waiting, False if a stop had already been handed to it.
        """
        with self._cond:
            if event not in self._stack:
                return False
            if DEBUG: _logger.info(f"[{self.pid}] lowering priority {event} for {comment}")
            self._stack.remove(event)
            self._cond.notify_all()
            return True

    def cancel_action(self, event: PriorityEvent, comment: str) -> None:
        "The command that should have resumed the process failed: remove its event, the process didn't move"
        with self._cond:
            if self.lower_priority(event, comment):
                self.running = False
                self._cond.notify_all()

    @contextmanager
    def blocked_on(self, event: PriorityEvent | DoneEvent) -> Iterator[None]:
        """
        Wrap the wait of a thread of the debugger (stop handler, callback, task) on event: until event is set the thread
        counts as waiting for interrupt() (see _settled). The waits of the script's threads are not counted.
        """
        layer = getattr(self._local, "layer", None)
        ident = get_ident()
        with self._cond:
            if layer is not None and not event.is_set():
                event.sleepers[ident] = layer
                self._awake[layer] -= 1
                self._cond.notify_all()
        try:
            yield
        finally:
            with self._cond:
                # Still there if the wait timed out: whoever set the event has already counted the thread as awake
                if event.sleepers.pop(ident, None) is not None:
                    self._awake[layer] += 1

    def wait(self, event: PriorityEvent, comment: str = "", timeout: float | None = None) -> bool:
        "Wait for the stop of an action. False on timeout or if gdb died"
        if DEBUG: _logger.debug(f"[{self.pid}] waiting on {event} for {comment}")
        with self.blocked_on(event):
            finished = event.wait(timeout)
        if not finished:
            if DEBUG: _logger.warning(f"[{self.pid}] {comment} did not complete.")
            return False
        return not self.aborted

    ########################## STOPS ##########################

    def _target(self) -> PriorityEvent | None:
        """
        The event that receives a stop handled by the current thread: the last one pushed in its layer or above (a
        suspended event never receives the stops of the layers above it).
        Called from a handler thread, only the events created before the stop it handles are candidates:
        the ones created later belong to actions of its callbacks.
        """
        return self._target_of(getattr(self._local, "context", None), self._layer())

    def _target_of(self, context: HandlerContext | None, layer: int) -> PriorityEvent | None:
        "The event that receives the stop of context (see _target)"
        for event in reversed(self._stack):
            if event.layer >= layer and (context is None or event.seq <= context.mark):
                return event
        return None

    def deliver(self, reason: str) -> PriorityEvent | None:
        "The process stopped and will stay stopped: wake the action waiting for this stop. Returns its event, if any"
        with self._cond:
            self.running = False
            event = self._target()
            if event is None:
                if DEBUG: _logger.debug(f"[{self.pid}] nobody waits for the stop: {reason}")
            else:
                if DEBUG: _logger.debug(f"[{self.pid}] {reason} -> {event}")
                self._stack.remove(event)
                self._hand(event, reason)
            self._cond.notify_all()
            return event

    def deliver_all(self, reason: str) -> None:
        "The process is gone: wake every action, the suspended ones included. Nothing is left to resume"
        with self._cond:
            self.running = False
            for event in self._stack:
                self._hand(event, reason)
            self._stack.clear()
            self._suspensions.clear()
            self._cond.notify_all()

    def abort(self) -> None:
        "gdb died: wake every action, and let the actions started from now on return immediately"
        with self._cond:
            self.aborted = True
            self.deliver_all("aborted")

    def absorb_interrupt(self) -> bool:
        """
        Called by the stop handler when the SIGINT of an interrupt stopped the process. If the process was running for an
        action of the debugger in a suspended layer, nobody receives the stop: the action keeps waiting, and resume()
        repeats the command it stopped. Returns False if the stop must be delivered as usual: the layer isn't suspended,
        the action is the script's (it ends with this stop), nobody waits, or an interrupt claimed the stop (see
        claim_if_running).
        """
        with self._cond:
            self.running = False
            layer = self._layer()
            if layer >= len(self._suspensions):
                return False
            target = self._target()
            if target is None or target.script or target.kind == "claim":
                return False
            if DEBUG: _logger.debug(f"[{self.pid}] SIGINT absorbed: resume() will repeat {self._run_kind} for layer {layer}")
            self._suspensions[layer].pending = self._run_kind
            self._cond.notify_all()
            return True

    def resumed_externally(self) -> None:
        "gdb resumed the process without us (a command typed in gdb)"
        with self._cond:
            if not self.running:
                self._resumed("continue", self._layer())

    def stopped_externally(self) -> None:
        "The process stopped for a reason no action asked for (a command typed in gdb): the actions keep waiting"
        with self._cond:
            self.running = False
            self._cond.notify_all()

    def expect_more_stops(self, count: int) -> None:
        """
        Several breakpoints that stop the process are at the address of the current stop. The first stop is delivered now,
        the next `count` auto-resumes are turned into stops for the actions below it. Example: the script waits in c() and a
        callback waits in finish(), both for this address. The finish receives the stop, and when its callback returns False
        the process stays stopped and the c() receives the next one.
        """
        with self._cond:
            self.pending_stops = count

    ########################## HANDLERS ##########################

    def stop_detected(self, comment: str = "stop") -> HandlerContext:
        "Called by the thread that detects a stop, before it starts the handler thread. Returns the context to give it"
        with self._cond:
            self.running = False
            return self._open(comment)

    def open_context(self, comment: str) -> HandlerContext:
        "Open a context for an event that isn't a stop but has to be handled like one (the split of a forked child)"
        with self._cond:
            return self._open(comment)

    def _open(self, comment: str) -> HandlerContext:
        context = HandlerContext(self._seq, self._run_layer, comment)
        self._active.append(context)
        self._awake[context.layer] += 1
        self._cond.notify_all()
        return context

    def share(self, context: HandlerContext) -> None:
        "Count one more thread handling the same stop. Call it before starting that thread"
        with self._cond:
            context.threads += 1
            self._awake[context.layer] += 1

    def enter(self, context: HandlerContext) -> None:
        "The current thread starts handling the stop of context"
        self._local.context = context
        self._local.layer = context.layer

    def leave(self, context: HandlerContext) -> None:
        "The current thread is done with the stop of context. The context closes with its last thread"
        self._local.context = None
        self._local.layer = None
        with self._cond:
            context.threads -= 1
            self._awake[context.layer] -= 1
            if context.threads == 0:
                self._active.remove(context)
            self._cond.notify_all()

    def in_handler(self) -> bool:
        "The current thread handles a stop: a stop handler, a callback, or an action started by a callback"
        return getattr(self._local, "context", None) is not None

    def current_context(self) -> HandlerContext | None:
        return getattr(self._local, "context", None)

    def inherit(self, target: Callable[P, None], done: DoneEvent | None = None, *, own: bool = False) -> Callable[P, None]:
        """
        Wrap the target of the thread of a task. The thread acts in the layer of done, the DoneEvent of its task, and,
        started from a callback (a finish() inside a callback), belongs to the stop the callback handles.
        Without done the thread acts in the layer of the current thread, and counts as one of its threads until it ends.
        own: the task is an action of the debugger even if the script started it (call()): interrupt() suspends it like an
             action of a callback instead of ending it. The tasks it starts inherit this.
        """
        context = getattr(self._local, "context", None)
        own = own or getattr(self._local, "own", False)
        with self._cond:
            if done is not None:
                layer = done.layer
            else:
                layer = self._layer()
                self._awake[layer] += 1
        @wraps(target)
        def run(*args: P.args, **kwargs: P.kwargs) -> None:
            self._local.context = context
            self._local.layer = layer
            self._local.own = own
            self._local.task = done
            try:
                target(*args, **kwargs)
            finally:
                if done is None:
                    with self._cond:
                        self._awake[layer] -= 1
                        self._cond.notify_all()
        return run

    def request_stop(self) -> None:
        "interrupt() called from a callback: the process must stay stopped once the callbacks of this stop are done"
        context = getattr(self._local, "context", None)
        if context is not None:
            context.stop_requested = True

    def auto_resume(self) -> str | None:
        """
        Called before an auto-resume. Returns None if the process may resume (and counts it as running).
        Otherwise the process must stay stopped and the value says why:
        - SUSPENDED: an interrupt() suspended the action of the debugger this stop belongs to. Nobody is woken: resume()
          will resume the process
        - any other reason: the caller delivers a stop with that reason instead (to the action of the script that
          interrupt() ends, for "interrupted")
        """
        with self._cond:
            context = getattr(self._local, "context", None)
            if context is not None and context.stop_requested:
                context.stop_requested = False
                return "interrupted by a callback"
            if self.pending_stops > 0:
                self.pending_stops -= 1
                return "another breakpoint at this address stops"
            if self.aborted:
                return "aborted"
            if context is not None and context.orphaned:
                return "interrupted"
            layer = self._layer()
            if layer < len(self._suspensions):
                target = self._target()
                if target is None or target.script:
                    # The stop belongs to an action of the script (or to nobody): interrupt() ends it with this stop
                    return "interrupted"
                self._suspensions[layer].pending = "continue"
                self._cond.notify_all()
                return SUSPENDED
            self._resumed("continue", layer)
            return None

    ########################## INTERRUPT ##########################

    def hold(self) -> bool:
        "Start an interrupt() in the current thread. False if another thread is already interrupting"
        with self._cond:
            if self.holder is not None:
                return False
            self.holder = current_thread()
            return True

    def release(self) -> None:
        "End the interrupt() of the current thread"
        with self._cond:
            self.holder = None
            self._cond.notify_all()

    def _idle(self) -> bool:
        "The process is stopped and nothing of the current layer is in progress. The suspended layers don't count"
        layer = len(self._suspensions)
        return (not self.running
                and not any(event.layer >= layer for event in self._stack)
                and not any(context.layer >= layer for context in self._active)
                and not any(count for task_layer, count in self._tasks.items() if task_layer >= layer))

    def busy(self) -> bool:
        "The process runs, or an action, a stop handler or a task of the current layer is in progress"
        with self._cond:
            return not self._idle()

    def _settled(self, layer: int) -> bool:
        """
        Every thread of the debugger in this layer waits: for a stop, for a task, or parked until resume().
        A callback that is still running (or waits for something else, like input) keeps the layer unsettled.
        """
        if self._awake[layer] < 0:
            unexpected(f"[{self.pid}] {self._awake[layer]} threads awake in layer {layer}", log)
        return self._awake[layer] <= 0

    def suspend(self, kick: Callable[[], None], timeout: float | None = None, set_aside: Callable[[], dict[str, object]] | None = None) -> bool:
        """
        The body of interrupt(), called while holding the manager. Suspends the current layer, then loops:
        - while the process runs, call kick() (which sends the SIGINT), once for each time the process was resumed;
        - once it is stopped, wait until every thread of the debugger in the layer waits (see _settled). A callback still
          running is waited for;
        - end the actions of the script in the layer (_end_script) and wait again, for the threads they wake up.
        If nothing is left in the layer the suspension is dropped: there is nothing to resume. Otherwise set_aside()
        returns the state of the Debugger that belongs to the suspended layer and resets it: resume() gives it back.
        kick() is called without the lock, since it talks to gdb. Returns False on timeout or if gdb died.
        """
        deadline = None if timeout is None else monotonic() + timeout
        with self._cond:
            layer = len(self._suspensions)
            suspension = Suspension()
            self._suspensions.append(suspension)
            if DEBUG: _logger.info(f"[{self.pid}] suspending layer {layer}")
            self._cond.notify_all()
        kicked = None
        while True:
            with self._cond:
                if self.aborted:
                    return False
                must_kick = False
                if self.running:
                    if kicked != self.resumes:
                        kicked = self.resumes
                        must_kick = True
                elif layer >= len(self._suspensions):
                    # The process exited: deliver_all() dropped the suspension
                    return True
                elif self._settled(layer):
                    if self._end_script(layer):
                        continue
                    if self._empty(layer):
                        if DEBUG: _logger.info(f"[{self.pid}] nothing suspended in layer {layer}")
                        self._suspensions.remove(suspension)
                        self._cond.notify_all()
                    elif set_aside is not None:
                        suspension.saved = set_aside()
                    return True
                if not must_kick:
                    remaining = None if deadline is None else deadline - monotonic()
                    if remaining is not None and remaining <= 0:
                        if DEBUG: _logger.warning(f"[{self.pid}] interrupt gave up: {self._stack} {self._active} awake={self._awake[layer]} running={self.running}")
                        self._end_script(layer)
                        if set_aside is not None:
                            suspension.saved = set_aside()
                        return False
                    self._cond.wait(remaining)
                    continue
            kick()

    def _end_script(self, layer: int) -> bool:
        """
        End the actions of the script waiting in layer, innermost first: they receive an "interrupted" stop. The stops being
        handled that belonged to them are orphaned. Returns False if there was none.
        """
        ended = [event for event in reversed(self._stack) if event.layer == layer and event.script]
        if not ended:
            return False
        for context in self._active:
            if context.layer == layer and self._target_of(context, context.layer) in ended:
                context.orphaned = True
        for event in ended:
            if DEBUG: _logger.debug(f"[{self.pid}] interrupt ends {event}")
            self._stack.remove(event)
            self._hand(event, "interrupted")
        self._cond.notify_all()
        return True

    def _empty(self, layer: int) -> bool:
        "Nothing of layer is left: no event, no stop being handled, no task, no parked thread"
        return (not any(event.layer == layer for event in self._stack)
                and not any(context.layer == layer for context in self._active)
                and self._tasks[layer] == 0 and self._parked[layer] == 0)

    def resume(self, put_back: Callable[[dict[str, object]], None] | None = None) -> str | None:
        """
        Undo the last suspend(): its layer is the current one again and its parked thread goes on.
        put_back(saved) restores the state set aside by suspend(), before any thread of the layer can run.
        Returns the command the caller must send to resume the process for that layer ("continue" or "step"), already
        counted as running, or None if there is nothing to send: a parked thread sends its own command, the process
        wasn't running for that layer, or nothing was suspended. The caller checks first that the current layer is idle.
        """
        with self._cond:
            if not self._suspensions:
                return None
            suspension = self._suspensions.pop()
            layer = len(self._suspensions)
            if DEBUG: _logger.info(f"[{self.pid}] resuming layer {layer}: {suspension}, {self._parked[layer]} parked")
            if put_back is not None and suspension.saved:
                put_back(suspension.saved)
            self._cond.notify_all()
            if self._parked[layer] > 0 or suspension.pending is None or self.aborted:
                return None
            self._resumed(suspension.pending, layer)
            return suspension.pending

    def wait_idle(self, timeout: float | None = None) -> bool:
        "Wait until the process is stopped and nothing of the current layer is in progress. False on timeout or if gdb died"
        with self._cond:
            idle = self._cond.wait_for(lambda: self.aborted or self._idle(), timeout)
            return idle and not self.aborted

    ########################## TASKS ##########################

    def begin_task(self, done: DoneEvent) -> None:
        "The task of done starts, in the layer of the current thread and waited for by the task of the current thread, if any"
        with self._cond:
            done.layer = self._layer()
            done.parent = getattr(self._local, "task", None)
            self._tasks[done.layer] += 1
            self._awake[done.layer] += 1

    def end_task(self, done: DoneEvent) -> None:
        "The task of done ended. Called by done.set() right before setting it: the threads waiting on it count as awake"
        with self._cond:
            self._tasks[done.layer] -= 1
            self._awake[done.layer] -= 1
            self._release(done)
            self._release(done.resumed)
            self._cond.notify_all()

class MyLock:
    def __init__(self, event: Event, owner: Debugger) -> None:
        self.owner = owner
        self.event = event
        self.counter: int = 0
        # prevent bugs with the counter ? [12/06/23]
        self.__lock = Lock()
        # Block from ptrace (strict interrupt)
        # I'm not sure if it makes sense. Maybe in the interrupt strict after having removed the lock there.
        #self.can_run = Event()
        #self.can_run.set()


    def log(self, function_name: str) -> MyLock:
        if DEBUG: self.owner.logger.info(f"[{self.owner.pid}] wrapping {function_name}")
        return self

    def __enter__(self) -> None:
        if not self.owner.debugging:
            return
        #self.can_run.wait()
        with self.__lock:
            self.event.clear()
            self.counter += 1
            if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] entering lock with level {self.counter}")

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_traceback: TracebackType | None) -> None:
        if not self.owner.debugging:
            return
        with self.__lock:
            if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] exiting lock with level {self.counter}")
            self.counter -= 1
            # What about if we want to interrupt a continue until ? [21/06/23]
            if self.counter == 0:
                self.event.set()

class DoneEvent(Event):
    """
    Event set by the thread behind a blocking action (c, finish, continue_until...) when it ends.
    If the thread failed, wait() raises its exception in the thread that waits instead of blocking forever.

    manager: the PriorityManager of the debugger. The action then counts as a task of the layer of the current thread,
             from the creation of the event until it is set, so that wait() and interrupt() know about it even before its
             thread resumes the process. Give the event to PriorityManager.inherit() so that the thread acts in that layer.
    layer: that layer
    parent: the task whose thread created this one (the continue_until() of a finish()): it has resumed the process as soon
            as this one has
    interrupted: the action ended because of an interrupt() instead of reaching its goal
    resumed: set once the thread of the task resumed the process, or when the task ended (see wait_resumed)
    sleepers: threads of the debugger waiting on it, with their layer (see PriorityManager.blocked_on)
    """
    def __init__(self, manager: PriorityManager | None = None) -> None:
        super().__init__()
        self.error: BaseException | None = None
        self.interrupted: bool = False
        self.layer = 0
        self.parent: DoneEvent | None = None
        self.resumed = ResumedEvent()
        self.sleepers: dict[int, int] = {}
        self._manager = manager
        self._once = Lock()
        if manager is not None:
            manager.begin_task(self)
        else:
            self.resumed.set()

    def set(self) -> None:
        with self._once:
            if self._manager is not None and not self.is_set():
                self._manager.end_task(self)
            super().set()
            # After done itself: wait_resumed() then sees the error of a task that failed before resuming the process
            self.resumed.set()

    def wait_resumed(self) -> None:
        """
        Wait until the thread of the task resumed the process, or the task ended: the actions with wait=False return then.
        Raises the exception of a task that failed before resuming the process.
        """
        if self._manager is not None:
            with self._manager.blocked_on(self.resumed):
                self.resumed.wait()
        if self.is_set() and self.error is not None:
            raise self.error

    def wait(self, timeout: float | None = None) -> bool:
        if self._manager is None:
            finished = super().wait(timeout)
        else:
            with self._manager.blocked_on(self):
                finished = super().wait(timeout)
        if finished and self.error is not None:
            raise self.error
        return finished

def set_done_if_panic(func: Callable[P, None]) -> Callable[P, None]:
    """
    For the body of the thread behind a blocking action: `done` is set whatever happens, so the waiter wakes up,
    and an exception is handed to it (see DoneEvent) instead of being lost with the thread.
    Interrupted is not an error: the action ended because of interrupt(), and done.interrupted is set instead.
    The decorated function must have a parameter called `done`.
    """
    position = list(signature(func).parameters).index("done")
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
        done: DoneEvent = kwargs["done"] if "done" in kwargs else args[position]
        try:
            func(*args, **kwargs)
        except Interrupted:
            if done is not None:
                done.interrupted = True
        except Exception as e:
            if done is not None:
                done.error = e
        finally:
            if done is not None:
                done.set()
    return wrapper
