"""
PriorityManager decides which thread receives each stop of the process (LIFO) and what interrupt() does to them, and MyLock guards the ptrace sections.
"""
import logging
import queue
import threading
import time

import pytest

from gdb_plus.utils.sync import PriorityManager, DoneEvent, Interrupted, MyLock, Suspended, set_done_if_panic


def _in_thread(function, *args):
    results = []
    thread = threading.Thread(target=lambda: results.append(function(*args)), daemon=True)
    thread.start()
    return thread, results


def _stop(manager, reason="stop"):
    "What a stop handler does: detect the stop, deliver it, end the handling"
    context = manager.stop_detected()
    manager.enter(context)
    try:
        return manager.deliver(reason)
    finally:
        manager.leave(context)


def _in_context(manager, context, function):
    "Run function in a thread of the debugger that handles the stop of context (a callback)"
    manager.enter(context)
    try:
        return function()
    finally:
        manager.leave(context)


def _sigint(manager, absorbed=None):
    """
    What kick() leads to: a moment later the process stops for the SIGINT, and the stop handler hands it to
    absorb_interrupt(), then delivers it if it wasn't absorbed (Debugger.__interrupted_stop)
    """
    def stop():
        context = manager.stop_detected("SIGINT")
        manager.enter(context)
        try:
            result = manager.absorb_interrupt()
            if absorbed is not None:
                absorbed.append(result)
            if not result:
                manager.deliver("interrupted")
        finally:
            manager.leave(context)
    threading.Timer(0.05, stop).start()


def _start_task(manager):
    "What c(wait=False) does: a task whose thread resumes the process and waits for the stop of its continue"
    done = DoneEvent(manager)
    events = queue.Queue()
    def body(done):
        event = manager.begin_action("continue")
        events.put(event)
        manager.wait(event)
        done.set()
    threading.Thread(target=manager.inherit(body, done), args=(done,), daemon=True).start()
    return done, events.get(timeout=1)


def _interrupt_a_callback_in_an_action(manager, after_finish=None):
    """
    The script waits in c() (its event `script`) and the callback of the stop it reached starts a finish() after
    interrupt(): the finish is parked. Returns the event of the script, the context of the stop, the thread of the callback
    and the list where the callback puts the event of its finish once it is let go. With after_finish the callback then
    waits for the stop of its finish and adds the result of after_finish() to the list.
    """
    script = manager.begin_action("continue")
    context = manager.stop_detected()
    manager.hold()
    suspender, settled = _in_thread(manager.suspend, lambda: None, 2)
    assert _eventually(lambda: manager.suspended == 1)
    results = []
    def callback():
        event = manager.begin_action("finish")
        results.append(event)
        if after_finish is not None:
            manager.wait(event)
            results.append(after_finish())
    thread, _ = _in_thread(_in_context, manager, context, callback)
    suspender.join(2)
    manager.release()
    assert settled == [True]
    return script, context, thread, results


def _eventually(condition, timeout=1):
    "Poll condition until it is true: for the state another thread of the test reaches"
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


def test_a_stop_goes_to_the_last_action_and_removes_it():
    """The stop is handed to the event pushed last, which leaves the stack at once: the next stop goes to the one below."""
    manager = PriorityManager()
    outer = manager.begin_action("continue")
    inner = manager.begin_action("finish")
    assert manager.priority == 2
    assert _stop(manager) is inner
    assert inner.is_set() and not outer.is_set()
    assert manager.priority == 1
    assert _stop(manager) is outer
    assert manager.priority == 0


def test_a_stop_set_before_the_wait_is_not_lost():
    """The event is set even if its thread isn't waiting yet: the wait returns at once."""
    manager = PriorityManager()
    event = manager.begin_action("step")
    _stop(manager)
    assert manager.wait(event, "step", timeout=0.1)


def test_a_raise_after_the_stop_does_not_steal_it():
    """
    The continue's stop arrives before its thread wakes up, then an interrupt tries to claim the next stop: the process is
    already stopped so it claims nothing, and the continue still receives its own stop.
    """
    manager = PriorityManager()
    continue_ = manager.begin_action("continue")
    _stop(manager)
    interrupt = manager.claim_if_running("interrupt")
    assert interrupt is None # The process is stopped: nothing to claim
    assert manager.wait(continue_, timeout=0.1)
    assert manager.priority == 0


def test_a_stale_stop_never_wakes_a_new_action():
    """A stop nobody waits for is dropped, it doesn't wake the next action."""
    manager = PriorityManager()
    _stop(manager)
    event = manager.begin_action("step")
    assert not manager.wait(event, timeout=0.05)


def test_a_handler_delivers_to_the_actions_older_than_its_stop():
    """A callback's own action (pushed after the stop) never receives the stop of the callback's handler."""
    manager = PriorityManager()
    script = manager.begin_action("continue")
    context = manager.stop_detected() # breakpoint with a callback
    manager.enter(context)
    callback_action = manager.begin_action("finish") # the callback runs finish()
    assert manager.deliver("callback returned True") is script
    assert not callback_action.is_set()
    manager.leave(context)


def test_timeout_keeps_the_event_until_lowered():
    """A wait that times out keeps its event (the action is still running) until the caller gives up on it."""
    manager = PriorityManager()
    event = manager.begin_action("step")
    assert manager.wait(event, timeout=0.05) is False
    assert manager.priority == 1
    assert manager.lower_priority(event, "step interrupted") is True
    assert manager.lower_priority(event, "again") is False
    assert manager.priority == 0


def test_abort_wakes_everyone_and_the_next_actions():
    """When gdb dies every waiter wakes up, and actions started afterwards don't wait."""
    manager = PriorityManager()
    event = manager.begin_action("continue")
    thread, results = _in_thread(manager.wait, event)
    manager.abort()
    thread.join(1)
    assert results == [False]
    assert manager.wait(manager.begin_action("step"), timeout=1) is False


def test_extra_breakpoints_turn_the_next_auto_resume_into_a_stop():
    """Two breakpoints stop at the same address: the second stop goes to the action below when the first woken one tries to resume."""
    manager = PriorityManager()
    script = manager.begin_action("continue")
    manager.expect_more_stops(1)
    assert manager.auto_resume() is not None
    assert manager.auto_resume() is None


def test_suspend_ends_the_actions_of_the_script():
    """interrupt() of a stopped process with two actions of the script waiting: both receive an "interrupted" stop, the inner one first, and nothing is left to resume."""
    manager = PriorityManager()
    outer = manager.begin_action("continue")
    inner = manager.begin_action("finish")
    manager.stopped_externally()
    order = []
    for event in (outer, inner):
        original = event.set
        event.set = lambda original=original, event=event: (order.append(event.comment), original())
    manager.hold()
    assert manager.suspend(kick=lambda: None, timeout=1)
    manager.release()
    assert order == ["finish", "continue"]
    assert outer.reason == inner.reason == "interrupted"
    assert manager.priority == 0 and manager.suspended == 0


def test_the_sigint_that_stops_an_action_of_the_script_is_delivered_to_it():
    """A c(wait=False) runs: suspend() kicks the process once, and the stop of the SIGINT goes to the continue, which ends."""
    manager = PriorityManager()
    done, event = _start_task(manager)
    kicks, absorbed = [], []
    def kick():
        kicks.append(1)
        _sigint(manager, absorbed)
    manager.hold()
    assert manager.suspend(kick, timeout=2)
    manager.release()
    assert kicks == [1] and absorbed == [False]
    assert event.reason == "interrupted"
    assert done.wait(1)
    assert manager.priority == 0 and manager.suspended == 0 and not manager.running


def test_the_sigint_that_stops_an_action_of_a_callback_is_absorbed():
    """
    The callback of the stop the script's continue reached runs finish(), and the process runs for it when interrupt()
    comes: nobody receives the SIGINT, the finish keeps waiting and resume() returns its continue. The script's continue
    ends and the stop of the callback is orphaned.
    """
    manager = PriorityManager()
    script = manager.begin_action("continue")
    context = manager.stop_detected()
    finish = queue.Queue()
    def callback():
        event = manager.begin_action("finish")
        finish.put(event)
        manager.wait(event)
    _in_thread(_in_context, manager, context, callback)
    event = finish.get(timeout=1)
    absorbed = []
    manager.hold()
    assert manager.suspend(lambda: _sigint(manager, absorbed), timeout=2)
    manager.release()
    assert absorbed == [True]
    assert not event.is_set()
    assert script.reason == "interrupted" and context.orphaned
    assert manager.priority == 1 and manager.suspended == 1
    assert manager.resume() == "continue"


def test_resume_repeats_a_step_of_a_callback_stopped_by_the_interrupt():
    """A step of a callback blocked in a syscall is stopped by the SIGINT: resume() returns "step", so that the step reaches its own stop."""
    manager = PriorityManager()
    manager.begin_action("continue")
    context = manager.stop_detected()
    steps = queue.Queue()
    def callback():
        event = manager.begin_action("step", step=True)
        steps.put(event)
        manager.wait(event)
    _in_thread(_in_context, manager, context, callback)
    event = steps.get(timeout=1)
    manager.hold()
    assert manager.suspend(lambda: _sigint(manager), timeout=2)
    manager.release()
    assert not event.is_set()
    assert manager.resume() == "step"


def test_a_task_of_the_debugger_started_by_the_script_is_suspended():
    """The thread of a call() belongs to the debugger although the script started it: interrupt() suspends its continue instead of ending it."""
    manager = PriorityManager()
    done = DoneEvent(manager)
    events = queue.Queue()
    def body(done):
        event = manager.begin_action("continue")
        events.put(event)
        manager.wait(event)
        done.set()
    threading.Thread(target=manager.inherit(body, done, own=True), args=(done,), daemon=True).start()
    event = events.get(timeout=1)
    absorbed = []
    manager.hold()
    assert manager.suspend(lambda: _sigint(manager, absorbed), timeout=2)
    manager.release()
    assert absorbed == [True]
    assert not event.is_set() and not done.is_set()
    assert manager.suspended == 1
    assert manager.resume() == "continue"


def test_a_claimed_sigint_is_delivered_to_its_claim():
    """The SIGINT of split() or step(timeout=) is claimed (claim_if_running): the stop handler delivers it as usual."""
    manager = PriorityManager()
    manager.begin_action("continue")
    claim = manager.claim_if_running("interrupt")
    context = manager.stop_detected("SIGINT")
    manager.enter(context)
    try:
        assert not manager.absorb_interrupt()
        assert manager.deliver("interrupted") is claim
    finally:
        manager.leave(context)


def test_a_callback_that_returns_false_during_the_interrupt_ends_the_continue():
    """
    interrupt() while a callback runs: suspend() waits for it. When the callback returns False its auto-resume becomes the
    "interrupted" stop of the script's continue, and nothing is left to resume.
    """
    manager = PriorityManager()
    script = manager.begin_action("continue")
    context = manager.stop_detected() # breakpoint with a callback
    manager.hold()
    suspender, settled = _in_thread(manager.suspend, lambda: None, 2)
    assert _eventually(lambda: manager.suspended == 1)
    assert suspender.is_alive()
    manager.enter(context)
    reason = manager.auto_resume()
    assert reason == "interrupted"
    assert manager.deliver(reason) is script
    manager.leave(context)
    suspender.join(2)
    manager.release()
    assert settled == [True]
    assert manager.priority == 0 and manager.suspended == 0 and not manager.running
    assert manager.resume() is None


def test_an_action_of_a_suspended_callback_waits_for_resume():
    """
    A callback that starts an action (a finish()) after interrupt() is parked before its command is sent: suspend() counts
    it as waiting and ends the script's continue, the finish stays on the stack, and resume() lets it send its command.
    """
    manager = PriorityManager()
    script, context, callback, results = _interrupt_a_callback_in_an_action(manager)
    assert script.reason == "interrupted" and context.orphaned
    assert callback.is_alive() and not manager.running
    assert manager.priority == 1 and manager.suspended == 1
    assert manager.resume() is None # nothing to send: the parked action sends its command itself
    callback.join(1)
    assert len(results) == 1 and manager.running


def test_an_orphaned_callback_leaves_the_process_stopped():
    """After resume() the finish of the suspended callback receives its stop, and when the callback returns False the process stays stopped: the script's continue is over."""
    manager = PriorityManager()
    script, context, callback, results = _interrupt_a_callback_in_an_action(manager, after_finish=manager.auto_resume)
    manager.resume()
    assert _eventually(lambda: len(results) == 1)
    assert _stop(manager) is results[0]
    callback.join(1)
    assert results[1] == "interrupted"
    assert not manager.running


def test_the_script_cannot_resume_the_process_while_a_callback_is_suspended():
    """While an action of a callback is suspended an action of the script raises Suspended (its stops would go to it); after resume() it is allowed again."""
    manager = PriorityManager()
    script, context, callback, results = _interrupt_a_callback_in_an_action(manager)
    with pytest.raises(Suspended):
        manager.begin_action("step", step=True)
    with pytest.raises(Suspended):
        manager.check_can_resume("call")
    assert manager.priority == 1
    manager.resume()
    callback.join(1)
    manager.check_can_resume("call")


def test_internal_actions_of_a_suspended_stop_are_sent():
    """The steps a stop handler needs to finish handling a stop (skip a syscall) are not parked by interrupt()."""
    manager = PriorityManager()
    script = manager.begin_action("continue")
    context = manager.stop_detected() # syscall catchpoint
    manager.hold()
    suspender, settled = _in_thread(manager.suspend, lambda: None, 2)
    assert _eventually(lambda: manager.suspended == 1)
    handler, jumps = _in_thread(_in_context, manager, context, lambda: manager.begin_action("jump", internal=True))
    handler.join(1)
    assert len(jumps) == 1 and manager.running
    jump = manager.stop_detected() # the jump stops on its own
    manager.enter(jump)
    assert manager.deliver("jump") is jumps[0]
    manager.leave(jump)
    suspender.join(2)
    manager.release()
    assert settled == [True]
    assert script.reason == "interrupted" and manager.suspended == 0


def test_a_task_of_the_script_that_has_not_resumed_the_process_yet_ends():
    """c(wait=False) whose thread hasn't resumed the process when interrupt() comes: its first action raises Interrupted, done.interrupted is set and nothing is left to resume."""
    manager = PriorityManager()
    done = DoneEvent(manager)
    manager.hold()
    suspender, settled = _in_thread(manager.suspend, lambda: None, 2)
    assert _eventually(lambda: manager.suspended == 1)
    assert suspender.is_alive()
    @set_done_if_panic
    def body(done):
        manager.begin_action("continue")
    threading.Thread(target=manager.inherit(body, done), args=(done,), daemon=True).start()
    suspender.join(2)
    manager.release()
    assert settled == [True]
    assert done.is_set() and done.interrupted
    assert not manager.running and manager.priority == 0 and manager.suspended == 0


def test_wait_idle_ignores_the_suspended_actions():
    """While an action of a callback is suspended wait_idle() (dbg.wait()) doesn't wait for it; after resume() it does."""
    manager = PriorityManager()
    script, context, callback, results = _interrupt_a_callback_in_an_action(manager)
    assert manager.wait_idle(timeout=0.05)
    manager.resume()
    callback.join(1)
    assert not manager.wait_idle(timeout=0.05)


def test_the_exit_of_the_process_ends_the_suspension():
    """The process exits while a callback is parked: every action wakes with the exit, and nothing is left to resume."""
    manager = PriorityManager()
    script, context, callback, results = _interrupt_a_callback_in_an_action(manager)
    manager.deliver_all("process exited")
    callback.join(1)
    assert results[0].reason == "process exited" and script.reason == "interrupted"
    assert manager.suspended == 0 and not manager.running
    assert manager.resume() is None


def test_wait_resumed_returns_once_the_task_resumed_the_process():
    """c(wait=False) returns when its thread has resumed the process (DoneEvent.wait_resumed), not before."""
    manager = PriorityManager()
    done = DoneEvent(manager)
    go = threading.Event()
    def body(done):
        go.wait()
        event = manager.begin_action("continue")
        manager.task_resumed() # what execute_action() does once the command is sent
        manager.wait(event)
        done.set()
    threading.Thread(target=manager.inherit(body, done), args=(done,), daemon=True).start()
    waiter, _ = _in_thread(done.wait_resumed)
    waiter.join(0.1)
    assert waiter.is_alive()
    go.set()
    waiter.join(1)
    assert not waiter.is_alive()
    assert manager.running and not done.is_set()
    _stop(manager)
    assert done.wait(1)


def test_a_task_has_resumed_the_process_once_the_task_it_waits_for_has():
    """until(wait=False) waits for the continue it starts in its own thread: it has resumed the process as soon as that continue has."""
    manager = PriorityManager()
    outer = DoneEvent(manager)
    def inner_body(done):
        manager.begin_action("continue")
        manager.task_resumed()
    def outer_body(done):
        inner = DoneEvent(manager)
        threading.Thread(target=manager.inherit(inner_body, inner), args=(inner,), daemon=True).start()
    threading.Thread(target=manager.inherit(outer_body, outer), args=(outer,), daemon=True).start()
    waiter, _ = _in_thread(outer.wait_resumed)
    waiter.join(1)
    assert not waiter.is_alive()
    assert manager.running and not outer.is_set()


def test_wait_resumed_raises_the_error_of_a_task_that_failed_before_resuming():
    """A task that fails before resuming the process: c(wait=False) raises its exception at once (DoneEvent.wait_resumed)."""
    manager = PriorityManager()
    done = DoneEvent(manager)
    @set_done_if_panic
    def body(done):
        raise ValueError("test")
    thread = threading.Thread(target=manager.inherit(body, done), args=(done,), daemon=True)
    thread.start()
    thread.join(1)
    with pytest.raises(ValueError):
        done.wait_resumed()


def test_a_task_in_flight_is_waited_for():
    """c(wait=False) counts from the call: wait_idle() and suspend() wait for its thread even before it resumes the process."""
    manager = PriorityManager()
    done = DoneEvent(manager)
    assert manager.busy()
    assert not manager.wait_idle(timeout=0.05)
    done.set()
    done.set()
    assert manager.tasks == 0
    assert manager.wait_idle(timeout=0.05)


def test_interrupted_is_not_an_error_for_a_blocking_action():
    """set_done_if_panic(): an action ended by interrupt() sets done.interrupted instead of handing an exception to the waiter."""
    @set_done_if_panic
    def body(done):
        raise Interrupted("test")
    done = DoneEvent()
    body(done)
    assert done.wait(1) and done.interrupted


def test_an_exception_of_a_blocking_action_reaches_the_waiter():
    """set_done_if_panic(): the exception of the thread behind an action is raised by done.wait() instead of being lost."""
    @set_done_if_panic
    def body(done):
        raise ValueError("test")
    done = DoneEvent()
    body(done)
    with pytest.raises(ValueError):
        done.wait(1)


class _Owner:
    debugging = True
    pid = 1
    logger = logging.getLogger("test")


def test_lock_clears_the_event_until_the_outermost_exit():
    """
    MyLock is re-entrant: the event is cleared on the first enter and set again only when the outermost section exits.
    """
    event = threading.Event()
    event.set()
    lock = MyLock(event, owner=_Owner())
    with lock.log("outer"):
        assert not event.is_set()
        with lock.log("inner"):
            assert lock.counter == 2
        assert not event.is_set()
    assert lock.counter == 0
    assert event.is_set()


def test_lock_does_nothing_when_not_debugging():
    """With debugging=False MyLock doesn't touch the event."""
    class Off(_Owner):
        debugging = False
    event = threading.Event()
    event.set()
    with MyLock(event, owner=Off()):
        assert event.is_set()
