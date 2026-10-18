"""
MyEvent and MyLock are what lets an action inside a callback (finish() in a breakpoint handler...)
wait for its own stop without waking the script that is waiting for the outer action.
"""
import logging
import threading
import time

from gdb_plus.utils.sync import MyEvent, MyLock


def _waiter(event, priority, results, name):
    thread = threading.Thread(target=lambda: results.append((name, event.priority_wait(name, priority))), daemon=True)
    thread.start()
    return thread


def test_wait_returns_when_set_and_lowers_priority():
    """MyEvent.priority_wait() returns once the event is set and lowers the priority back to 0."""
    event = MyEvent()
    event.raise_priority("action")
    event.clear("action")
    results = []
    thread = _waiter(event, 1, results, "action")
    time.sleep(0.05)
    assert results == []
    event.set()
    thread.join(1)
    assert results == [("action", True)]
    assert event.priority == 0


def test_nested_waits_are_released_one_stop_at_a_time():
    """
    With an outer wait (the script's c()) and an inner one (finish() in a callback), each stop releases only the waiter
    of the current priority, innermost first.
    """
    event = MyEvent()
    event.clear("start")
    results = []

    event.raise_priority("outer")  # the script: dbg.c()
    outer = _waiter(event, 1, results, "outer")
    time.sleep(0.05)
    event.raise_priority("inner")  # a callback: dbg.finish()
    inner = _waiter(event, 2, results, "inner")
    time.sleep(0.05)

    event.set()  # the stop the finish() was waiting for
    inner.join(1)
    time.sleep(0.05)
    assert results == [("inner", True)]
    assert outer.is_alive(), "the outer action woke up on the stop of the inner one"
    assert event.priority == 1

    event.clear("callback continues")
    event.set()  # the stop the continue was waiting for
    outer.join(1)
    assert results == [("inner", True), ("outer", True)]
    assert event.priority == 0


def test_timeout_keeps_the_priority():
    """A priority_wait() that times out returns False and keeps its priority (the action is still running)."""
    event = MyEvent()
    event.clear("start")
    event.raise_priority("step")
    assert event.priority_wait("step", 1, timeout=0.05) is False
    assert event.priority == 1


def test_negative_priority_only_warns():
    """Lowering the priority below 0 warns instead of raising."""
    event = MyEvent()
    event.lower_priority("too much")
    assert event.priority == -1


def test_enforce_stop_is_reset_at_priority_zero():
    """The enforce_stop flag survives while nested actions end and is reset when the priority is back to 0."""
    event = MyEvent()
    event.raise_priority("a")
    event.raise_priority("b")
    event.flag_enforce_stop = 1
    assert event.enforce_stop
    event.lower_priority("b")
    assert event.enforce_stop
    event.lower_priority("a")
    assert event.flag_enforce_stop is None
    assert not event.enforce_stop


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
