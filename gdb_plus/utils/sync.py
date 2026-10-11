from threading import Event, Lock
from time import sleep
from pwn import log
from gdb_plus.utils.logger import DEBUG, _logger

# Warning. Calling wait() before clear() returns immediately!
# TODO add a counter on when to stop treating return False as continues
class MyEvent(Event):
    def __init__(self):
        super().__init__()
        self.cleared = Event()
        #self.secret = Event()
        self.priority = 0
        self.pid = 0 # here to handle multiple processes under the same debugger.
        self.flag_enforce_stop = None

    # I still need a standard wait for actions not initiated by dbg.cont and dbg.next
    # There seems to be a rare bug where multiple priorities are cleared at the same time [11/06/23]
    # If timeout is met we don't want to lower the priority
    def priority_wait(self, comment = "", priority=None, *, timeout=None):
        if priority is None:
            priority = self.priority
        if DEBUG: _logger.debug(f"[{self.pid}] waiting with priority {priority} for {comment}")
        while True:
            # Unfortunately you can not use the number of threads waiting to find the max priority [18/06/23]
            finished = super().wait(timeout)
            if DEBUG: _logger.debug(f"wait [{priority}] finished" + ("" if finished else " for timeout"))
            if priority == self.priority:
                if finished:
                    if DEBUG: _logger.debug(f"[{self.pid}] met priority {priority} for {comment}")
                    # Prevent race conditions. Make sure all threads know the current priority before anyone calls lower_priority
                    sleep(0.001)
                    self.lower_priority(comment)
                    # why does it work ?
                    #super().clear()
                else:
                    if DEBUG: _logger.warning(f"[{self.pid}] {comment} did not complete.")
                break
            # If I call wait again while the event is set it won't block ! [04/04/23]
            self.cleared.wait()
            # I forgot to clear it somewhere... [22/05/23]
            # Wait, what happens if we have 3 threads waiting ??
            self.cleared.clear()
        return finished

    # I move the priority -= 1 in here to avoid a race condition on the check priority == self.priority. I hope it won't break because I missed a clear somewhere, but with the cleared.wait; cleared.clear it should already break anyway [13/06/23]
    def clear(self, comment):
        #self.secret.clear()
        if self.is_set():
            super().clear()
            self.cleared.set()

    #def hidden_clear(self):
    #    if self.is_set():
    #        super().clear()
    #        self.cleared.set()

    def raise_priority(self, comment):
        if DEBUG: _logger.info(f"[{self.pid}] raising priority [{self.priority}] -> [{self.priority + 1}] for {comment}")
        self.priority += 1

    def lower_priority(self, comment):
        if DEBUG: _logger.info(f"[{self.pid}] lowering priority [{self.priority - 1}] <- [{self.priority}] for {comment}")
        self.priority -= 1
        if self.priority < 0:
            log.warn(f"I think there is something wrong with the wait! We reached priority {self.priority}")
        if self.priority == 0:
            # Should reset when reaching 0, but also when debugging manually ? [18/06/23]
            if DEBUG: _logger.debug("reset enforce stop")
            self.flag_enforce_stop = None

    # If we enforce a stop on level 5 through a breakpoint, a return False on level 7 should still continue, but not on level 3
    # If we enforce a stop because we are using gdb manually, a return False on level 7 should stop because we don't want to loose control, but not on level 3
    # Wait, I'm not convinced...
    @property
    def enforce_stop(self):
        if self.flag_enforce_stop is None:
            return False
        else:
            if DEBUG: _logger.debug(f"priority is {self.priority}. Enforce is {self.flag_enforce_stop}")
            return self.priority >= self.flag_enforce_stop

class MyLock:
    def __init__(self, event, owner):
        self.owner = owner
        self.event = event
        self.counter = 0
        # prevent bugs with the counter ? [12/06/23]
        self.__lock = Lock()
        # Block from ptrace (strict interrupt)
        # I'm not sure if it makes sense. Maybe in the interrupt strict after having removed the lock there.
        #self.can_run = Event()
        #self.can_run.set()


    def log(self, function_name):
        if DEBUG: self.owner.logger.info(f"[{self.owner.pid}] wrapping {function_name}")
        return self

    def __enter__(self):
        if not self.owner.debugging:
            return
        #self.can_run.wait()
        with self.__lock:
            self.event.clear()
            self.counter += 1
            if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] entering lock with level {self.counter}")

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not self.owner.debugging:
            return
        with self.__lock:
            if DEBUG: self.owner.logger.debug(f"[{self.owner.pid}] exiting lock with level {self.counter}")
            self.counter -= 1
            # What about if we want to interrupt a continue until ? [21/06/23]
            if self.counter == 0:
                self.event.set()
