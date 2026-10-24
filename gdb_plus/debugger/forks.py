from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log, sleep

from gdb_plus.utils import DEBUG
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, IMPORTANT_DEBUG_OFF, NEEDS_LOCAL_PROCESS, context_decorator, _logger

if TYPE_CHECKING:
    from gdb import Inferior
    from gdb_plus.debugger.debugger import Debugger

class ForksMixin(DebuggerBase):
    """
    Several processes in one session: gdb inferiors, one Debugger per child when the process forks
    (set_split_on_fork, wait_split, children), and _process_group, every process of the session by pid.
    """
    # Return old_inferior to know where to go back
    def switch_inferior(self, n: int) -> Inferior | None:
        """
        For multi-process applications change the process you are working with in gdb. 
        Try to avoid it and instead split each process in a different Debugger.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self._backend.clear_register_cache()
        # May not be accurate if you switched manually before
        old_inferior = self.current_inferior
        while self.current_inferior.num != n:
            if DEBUG: self.logger.debug("switching to inferior %d", n)
            self.execute(f"inferior {n}")
            inferior = self.current_inferior
            if DEBUG: self.logger.debug("I'm inferior %d, [pid: %d]", inferior.num, inferior.pid)
            sleep(0.1)
        pid = self.current_inferior.pid
        if pid not in (None, 1, 42000): # The gdbstub of qemu reports a fake pid: keep the one of the emulator
            self.pid = pid
        return old_inferior

    @property
    def inferiors(self) -> dict[int, Inferior]:
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return {}
        return {inferior.num: inferior for inferior in self.gdb.inferiors()}

        #return (None,) + self.gdb.inferiors()

    def inferior_from_pid(self, pid: int) -> Inferior | None:
        for inferior in self.inferiors.values():
            if inferior.pid == pid:
                return inferior
        self.logger.warning(f"can't find inferior for pid {pid}")
        return None

    # TODO if possible allow for an optimisation "single inferior" or something similar where we never waste time calling the inferior [08/10/24]
    @property
    def current_inferior(self) -> Inferior | None:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if self.gdb is not None:
            return self.gdb.selected_inferior()

        #elif self.libdebug is not None:
        #   return ... 

    inferior = current_inferior

    #def wait_fork(self):
    #    self.gdb.forked.wait()
    #    self.gdb.forked.clear()

    def wait_split(self) -> int:
        """
        Wait for the process to fork
        set_split_on_fork() must be set before the call to fork

        Return:
            pid: pid of the child process

        Example:
            dbg.set_split_on_fork()
            dbg.c(wait=False)
            pid_child = dbg.wait_split()
            child = dbg.children[pid_child]
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        if self.new_libdebug is not None:
            raise NotImplementedError("new_libdebug doesn't support waiting for a fork!")

        pid = self.split.get()
        if pid == 0:
            raise Exception("What the fuck happened with split ???")
        return pid

    # TODO find a better name [28/02/23]
    # TODO make inferior and n the same parameter ? [04/03/23]

    # Call shellcode has problems: https://sourceware.org/gdb/onlinedocs/gdb/Registers.html. Can't push rip
    # Warn that the child will still be in the middle of the fork [26/04/23]
    # TODO support split for libdebug [02/06/23] (Will require a new patch to libdebug)
    # I thought about setting emulate_ptrace for the child if it is set in the parent, but I want to let the user free of choosing the parameters they wants [23/07/23]
    @context_decorator
    def _split_child(self, *, pid: int | None = None, inferior: Inferior | None = None, n: int | None = None, script: str = "") -> Debugger:
        if not self.local_debugging:
            log.error(NEEDS_LOCAL_PROCESS.format("Splitting a child (a new gdb attached to its pid)"))
        if inferior is None:
            for inf_n, inferior in self.inferiors.items():
                if (pid is not None and inferior.pid == pid) or (n is not None and inf_n == n):
                    break
            else:
                if pid is not None:
                    raise Exception(f"No inferior with pid {pid}")
                elif n is not None:
                    raise Exception(f"No inferior {n}")
                else:
                    # Yah, I could use the last inferior, but I don't like the idea [29/04/23]
                    raise Exception(f"How am I expected to find which child you want ??")

        if DEBUG: self.logger.debug("splitting inferior %d, [pid: %d]", inferior.num, inferior.pid)
        n = inferior.num
        pid = inferior.pid
        old_inferior = self.switch_inferior(n)
        ip = self.instruction_pointer
        backup = self.inject_sleep(ip)
        self.switch_inferior(old_inferior.num)
        if DEBUG: self.logger.debug("detaching from child [%d]", pid)
        self.execute(f"detach inferiors {n}")
        from gdb_plus.debugger.debugger import Debugger # not at the top: debugger.py imports this module
        child = Debugger(pid, binary=self._exe, script=script, from_start=False, silent=self.silent)
        # needed even though by default they both inherit the module's priority since the user may change the priority of a specific debugger. [17/11/23]
        child.logger.setLevel(self.logger.level)
        # TODO copy all syscall handlers in the parent ? [31/07/23]
        # Copy libc since child can't take it from process [04/06/23]
        # Maybe not needed anymore, but better do it with all libraries anyway [01/05/25]
        child.space._libraries = self.space._libraries
        # Set parent for ptrace [08/06/23]
        child._parent = self
        if DEBUG: _logger.debug("new debugger opened")
        child.write(ip, backup)
        child.logger.debug("shellcode patched")
        child.jump(ip)

        # GEF puts a breakpoint after the fork...
        if self.gdb is not None and self._gef:
            bps = child.gdb.breakpoints()
            if len(bps) > 0:
                bp = bps[-1]
                if bp.location == "*" + hex(child.instruction_pointer + 1):
                    bp.delete()
        
        return child  

    
    # entrambi dovrebbero essere interrotti, il parent alla fine di fork, il child a metà
    # Ho deciso di lasciare correre il parent. Te la gestisci te se vuoi mettere un breakpoint mettilo dopo
    # I just discovered "gdb.events.new_inferior"... I can take the pid from event.inferior.pid, but can I do more ?
    # interrupt is not working as well as we would like. With a callback on the event we have to call interrupt when we notice the fork, but the program will have continued for a while [22/12/23] 
    # We should move to catch fork and catch clone if we want to allow interrupt [22/12/23]
    # BUG: interrupt may be confused during a split.
    @context_decorator
    def set_split_on_fork(self, off: bool = False, c: bool = False, keep_breakpoints: bool = False, interrupt: bool = False, script: str = "") -> Debugger:
        """
        split out a new debugging session for the child process every time you hit a fork

        Arguments:
            off: disable feature
            interrupt: stop parent when forking

        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self

        if self.libdebug is not None:
            log.error("Libdebug can not split on fork. You have to use gdb or new_libdebug.")
            return self


        if self._pwndbg:
            log.warn_once("pwndbg may not handle correctly multi process applications. We recommend using GEF")

        if not off and not self.local_debugging:
            log.error(NEEDS_LOCAL_PROCESS.format("set_split_on_fork() (a new gdb attached to the pid of each child)"))

        if off:
            self._backend.stop_splitting()
                
        else:
            self._backend.start_splitting(interrupt, script)
            
        return self

    split_on_fork = set_split_on_fork

    # Take all processes related
    @property
    def _process_group(self) -> dict[int, Debugger]:
        if self._parent is not None:
            return self._parent._process_group

        return {p.pid: p for p in self._recursive_children}

    # Take all grand-children
    @property
    def _recursive_children(self) -> set[Debugger]:
        group = {self}
        for child in self.children.values():
            group |= child._recursive_children
        return group
