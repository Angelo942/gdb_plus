from __future__ import annotations

from math import ceil
from multiprocessing import Process
from multiprocessing import Event as p_Event
from multiprocessing import Queue as p_Queue
from multiprocessing import cpu_count
from typing import TYPE_CHECKING

from pwn import constants, context, log

from gdb_plus.debugger._base import DebuggerBase, IMPORTANT_DEBUG_OFF, context_decorator

if TYPE_CHECKING:
    from typing import Callable
    from multiprocessing.queues import Queue as MPQueue
    from multiprocessing.synchronize import Event as MPEvent
    from gdb_plus.debugger.debugger import Debugger

class BruteforceMixin(DebuggerBase):
    """
    bruteforce(): try a value in each child of the stopped process, forked for it (experimental).
    """
    @context_decorator
    def _bruteforce(self, threads: list[tuple[Debugger, range]], init: Callable[[Debugger], object] | None, setup: Callable[[Debugger, int], object] | None, _to: int, check: Callable[[Debugger, int], bool], backup: list[tuple[int, int]], result: MPQueue[int | None], shutdown: MPEvent, libdebug: bool) -> None:
        # Riconnetti gli eventi di gdb con il nuovo processo 
        for child, _ in threads:
            child.migrate(libdebug=True)
            if not libdebug:
                child.migrate(gdb=True)
        for child, range in threads:
            context.Thread(target=child._bruteforce_thread, args=(init, setup, _to, check, range, backup, result, shutdown, libdebug), name=f"[{self.pid}] bruteforce [{range.start}:{range.stop}]", daemon=True).start()
        shutdown.wait()

    def _bruteforce_thread(self, init: Callable[[Debugger], object] | None, setup: Callable[[Debugger, int], object] | None, _to: int, check: Callable[[Debugger, int], bool], range: range, backup: list[tuple[int, int]], result: MPQueue[int | None], shutdown: MPEvent, libdebug: bool) -> None:
        if init is not None:
            init(self)
        registers = self.backup()
        # continue_until would be too slow, so I use a single breakpoint # Warning for self modifying code
        self.b(_to, user_defined=False)
        saved_memory = []
        for address, size in backup:
            saved_memory.append((address, self.read(address, size)))
        for i in range:
            if shutdown.is_set():
                return
            if setup is not None:
                setup(self, i)
            self.cont()
            assert self.instruction_pointer == _to, f"[{self.pid}] stopped at {hex(self.instruction_pointer)} instead of {hex(_to)} with {self._stop_reason}!!"
            if check(self, i):
                result.put(i)
            # restore backups
            self.restore_backup(registers)
            for address, data in saved_memory:
                self.write(address, data)
        result.put(None)

    def bruteforce(self, _to: int | str, check: Callable[[Debugger, int], bool], _from: int | str | None = None, setup: Callable[[Debugger, int], object] | None = None, init: Callable[[Debugger], object] | None = None, limit: int = 1000, backup: list[tuple[int, int]] = [], libdebug: bool = False, n_threads: int = 1, n_processes: int = cpu_count()) -> int | None:
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return None
        log.warn_once("Bruteforce is experimental! Function may break and names may change")
        parallel = n_threads * n_processes
        result = p_Queue()
        shutdown = p_Event()
        processes = []
        if _from is not None:
            self.jump(_from)
        _to = self._parse_address(_to)
        n = ceil(limit / parallel)
        if self.gdb is None:
            log.warn_once("debugger must be set on gdb... migrating to gdb")
            self.migrate(gdb=True)
        self.set_split_on_fork(interrupt=True)
        progress = log.progress("setting up processes...")
        for i in range(0, parallel, n_threads):
            threads = []
            for j in range(n_threads):
                idx = i+j
                progress.status(f"Process {i+1}/{n_processes}, Thread {j+1}/{n_threads}")
                # Why return negative value, but still split ?
                self.syscall(constants.SYS_fork, [])
                pid = self.wait_split()
                child = self.children[pid]
                # The shellcode hasn't been removed in the child process
                child.write(self.instruction_pointer, self.read(self.instruction_pointer, child.instruction_pointer + 1 - self.instruction_pointer))
                child.jump(self.instruction_pointer)
                threads.append((child, range(idx*n, (idx+1)*n)))
            processes.append(Process(target=child._bruteforce, args=(threads, init, setup, _to, check, backup, result, shutdown, libdebug)))
        progress.success("all threads are ready")
        self.detach()
        #if libdebug:
        #    log.debug(f"{self.gdb=}")
        #    self.migrate(libdebug=True)
        #processes.append(context.Thread(target=self._bruteforce, args=(init, setup, _to, check, range(n), backup, result, shutdown, libdebug)))
        for t in processes:
            log.info(f"starting {t}")
            t.start()
        for _ in range(parallel):
            res = result.get()
            if res is not None:
                shutdown.set()
                return res
        else:
            log.critical("couldn't find a solution")
