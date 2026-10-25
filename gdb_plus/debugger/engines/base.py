from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import log

from gdb_plus.utils import unexpected, PriorityEvent, DoneEvent, Breakpoint

if TYPE_CHECKING:
    from typing import Any, Callable
    from gdb import Inferior
    from gdb_plus.debugger.debugger import Debugger
    from gdb_plus.debugger.control import Controller

class Backend:
    """
    What the Debugger does differently with each engine. One subclass per engine: GdbBackend, LibdebugBackend,
    NewLibdebugBackend; this class itself stands for "no engine". The Debugger reaches the backend of the attached
    engine through self._backend (BackendsMixin).
    Each method runs on the thread, and under the lock, of the Debugger method that calls it. An engine that has no
    version of its own of a method uses the one of this class: what the Debugger does when no engine handles the
    action, often a NotImplementedError.
    A backend keeps only the state of its engine (see GdbBackend); the rest is on its Debugger, self.dbg.
    """
    # Set when the engine is gone without detach(): the Debugger refuses to use it (GdbDiedError)
    died = False
    def __init__(self, dbg: Debugger) -> None:
        self.dbg = dbg
        # The object of the engine (dbg.gdb, dbg.libdebug, dbg.new_libdebug), None while it isn't attached
        self.handle: Any = None
    def clear_register_cache(self) -> None:
        """Forget the registers read so far: the next reads ask the engine (switch_inferior). Only gdb caches them"""
        pass
    # lock_decorator and context_decorator read these on the object whose method they decorate
    @property
    def control(self) -> Controller:
        return self.dbg.control
    @property
    def _initialized(self) -> bool:
        return self.dbg._initialized
    @property
    def _context_params(self) -> dict[str, Any]:
        return self.dbg._context_params
    def delete_breakpoint(self, breakpoint: Breakpoint) -> None:
        """
        Remove the native breakpoint of `breakpoint` from the engine. Called by delete_breakpoint() once it is out of
        dbg.breakpoints.
        """
        raise NotImplementedError(f"delete_breakpoint is not implemented for the given debugger")
    def alloc(self, n: int) -> int:
        """
        alloc(heap=True): allocate n bytes on the heap of the process (malloc) and return their address.
        """
        raise NotImplementedError(f"alloc is not implemented for the given debugger")
    def dealloc(self, pointer: int) -> None:
        """
        dealloc(heap=True): free the heap memory at `pointer` (free).
        """
        raise NotImplementedError(f"dealloc is not implemented for the given debugger")
    def stopped_pid(self) -> int:
        """
        The pid of the process (or thread) whose stop _set_stop() delivers.
        """
        raise NotImplementedError(f"_set_stop is not implemented for the given debugger")
    def stop_signal(self) -> int:
        """
        The number of the signal that stopped the process (dbg.stop_signal, read while it is stopped).
        """
        raise NotImplementedError(f"stop_signal is not implemented for the given debugger")
    def running(self) -> bool:
        """
        Whether the process runs (dbg.running). Called inside context.silent.
        """
        raise NotImplementedError(f"running is not implemented for the given debugger")
    def internal_wait(self) -> None:
        """
        Block until the process stops. Called by the loop thread of the stop handlers (see GdbBackend.setup and
        NewLibdebugBackend.setup).
        Legacy libdebug has no such loop: it calls handle_stop itself.
        """
        pass
    def jump(self, address: int) -> None:
        """
        Move the instruction pointer to `address` without running anything (jump()).
        """
        raise NotImplementedError(f"jump is not implemented for the given debugger")
    def write(self, address: int, data: bytes, inferior: Inferior | None, pid: int | None) -> int | None:
        """
        Write `data` at `address` (write(), once the address is known) and return the address.
        Without an engine version: through /proc/pid/mem, which only exists for a local process.
        """
        dbg = self.dbg

        # Doesn't exist if the process is not running locally (ex remote gdbserver)
        # Doesn't matter if running under qemu because /proc/pid/mem is just a copy created at launch and nothing more 
        if inferior is not None:
            pid = inferior.pid
        if pid is None:
            pid = dbg.pid

        with open(f"/proc/{pid}/mem", "r+b") as fd:
            fd.seek(address)
            fd.write(data)

        return address
    def read(self, address: int, size: int, inferior: Inferior | None, pid: int | None) -> bytes:
        """
        Read `size` bytes at `address` (read(), once the pid is known).
        Without an engine version: through /proc/pid/mem, which only exists for a local process.
        """
        # Data inside qemu is not updated
        # We can not access memory inside remote gdbserver
        with open(f"/proc/{pid}/mem", "r+b") as fd:
            fd.seek(address)
            return fd.read(size)
    def kick(self) -> None:
        """
        Send the signal that stops the running process (_kick(), for interrupt()). Holding _action_lock.
        """
        raise NotImplementedError(f"interrupt is not implemented for the given debugger")
    def resume_process(self, step: bool) -> None:
        """
        Send the command that resumes the process: one instruction if `step`, otherwise a continue (_resume_process()).
        The caller has already counted the process as running in the PriorityManager.
        """
        raise NotImplementedError(f"_resume_process is not implemented for the given debugger")
    def start_continue(self, force: bool, wait: bool, done: DoneEvent, signal: int) -> None:
        """
        c(): start the thread that continues the process (cont), with its own task `done` in the PriorityManager.
        cont runs in that thread and sets `done` when the process stops (set_done_if_panic).
        """
        raise NotImplementedError(f"continue is not implemented for the given debugger")
    def start_continue_until(self, address: int, done: DoneEvent, force: bool, breakpoint: Breakpoint) -> None:
        """
        continue_until(): start the thread that continues the process until `address` (continue_until), where the temporary
        `breakpoint` is set. The thread sets `done` when the process stops there (set_done_if_panic).
        """
        raise NotImplementedError(f"continue until is not implemented for the given debugger")
    def breakpoint(self, address: int, legacy_callback: Callable[[Debugger], bool | int | None] | None, callback: Callable[[Debugger], bool | int | None] | None, temporary: bool, user_defined: bool, hw: bool) -> Breakpoint:
        """
        b(): set the native breakpoint of the engine at `address` and return the Breakpoint that wraps it.
        The caller adds it to dbg.breakpoints.
        """
        raise NotImplementedError(f"breakpoint is not implemented for the given debugger")
    def saved_ip(self, link_register: str | None) -> int:
        """
        The return address of the current function (_saved_ip()). link_register: the register that holds it on
        the architectures that have one, None on i386 / amd64 / arm.
        """
        raise NotImplementedError(f"_saved_ip is not implemented for the given debugger")
    def step(self, signal: int | str, timeout: float | None, internal: bool) -> tuple[PriorityEvent | None, bool]:
        """
        _step(): execute one instruction and wait for it, at most `timeout` seconds. Returns the PriorityEvent of the step
        (None if the step didn't need one) and whether it finished. Called with _stepped set.
        """
        raise NotImplementedError(f"step is not implemented for the given debugger")
    def signal(self, n: int | str, step: bool, timeout: float | None) -> None:
        """
        signal(): send signal `n` to the process and wait for it to come back from the handler (one step if `step`).
        The caller has already set the breakpoint where the process stops.
        """
        raise NotImplementedError(f"sending signals is not implemented for the given debugger")
    def queue_signal(self, n: int) -> None:
        """
        The next command that resumes the process (step or continue) delivers signal `n` (Linux number), and the signal
        that stopped the process is not delivered; n = 0 delivers nothing. Called while the process is stopped by the
        ptrace emulation of its tracer (PtraceEmulator._inject_signal), before it resumes the process.
        """
        raise NotImplementedError(f"queueing signals is not implemented for the given debugger")
    def auxiliary_vector(self) -> dict[str, int] | None:
        """
        The auxiliary vector of the process, {AT_* name: value} (dbg._auxiliary_vector caches it). None if gdb can't
        read it. This version asks gdb (`info auxv`): it serves gdb, and the Debugger without an engine.
        """
        dbg = self.dbg
        auxv_info = dbg.execute("info auxv")
        if "failed" in auxv_info:
            unexpected(auxv_info, log)
            return None
        auxiliary_vector = {}
        for line in auxv_info.splitlines():
            line = line.split('"')[0].strip()  # remove the ending string (if any)
            line = line.split()  # split the string by whitespace(s)
            if len(line) < 4:
                continue
            __av_type = line[1]
            __av_value = line[-1]
            auxiliary_vector[__av_type] = int(__av_value, base=0)
        return auxiliary_vector
    def stop_reason(self) -> str:
        """
        Why the process stopped (dbg._stop_reason): a signal name, "BREAKPOINT", "SINGLE STEP", "RUNNING", "NOT RUNNING"...
        Called once the process has had a chance to stop (up to 0.5 s).
        """
        raise NotImplementedError(f"_stop_reason is not implemented for the given debugger")
    def detach(self, quit: bool, block: bool) -> None:
        """
        detach(): release the process, already interrupted, and the engine. quit: also kill the process (new libdebug only);
        block: leave the process stopped. _detached is already set.
        """
        raise NotImplementedError(f"detach is not implemented for the given debugger")
    def stop_splitting(self) -> None:
        """
        set_split_on_fork(off=True): stop creating a Debugger for each child. Legacy libdebug never splits (set_split_on_fork
        refuses it before), so nothing to do.
        """
        pass
    def start_splitting(self, interrupt: bool, script: str) -> None:
        """
        set_split_on_fork(): create a Debugger for each child the process forks (dbg.children, dbg.split). interrupt: stop the
        parent at each fork; script: the gdbscript of the children. Legacy libdebug never splits, so nothing to do.
        """
        pass
    def read_register(self, name: str) -> int:
        """
        The value of the register `name` (dbg.rax, dbg.eax...), from __getattr__ while debugging. The process must be stopped.
        """
        raise NotImplementedError(f"register access is not implemented for the given debugger")
    def write_register(self, name: str, value: int) -> None:
        """
        Set the register `name` to `value` (dbg.rax = ...), from __setattr__ while debugging. The process must be stopped.
        """
        raise NotImplementedError(f"setting registers is not implemented for the given debugger")
    def send_command(self, command: str | Callable[[], object]) -> None:
        """
        execute_action(): send the command that resumes the process, once its PriorityEvent exists. A gdb command, or for
        the libdebugs a function that resumes the process; "" only resets the wait, and only with gdb.
        """
        raise NotImplementedError(f"execute_action is not implemented for the given debugger")
    def call_mprotect(self, page_address: int, length: int) -> None:
        """
        make_page_rwx(): make `length` bytes from `page_address` readable, writable and executable with the mprotect of the
        process, through call(). gdb calls it itself.
        """
        dbg = self.dbg
        dbg.call("mprotect", [page_address, length, 7])
    def catch_pending_sigint(self) -> int:
        """
        _catch_pending_sigint(): the process stopped for something else before our SIGINT arrived. Only gdb can leave the
        SIGINT pending: the other engines only forget the interrupt. Returns INTERRUPT_HIT_BREAKPOINT, or 0.
        """
        dbg = self.dbg
        dbg.control.interrupted = False
        return 0
    def handle_signal(self, signal: str) -> None:
        """
        handle_signal(): make the engine stop on `signal` without passing it to the process. Only gdb needs a command.
        """
        pass
    def close(self) -> None:
        """
        close(): what the engine needs once the process and its tubes are closed. Only gdb has something to do.
        """
        pass
    def read_long_register(self, name: str) -> int:
        """
        The value of the 128 bit register `name` (dbg.xmm0...), from __getattr__ while debugging. Only gdb reads them.
        """
        raise Exception("not supported")
    def write_long_register(self, name: str, value: int) -> None:
        """
        Set the 128 bit register `name` to `value` (dbg.xmm0 = ...), from __setattr__ while debugging. Only gdb writes them.
        """
        raise Exception("Not supported")
    def repr(self) -> str | None:
        """
        __repr__(): the representation the engine gives of the process, None to use the one of the Debugger.
        """
        return None
