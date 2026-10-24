"""
Emulation of ptrace between the processes of one debugging session.

Linux allows a single tracer per process, so a process traced by another one can't be debugged. When both the tracer
and the tracee run under gdb_plus we let neither of them call ptrace and waitpid for real: a breakpoint on each function
(or a catchpoint on each syscall) answers in its place, acting on the Debugger of the other process.

- PtraceEmulator, one per Debugger (`dbg.ptrace`), holds the state of the process both as a tracer (its slaves, the hooks
  it installed) and as a tracee (has it stopped for its tracer's waitpid ?), and implements the requests.
- PtraceMixin gives Debugger its public methods emulate_ptrace() and trace().
The other mixins only use the hooks take_stop(), on_exit(), suspended() and warn_if_used().
"""
from __future__ import annotations

import os
import sys
import signal
from contextlib import contextmanager
from functools import partial
from threading import Event
from typing import TYPE_CHECKING

from pwn import constants, context, log, p32, pack, sleep, unpack

from gdb_plus.utils import DEBUG, user_regs_struct, return_instruction, nop
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, SKIP_SYSCALL, context_decorator

if TYPE_CHECKING:
    from typing import Callable, Iterator, ParamSpec, TypeVar
    from gdb_plus.utils import Breakpoint
    from gdb_plus.debugger.debugger import Debugger
    P = ParamSpec("P")
    R = TypeVar("R")

# The requests we emulate (PTRACE_<name>). On Linux PEEKDATA and POKEDATA are the same requests as PEEKTEXT and POKETEXT
REQUESTS = ["TRACEME", "POKEDATA", "POKETEXT", "PEEKTEXT", "PEEKDATA", "GETREGS", "SETREGS", "ATTACH", "SEIZE",
            "INTERRUPT", "CONT", "DETACH", "SETOPTIONS", "SINGLESTEP"]
SAME_AS = {"POKEDATA": "POKETEXT", "PEEKDATA": "PEEKTEXT"}

def _define_missing_constants() -> None:
    "Add to pwntools' `constants` the ptrace requests and options it doesn't define (shared by every Debugger)"
    # Waiting for pwntools update
    constants.PTRACE_SEIZE = 0x4206
    constants.PTRACE_INTERRUPT = 0x4207
    if context.arch == "amd64":
        constants.PTRACE_GETREGS = 12
        constants.PTRACE_SETREGS = 13
        constants.PTRACE_SETOPTIONS = 0x4200 # really ??
        constants.PTRACE_O_EXITKILL = 0x00100000
        constants.PTRACE_O_SUSPEND_SECCOMP = 0x00200000
        constants.PTRACE_O_MASK     = 0x003000ff

def _in_debugger_context(func: Callable[..., R]) -> Callable[..., R]:
    """
    Run a method of PtraceEmulator in the pwntools context (arch, bits...) of its Debugger, as context_decorator does
    for the methods of the Debugger
    """
    def add_context(self: PtraceEmulator, *args: object, **kwargs: object) -> R:
        if not self.dbg._initialized:
            return func(self, *args, **kwargs)
        with context.local(**self.dbg._context_params):
            return func(self, *args, **kwargs)
    return add_context

class PtraceMixin(DebuggerBase):
    """The public methods of the ptrace emulation. The work is done by self.ptrace (PtraceEmulator)."""

    # I want a single function so that each process can be both master and slave [08/06/23]
    # I use real callback as long as we are breaking on the function it should work. The problem is if we start catch the syscall instead [08/06/23] Why ? [28/07/23]
    # Should we split the "manual" between ptrace and waitpid ? So that I can only wait for the later ? For now I will put the breakpoint a bit later so that you can do continue_until("waitpid") [28/07/23]
    # TODO teach how to add symbols in a binary for the functions if the code is statically linked and stripped
    # TODO use plt if binary is not statically linked so that you don't need to load the libc ? [31/07/24] -> This may interfere with ltrace.
    @context_decorator
    def emulate_ptrace(self, *, off: bool = False, wait_fun: str = "waitpid", wait_syscall: str = "wait4", manual: bool = False, silent: bool = False, signals: list[str] = ["SIGSTOP"], syscall: bool = False) -> Debugger | None:
        """
        Emulate all calls to ptrace and waitpid between processes debugged.
        Can hook the syscall instead of the function.

        Use manual=True if you want the debugger to stop when reaching a breakpoint, whether because you are using gdb manually or because you want to observe what is going on.

        Example:
            # Create debugger for child process.
            dbg.set_split_on_fork()
            done = dbg.until(..., wait=False) # Make sure to break before the first call to ptrace
            pid = dbg.wait_split()
            child = dbg.children[pid]
            done.wait()
            # Does NOT depend on which process is tracing which.
            dbg.emulate_ptrace()
            child.emulate_ptrace()
            # Continue execution.
            dbg.c(wait=False)
            child.c(wait=False)
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self

        if off:
            self.ptrace.disable()
            return None

        if not self.ptrace.enable(wait_fun=wait_fun, wait_syscall=wait_syscall, manual=manual, silent=silent, signals=signals, syscall=syscall):
            return None
        return self

    # We have problems with ptrace_group, but that was also a stupid idea so we should think about removing it... Just wait for the pid to be in the slaves... [22/12/23]
    # No, ptrace_group is still useful to get a process from his pid when emulating attach! [22/12/23]
    def trace(self, slave: Debugger, parent: bool = False) -> None:
        """
        Setup the debugger with the provided slave, simulating the state as if a fork and call to ptrace_traceme or ptrace_attach had been made.
        You still have to call self.emulate_ptrace() with the settings you want.

        Args:
            parent (bool): Optional. Set to True if the slave is the tracer's parent process. By default we will pretend the slave is a child.
        """
        self.ptrace.trace(slave, parent=parent)

class PtraceEmulator:
    """
    The ptrace state of one process and the emulated requests.

    A process can be a tracer (it has slaves), a tracee (its stops go to its tracer's waitpid), or both.
    _on_wait and _on_ptrace are breakpoint callbacks of the tracer: they run on the thread that handles that stop (see
    _handle_breakpoints). The request handlers (_PTRACE_*) run there too, on the emulator of the process that called
    ptrace, with the tracee as `slave`.
    """

    def __init__(self, dbg: Debugger) -> None:
        self.dbg = dbg
        # --- as a tracer ---
        self.slaves: dict[int, Debugger] = {} # I keep it to be sure I am tracing them
        self.syscall = False # The hooks catch the syscalls instead of the libc functions
        self._breakpoints: list[Breakpoint] = []
        self._backups: dict[int, bytes] = {} # address -> original bytes of the libc functions we disabled
        self._requests: dict[int, str] = {} # request number -> name, for the architecture of the process
        # --- as a tracee ---
        self.emulated = False # Our stops are reported to the tracer's waitpid instead of to the script
        self.has_stopped = Event()
        self.can_continue = Event()

    ########################## SETUP ##########################

    def enable(self, *, wait_fun: str, wait_syscall: str, manual: bool, silent: bool, signals: list[str], syscall: bool) -> bool:
        """
        Hook ptrace and wait_fun (or their syscalls) to emulate them.
        Returns False if the functions are hooked already.
        """
        dbg = self.dbg
        self.emulated = True
        if syscall:
            assert dbg.gdb is not None, "libdebug can't catch ptrace syscall. Emulate with syscall = False"
            self.syscall = True

        # TODO HANDLE CATCHPOINTS AS BREAKPOINTS TO DELETE THEM
        if len(self._breakpoints):
            log.warn(f"[{dbg.pid}] is already emulating ptrace")
            return False

        if DEBUG: dbg.logger.debug("emulating ptrace")

        if dbg.gdb is not None:
            # When emulating ptrace SIGSTOP is supposed to be used between the processes and caught by waitpid, so I don't pass it to the process to avoid problems [22/07/23]
            # https://stackoverflow.com/questions/10415739/gdb-gives-me-infinite-program-received-signal-sigtstp-when-i-try-to-resume
            for name in signals:
                dbg.execute(f"handle {name} stop nopass")

        if dbg.new_libdebug is not None:
            log.warn_once("We recommend libdebug over new_libdebug to emulate ptrace.")

        _define_missing_constants()
        self._requests = {getattr(constants, f"PTRACE_{name}"): name for name in REQUESTS}

        if not syscall:
            # Disable functions (Is it needed compared to a simple return in the callback ? I'm worried about the user manually going over the breakpoint)
            shellcode = nop[context.arch] + return_instruction[context.arch]
            for function in [wait_fun, "ptrace"]:
                address = dbg._parse_address(function)
                backup = dbg.read(address, len(shellcode))
                dbg.write(address, shellcode)
                self._backups[address] = backup

        # The callbacks only receive (dbg, entry): bind the options of this call to them
        on_wait = partial(self._on_wait, manual=manual, silent=silent, syscall=syscall)
        on_ptrace = partial(self._on_ptrace, manual=manual, silent=silent, syscall=syscall)

        if syscall:
            dbg.catch_syscall(wait_syscall, on_wait)
        else:
            self._breakpoints.append(dbg.b(wait_fun + f"+{len(nop[context.arch])}", callback=on_wait, user_defined=False))

        # I still lose control if I hit the breakpoint on ptrace with a dbg.si()... [18/01/25]
        if syscall:
            dbg.catch_syscall("ptrace", on_ptrace)
        else:
            self._breakpoints.append(dbg.b("ptrace+1", callback=on_ptrace, user_defined=False))

        return True

    def disable(self) -> None:
        """Remove the hooks and restore the functions. Not supported when hooking the syscalls."""
        if self.syscall:
            log.warn("I still don't know how to disable the emulation with syscall")
            return

        for bp in self._breakpoints:
            self.dbg.delete_breakpoint(bp)

        for address, backup in self._backups.items():
            self.dbg.write(address, backup)
        self.emulated = False

    def trace(self, slave: Debugger, parent: bool = False) -> None:
        """Make `slave` a tracee of this process, as if it called PTRACE_TRACEME after a fork (see Debugger.trace)"""
        dbg = self.dbg
        self.slaves[slave.pid] = slave
        slave.ptrace.emulated = True
        if parent:
            dbg._parent = slave
            slave.children[dbg.pid] = dbg
        else:
            dbg.children[slave.pid] = slave
            slave._parent = dbg

    ########################## HOOKS FOR THE DEBUGGER ##########################

    def take_stop(self, *, verbose: bool = False) -> bool:
        """
        Called by the stop handlers (on their thread, holding _action_lock) when the process stopped for a signal.
        While ptrace is emulated that stop belongs to the tracer's waitpid: mark the process as stopped for it and return
        True, and the stop handler must not wake the script. Returns False when ptrace isn't emulated.
        verbose: log the signal with log.info (it reads _stop_reason, which costs requests to gdb)
        """
        if not self.emulated:
            return False
        if verbose:
            log.info(f"stop signal {self.dbg._stop_reason} will be handled by waitpid")
        elif DEBUG:
            self.dbg.logger.debug("stop will be handle by waitpid")
        self.has_stopped.set()
        return True

    def on_exit(self) -> None:
        """
        Called when the process exits or gdb dies (_exit_handler, _on_gdb_died): wake the tracer if it waits for this
        process
        """
        self.has_stopped.set()

    @contextmanager
    def suspended(self) -> Iterator[None]:
        """
        Context manager: inside it the stop handlers give the signal stops to the script, as if ptrace wasn't emulated.
        Used by migrate() for the steps it makes after attaching.
        """
        backup, self.emulated = self.emulated, False
        try:
            yield
        finally:
            self.emulated = backup

    def warn_if_used(self) -> None:
        """Called by _setup_gdb(): warn once when the process calls ptrace (gdb only: it uses a catchpoint)"""
        # I still don't know how to disable it to let ptrace_emulate work in peace [26/07/23]
        def callback_ptrace(dbg: Debugger, entry: bool) -> bool:
            if entry:
                log.warn_once(f"THE PROCESS [{dbg.pid}] USES PTRACE!")
            # Do we also want to delete the breakpoint once we know we are using ptrace ? [13/08/23]
            else:
                dbg.delete_catch_syscall("ptrace")
            return False
        self.dbg.catch_syscall("ptrace", callback_ptrace)

    ########################## TRACEE SIDE ##########################

    # Can we remove these ? [25/08/24]
    def wait_can_continue(self) -> None:
        "With manual=True: block until the tracer's PTRACE_CONT or PTRACE_DETACH lets this process go. Nothing calls it"
        self.can_continue.wait()
        self.can_continue.clear()

    # TODO make sure the slave didn't stop for a user breakpoint !
    # Handle all options: https://stackoverflow.com/questions/21248840/example-of-waitpid-in-use
    def wait_stopped(self, options: int = 0x40000000) -> bool:
        """
        What the tracer's waitpid sees of this process: True once it stopped (False for WNOHANG while it runs).
        Called by the tracer's _on_wait: without WNOHANG it blocks that callback until this process stops.
        """
        if options == 0x1: # WNOHANG
            log.info("waitpid WNOHANG! Won't stop")
            # Check first that the slave isn't running in case has_stopped hasn't been cleared correctly ? Clear it in hidden_continue instead of PTRACE_CONT ? [27/06/23]
            stopped = self.has_stopped.is_set()
        else:
            if DEBUG: self.dbg.logger.debug("waiting for slave to stop.")
            self.has_stopped.wait()
            if DEBUG: self.dbg.logger.debug("slave has stop.")
            stopped = True

        # I can't clear it only here ! A wrong SIGSTOP in the step before a continue would set it again [22/07/23]
        if stopped:
            self.has_stopped.clear()

        return stopped

    ########################## BREAKPOINT CALLBACKS ##########################

    def _on_wait(self, dbg: Debugger, entry: bool | None = None, *, manual: bool, silent: bool, syscall: bool) -> bool | int:
        """
        Callback on wait_fun (or on its syscall): answer with the state of the slave.
        manual, silent, syscall: the options of the emulate_ptrace() that installed it
        """
        def callback(dbg: Debugger) -> bool:
            if syscall:
                args = dbg.syscall_args
            else:
                args = dbg.args

            pid = args[0]
            status_pointer = args[1]
            options = args[2]

            if pid == 2**32 - 1:
                assert len(self.slaves) <= 1, "For now I can only handle waitpid(-1) if there is only one slave"
                if len(self.slaves) == 0:
                    log.warn("The other process hasn't called TRACEME yet. I will wait... (just make sure you didn't setup ptrace_emulation too late)")
                while len(self.slaves) == 0:
                    sleep(0.2)
                pid = list(self.slaves.keys())[0]
                if DEBUG: dbg.logger.debug("waiting for -1...")

            log.info(f'waitpid for process [{pid}]')
            if pid not in dbg._process_group:
                raise Exception(f"We reached waitpid but we didn't have time to split the new process! Please stop the process earlier")
            if pid not in self.slaves:
                log.warn(f"The process {pid} hasn't called TRACEME yet. I will wait... (just make sure you didn't setup ptrace_emulation too late)")
            while pid not in self.slaves:
                sleep(0.2)
            tracee = self.slaves[pid]
            stopped = tracee.ptrace.wait_stopped(options)
            # If we close the program while both debuggers are still open we are gonna try to continue the stop handler letting the parent know that the child exited, but since the parent is also closed the code would crash
            # Instead we exit cleanly
            if dbg.control.closed.is_set(): sys.exit()

            # TODO what about handling events in status ? [04/06/23]
            if stopped:
                if tracee._stop_reason == "NOT RUNNING":
                    status = 0x0
                else:
                    status = (tracee.stop_signal * 0x100 + 0x7f)
                dbg.return_value = pid
            else:
                status = 0x0
                dbg.return_value = 0x0
            log.info(f"[{dbg.pid}] setting status waitpid for {pid}: {hex(status_pointer)} -> [{hex(status)}]")
            dbg.write(status_pointer, p32(status))
            # I don't handle the errors yet [19/06/23]
            # I would have liked it, but for now we have a bug if ret jumps on an address where we have a breakpoint that should stop, but our return False let the process run anyway [09/06/23]
            # Now it should work, but I don't want to risk it ahah [23/06/23]
            #dbg.ret()
            # Don't stop for a WNOHANG [09/06/23]

            # For some reason after the setoption it continues even with manual = False, but stops after continue...
            if manual and stopped:
                tracee.control.set_stop("waitpid asked to stop")
                return True
            else:
                return False

        if silent:
            with context.silent:
                should_stop = callback(dbg)
        else:
            should_stop = callback(dbg)

        if syscall:
            return_code = SKIP_SYSCALL | should_stop
        else:
            return_code = should_stop

        return return_code

    def _on_ptrace(self, dbg: Debugger, entry: bool | None = None, *, manual: bool, silent: bool, syscall: bool) -> bool | int:
        """
        Callback on ptrace (or on its syscall): dispatch the request to its _PTRACE_* handler.
        manual, silent, syscall: the options of the emulate_ptrace() that installed it
        """
        def callback(dbg: Debugger) -> bool:
            if syscall:
                args = dbg.syscall_args
            else:
                args = dbg.args

            ptrace_command = args[0]
            pid = args[1]
            arg1 = args[2]
            arg2 = args[3]

            name = self._requests.get(ptrace_command)
            log.info(f"[{dbg.pid}] ptrace {pid} -> {ptrace_command}[{'PTRACE_' + name if name is not None else 'UNKNOWN PTRACE'}]: ({hex(arg1)}, {hex(arg2)})")
            name = self._requests[ptrace_command]
            action = getattr(self, f"_PTRACE_{SAME_AS.get(name, name)}")

            if ptrace_command == constants.PTRACE_TRACEME:
                tracer = dbg if dbg._parent is None else dbg._parent

                if dbg.pid not in tracer.ptrace.slaves:
                    log.debug(f"TRACEME: [{dbg.pid}] will be trace by [{tracer.pid}]")
                    should_stop = action(tracer, manual=manual)

                else:
                    log.warn(f"[{dbg.pid}] is already traced !")
                    dbg.return_value = -1
                    return manual

            elif ptrace_command in [constants.PTRACE_ATTACH, constants.PTRACE_SEIZE]:

                if pid in self.slaves:
                    log.warn(f"[{pid}] is already traced !")
                    dbg.return_value = -1
                    return manual

                else:
                    tracee = dbg._process_group[pid]
                    should_stop = action(pid, arg2, slave=tracee, manual=manual)

            else:
                tracee = self.slaves[pid]
                should_stop = action(arg1, arg2, slave=tracee, manual=manual)

            return should_stop

        if silent:
            with context.silent:
                should_stop = callback(dbg)
        else:
            should_stop = callback(dbg)

        if syscall:
            return_code = SKIP_SYSCALL | should_stop
        else:
            return_code = should_stop

        return return_code

    ########################## PTRACE REQUESTS ##########################
    # If attach and interrupt stop the process I want continue and detach to let it run again, otherwise just set ptrace_can_continue [08/06/23]
    # Should we handle the interruptions in a special way ? Like adding a priority when attaching ? [08/06/23] (But how to handle stop due to a SIGNAL ?)

    # We could do a return False or True depending on if we interrupted the process or not. A small indication if we are debugging manually or not [08/06/23]
    def _PTRACE_ATTACH(self, pid: int, _: int, *, slave: Debugger, **kwargs: bool) -> bool:
        log.debug(f"pretending to attach to process {pid}")
        self.slaves[pid] = slave
        #if slave.running:
        #    log.info(f"attach will interrupt the slave")
        #    slave.interrupt()
        #    # It makes no sense because any signal interruption would not be able to distinguish if we were manually debugging or not [08/06/23] (Not really, but it would require a lot of work)
        #    #slave.ptrace_interrupted = True
        self._PTRACE_INTERRUPT(0, 0, slave=slave)
        slave.ptrace.has_stopped.set()
        self.dbg.return_value = 0
        return False

    def _PTRACE_SEIZE(self, pid: int, options: int, *, slave: Debugger, **kwargs: bool) -> bool:
        log.debug(f"pretending to seize process {slave.pid}")
        self._PTRACE_SETOPTIONS(pid, options, slave=slave)
        self.slaves[pid] = slave
        self.dbg.return_value = 0x0
        return False

    # Only function called by the slave
    def _PTRACE_TRACEME(self, tracer: Debugger, *, manual: bool = False, **kwargs: bool) -> bool:
        log.debug("slave wants to be traced")
        tracer.ptrace.slaves[self.dbg.pid] = self.dbg
        log.debug(f"setting {self.dbg.pid} as slave for {tracer.pid}")
        self.dbg.return_value = 0
        # dirt left by ptrace that could be checked
        # Only do it if we don't handle the syscall... [26/07/23]
        #if context.arch == "amd64":
        #    self.r8 = -1
        # Wait, why ? haha. This was stupid... [24/12/23]
        #tracer.ptrace.has_stopped.set()
        return manual

    def _PTRACE_CONT(self, _: int, __: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        if not manual:
            log.info(f"[{self.dbg.pid}] PTRACE_CONT will let the slave [{slave.pid}] continue")
            slave.ptrace.has_stopped.clear()
            slave._hidden_continue(force=True)
        else:
            slave.ptrace.can_continue.set()
            log.info("slave can continue !")
        self.dbg.return_value = 0x0
        return manual

    def _PTRACE_DETACH(self, _: int, __: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        log.debug(f"ptrace detached from {slave.pid}")
        self.slaves.pop(slave.pid)
        slave.ptrace.can_continue.set()
        if not manual:
            log.info(f"detach will let the slave continue")
            slave._hidden_continue(force=True)
        self.dbg.return_value = 0x0
        return manual

    def _PTRACE_POKETEXT(self, address: int, data: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        log.debug(f"poking {hex(data)} into process {slave.pid} at address {hex(address)}")
        slave.write(address, pack(data))
        self.dbg.return_value = 0 # right ?
        return manual

    @_in_debugger_context
    def _PTRACE_PEEKTEXT(self, address: int, _: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        try:
            data = unpack(slave.read(address, context.bytes))
            log.debug(f"peeking {hex(data)} from process {slave.pid} at address {hex(address)}")
        except Exception:
            data = -1
            log.warning(f"invalid address {hex(address)} to peek from process {slave.pid}. Returning -1")

        self.dbg.return_value = data
        return manual

    def _PTRACE_GETREGS(self, _: int, pointer_registers: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        registers = user_regs_struct()
        for register in slave._registers:
            value = getattr(slave, register)
            if DEBUG: self.dbg.logger.debug("reading [%d]'s register %s: 0x%x", slave.pid, register, value)
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            setattr(registers, register, value)
        self.dbg.write(pointer_registers, registers.get())
        self.dbg.return_value = 0 # right ?
        return manual

    # ATTENTO CHE setattr ritorna prima che venga fatto correttamente la jump per mettere rip. Quindi potresti avere una race condition [09/06/23]
    def _PTRACE_SETREGS(self, _: int, pointer_registers: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        registers = user_regs_struct()
        registers.set(self.dbg.read(pointer_registers, registers.size))
        for register in slave._registers:
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            value = getattr(registers, register)
            if DEBUG: self.dbg.logger.debug("setting [%d]'s register %s: 0x%x", slave.pid, register, value)
            setattr(slave, register, value)
        self.dbg.return_value = 0
        return manual

    def _PTRACE_SETOPTIONS(self, _: int, options: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        if DEBUG: self.dbg.logger.debug("0x%x", options)
        if options & constants.PTRACE_O_EXITKILL:
            options -= constants.PTRACE_O_EXITKILL
            log.info("Option EXITKILL set")
            #if DEBUG: self.dbg.logger.debug("They want to kill the slave if you remove the master")
            if DEBUG: self.dbg.logger.debug("0x%x", options)

        if options & constants.PTRACE_O_TRACESYSGOOD:
            options -= constants.PTRACE_O_TRACESYSGOOD
            log.info("Option TRACESYSGOOD set")
            #log.debug("")
            if DEBUG: self.dbg.logger.debug("0x%x", options)

        if options != 0:
            raise Exception(f"{hex(options)}: Not implemented yet")

        self.dbg.return_value = 0x0
        return manual

    def _PTRACE_SINGLESTEP(self, _: int, __: int, *, slave: Debugger, manual: bool = False, **kwargs: bool) -> bool:
        log.info(f"ptrace single step from {slave.reverse_lookup(slave.instruction_pointer)}")
        slave.step()
        if DEBUG: self.dbg.logger.debug("Telling the slave that it has stopped")
        slave.ptrace.has_stopped.set()
        self.dbg.return_value = 0x0
        return manual

    # NOT TESTED YET
    def _PTRACE_INTERRUPT(self, _: int, __: int, *, slave: Debugger, **kwargs: bool) -> bool:
        # Should I just send a SIGSTOP ? Using interrupt won't make it accessible to waitpid! [23/07/23]
        if DEBUG: self.dbg.logger.debug("waiting out of breakpoint")
        slave.control.out_of_breakpoint.wait()
        if DEBUG: self.dbg.logger.debug("out of breakpoint waited")
        ## 1) does it make sense ? If someone will try running while I interrupt it will try again just after. But this would break any action the master is trying to perform [21/06/23 14:00]
        ## 2) We can't have both this and the lock_wrapper for interrupt
        ##slave._action_lock.can_run.clear()
        #if slave.running:
        #    log.info(f"ptrace will interrupt the slave [{slave.pid}]")
        #    slave.interrupt()
        # It won't be able to continue, right ? [21/06/23 13:30]
        ##slave._action_lock.can_run.set()
        # Is the if needed ? Shouldn't we send the signal every time even in manual ? [23/07/23]
        if slave.running:
            os.kill(slave.pid, signal.SIGSTOP)
        self.dbg.return_value = 0x0
        return False
