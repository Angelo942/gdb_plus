"""
What the mixins of the Debugger share: DebuggerBase, which declares every instance attribute with its type and gives
it its initial value; the decorators lock_decorator and context_decorator; the constants (SKIP_SYSCALL, DEBUG_OFF...);
GdbDiedError; the logger.
"""
from __future__ import annotations

import os
import signal
import logging
from threading import Event
from typing import TYPE_CHECKING

from pwn import context

from gdb_plus.utils import DEBUG, LevelColorFormatter

if TYPE_CHECKING:
    from queue import Queue
    from typing import Any, Callable, Concatenate, ParamSpec, TypeVar
    from capstone import Cs
    from pwn import process, remote
    from pwnlib.gdb import Gdb
    from libdebug.debugger.debugger import Debugger as NewLibdebugDebugger
    from libdebug_legacy import Debugger as LegacyLibdebugDebugger
    from gdb_plus.utils import Arguments, Arguments_syscall, Breakpoint, EXE
    from gdb_plus.debugger.engines import Backend
    from gdb_plus.debugger.debugger import Debugger
    from gdb_plus.debugger.ptrace import PtraceEmulator
    from gdb_plus.debugger.space import AddressSpace
    from gdb_plus.debugger.control import Controller
    P = ParamSpec("P")
    R = TypeVar("R")

# Logs to debug the library can be enabled by setting DEBUG = True in gdb_plus/utils/logger.py
_logger = logging.getLogger("gdb_plus")
ch = logging.StreamHandler()
formatter = LevelColorFormatter("%(name)s:%(funcName)s:%(message)s")
ch.setFormatter(formatter)
_logger.addHandler(ch)
if DEBUG: _logger.level = 10

DEBUG_OFF = "Debug is off, commands won't be executed"
IMPORTANT_DEBUG_OFF = "Tried to get information while debug is off. Make sure to ignore the output"
# For the actions that signal the process or attach to it by pid from this machine
NEEDS_LOCAL_PROCESS = ("{} reaches the process through its pid on this machine: it can't be used on a gdbserver target, "
                       "whose pid may be another machine's")

SHOULD_STOP = 0b1
SKIP_SYSCALL = 0b10
# Constants for interrupt
INTERRUPT_SENT = 0b1 # We sent the signal
INTERRUPT_HIT_BREAKPOINT = 0b10 # The process stopped for a breakpoint instead of our signal.
# Return values of a syscall stopped by a signal that the kernel restarts: ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ERESTART_RESTARTBLOCK
_RESTART_SYSCALL = (512, 513, 514, 516)

_NEW_LIBDEBUG_REGISTERS = {"orig_rax": "syscall_number", "orig_eax": "syscall_number"}

def lock_decorator(func: Callable[Concatenate[Debugger, P], R]) -> Callable[Concatenate[Debugger, P], R]:
    def parse(self: Debugger, *args: P.args, **kwargs: P.kwargs) -> R:
        with self.control.action_lock.log(func.__name__):
            result = func(self, *args, **kwargs)
            return result
    return parse

def context_decorator(func: Callable[Concatenate[Debugger, P], R]) -> Callable[Concatenate[Debugger, P], R]:
    def add_context(self: Debugger, *args: P.args, **kwargs: P.kwargs) -> R:
        if not self._initialized:
            return func(self, *args, **kwargs)
        with context.local(**self._context_params):
            return func(self, *args, **kwargs)
    return add_context

class GdbDiedError(EOFError):
    """The gdb process behind the Debugger is gone (crashed, killed or `quit` typed in its terminal)"""

def _kill_gdb(gdb_pid: int) -> None:
    """
    Finalizer of a Debugger: must not hold a reference to it
    """
    try:
        os.kill(gdb_pid, signal.SIGTERM)
    except OSError:
        pass

class DebuggerBase:
    """
    Base class of every mixin of the Debugger: the instance attributes they share, declared with their type for the type
    checkers and for whoever reads a mixin that uses an attribute set by another one. _init_state() gives them their
    initial value.
    The declarations have no value on the class: reading an attribute that was never set still goes to
    Debugger.__getattr__ (registers, libraries, then the process and the engine).
    """
    # --- the process and the engine debugging it ---
    pid: int | None
    p: process | remote | None
    # The handles of the engines: properties of BackendsMixin, stored in the backends
    gdb: Gdb | None
    libdebug: LegacyLibdebugDebugger | None
    new_libdebug: NewLibdebugDebugger | None
    _backend: Backend # The backend of the attached engine, set by the setters of gdb, libdebug and new_libdebug
    gdbserver_qemu: Debugger | None # Debug remote qemu itself to access process maps
    debugging: bool
    local_debugging: bool
    silent: bool
    gdbscript: str # For non blocking debug_from
    debug_from_done: Event
    logger: logging.Logger
    _initialized: bool
    _context_params: dict[str, Any]
    _gef: bool
    _pwndbg: bool
    _backup_p: process | remote | None
    r: remote | None
    _host: str | None
    _port: int

    # --- files and symbols ---
    space: AddressSpace # The files of the process, their symbols and addresses
    _exe: EXE | None # Property of FilesMixin, stored in the address space
    _capstone: Cs | None
    _saved_auxiliary_vector: dict[str, int] | None
    _canary: bytes | None
    _args: Arguments | None
    _sys_args: Arguments_syscall | None
    _free_bss: int | None

    # --- the processes of the session ---
    _parent: Debugger | None
    children: dict[int, Debugger]
    split: Queue[int]
    ptrace: PtraceEmulator

    # --- stops and waits ---
    control: Controller # The stop state, the breakpoint tables and the lock of the actions (dbg.control)
    _detached: bool
    _last_breakpoint_deleted: int
    _backends: dict[type[Backend], Backend] # The backend of each engine, created by BackendsMixin._backend_of

    # --- breakpoints and events ---
    _ftrace_breakpoints: list[Breakpoint]
    _ltrace_breakpoints: list[Breakpoint]

    def _init_state(self, *, script: str, silent: bool, download: bool, qemu_gdbserver: Debugger | None) -> None:
        """
        Give the attributes their initial value, from the arguments of Debugger.__init__ (which calls it first).
        Debugger.__init__ sets debugging, ptrace, logger and _initialized itself; GdbBackend.setup() sets split.
        """
        # To decompile assembly for next_inst
        self._capstone = None

        # Only used to locate the canary
        self._saved_auxiliary_vector = None

        # Control access to the libraries
        from gdb_plus.debugger.space import AddressSpace # not at the top: space.py imports this module
        self.space = AddressSpace(self, download=download)

        self._canary = None
        self._args = None
        self._sys_args = None
        from gdb_plus.debugger.control import Controller # not at the top: control.py imports this module
        self.control = Controller(self)
        self._parent = None
        self.children = {} # Maybe put {self.pid: self} as first one
        self._ftrace_breakpoints = []
        self._ltrace_breakpoints = []

        self.pid = None
        self._context_params = context.copy() # NOTE: Be careful to check that you are using the right context arch for the binary before calling gdb
        self._context_params.setdefault("log_level", context.log_level) # Creating a child in local content silent would overwrite it otherwise
        self.silent = silent

        self.p = None
        # No engine yet: the handles (gdb, libdebug, new_libdebug) are None in their backends
        from gdb_plus.debugger.engines import Backend # not at the top: engines/ imports this module
        self._backends = {}
        self._backend = self._backend_of(Backend)

        self.gdbserver_qemu = qemu_gdbserver # Debug remote qemu itself to access process maps

        # Additional informations on the debugging context.
        self._gef = False
        self._pwndbg = False
        self.local_debugging = True # By default I let it to True, then switch it back if it's not the case

        self._backup_p = None
        self.r = None
        self._host = None
        self._port = 0

        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        self.gdbscript = script # For non blocking debug_from
        self.debug_from_done = Event()

        self._detached = False
        # Maybe not needed (see set_split_on_fork)
        self._last_breakpoint_deleted = 0 # Keep track of the last temporary breakpoint deleted if we really have to know if we hit something
