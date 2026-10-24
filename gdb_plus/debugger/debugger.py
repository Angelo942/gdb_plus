"""
Debugger, the class users create. It combines the mixins of this package; this module holds what belongs to none of
them: __init__ (a sequence of named steps), the registers and libraries read and written as attributes (__getattr__ /
__setattr__, which also hand unknown names to the process and to the engine), __repr__, __dir__ and the context manager.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from pwn import ELF, args, context, log, process, sleep

from gdb_plus.utils import DEBUG, EXE, enum_libs, unexpected
from gdb_plus.setup import identify_executable
from gdb_plus.debugger.engines import GdbBackend
from gdb_plus.debugger._base import DEBUG_OFF, context_decorator, _logger, ch
from gdb_plus.debugger.launch import LaunchMixin
from gdb_plus.debugger.backends import BackendsMixin
from gdb_plus.debugger.stops import StopsMixin
from gdb_plus.debugger.control_flow import ControlFlowMixin
from gdb_plus.debugger.stepping import SteppingMixin
from gdb_plus.debugger.breakpoints import BreakpointsMixin
from gdb_plus.debugger.events import EventsMixin
from gdb_plus.debugger.memory import MemoryMixin
from gdb_plus.debugger.registers import RegistersMixin
from gdb_plus.debugger.calls import CallsMixin
from gdb_plus.debugger.files import FilesMixin
from gdb_plus.debugger.forks import ForksMixin
from gdb_plus.debugger.ptrace import PtraceMixin, PtraceEmulator
from gdb_plus.debugger.bruteforce import BruteforceMixin
from gdb_plus.debugger.gef import GefMixin

if TYPE_CHECKING:
    from typing import Any

class Debugger(LaunchMixin, BackendsMixin, StopsMixin, ControlFlowMixin, SteppingMixin, BreakpointsMixin, EventsMixin,
               MemoryMixin, RegistersMixin, CallsMixin, FilesMixin, ForksMixin, PtraceMixin, BruteforceMixin, GefMixin):
    """
    The debugger of one process. Each feature area is a mixin (one module of gdb_plus/debugger/ each); the attributes
    they share are declared in DebuggerBase (_base.py).
    """
    # NOTE: If possible patch the rpath (spwn and pwninit do it automatically) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target: int | str | ELF | process | list[str] | tuple[str, int], *, binary: str | ELF | None = None, env: dict[str, str] | None = None, aslr: bool = True, script: str = "", from_start: bool = True, debug_from: int | str | None = None, timeout: float = 0.5, from_entry: bool = True, silent: bool = True, qemu_gdbserver: Debugger | None = None, download: bool = False) -> None:
        """
        Args:
            target (int, process, str, ELF, EXE, list, tuple):
                - **int**: The pid of a process to debug.
                - **process**: Process to debug
                - **str**: A path to the file to debug.
                - **ELF**: File to debug (EXE included).
                - **list**: A list of arguments as in process(list)
                - **tuple**: (host, port) of a running gdbserver

            binary (str, ELF, EXE, optional): Specify binary or path to the binary being debugged if the information is not included in the context or the target.
            env (dict, optional): Dictionary of environment variables to use instead of the on from the system. Default to None.
            aslr (bool, optional): Enable ASLR. Default to True.
            script (str, optional): Optional gdbscript to execute every time the debugger is launched.
                Use it only to setup things you always want present, but please don't run commands
                and never ever call continue form it.
            from_start (bool, optional): Start debugging from the first instruction of the binary with gdb.debug or first start it and then attach to it.
                Usually you would want to always have it to True, and if you want to skip the first part of the code use debug_from instead, but you are free.
                (Set it to False if you are attaching to a process that has already been running.) Default to True.
            debug_from (int, optional): Start debugging only from this specific address. Useful to bypass anti debug checks except checks for code tampering.
                If you need to interact with the process before it will reach the given address look instead at the method .debug_from(address). Default to None.
            timeout (float, optional): Time (s) to wait when using debug_from between two attempts at reattaching to the process. Default to O.5s.
            from_entry (bool, optional): Let the debugger continue until the entry point of the program if we start instead in the loader.
                This is useful to make absolutely sure the libc will be always available from the beginning so that for example we can set breakpoints in it. Default to True.
            silent (bool, optional): Enable pwntools default logs when starting a process. Default to True.
        """
        if DEBUG: _logger.debug("debugging %s using arch: %s [%dbits]", target if binary is None else binary, context.arch, context.bits)

        self._init_state(script=script, silent=silent, download=download, qemu_gdbserver=qemu_gdbserver)
        self.ptrace = PtraceEmulator(self)

        if args.REMOTE or context.noptrace:
            self.debugging = False
            self.local_debugging = False
            self.children = defaultdict(lambda: self) # Is this necessary ? If it's just for split we could change that function to return self
        else:
            self.debugging = True

        if args.ASLR:
            aslr = True

        self._exe = identify_executable(target, binary)
        self._ensure_context()

        # The idea was to let gdb interrupt only one inferior while letting the other one run, but this doesn't work [29/04/23]
        #script = "set target-async on\nset pagination off\nset non-stop on" + script

        if isinstance(target, tuple):
            self._attach_gdbserver_target(target, script)

        elif isinstance(target, int):
            self.p = None
            self.pid = target
            self.gdb = self._backend_of(GdbBackend).attach(target, exe=self._exe, gdbscript=script)

        elif isinstance(target, process):
            self.p = target
            self.gdb = self._backend_of(GdbBackend).attach(target, exe=self._exe, gdbscript=script)

        elif args.REMOTE:
            self.p = None

        else:
            self._start_local_target(target, env=env, aslr=aslr, from_start=from_start, script=script)

        if isinstance(self.p, process):
            self.pid = self.p.pid # Under qemu this is the pid of qemu, but it is good enough to read /proc/pid/maps

        self._init_logger()
        self._resolve_missing_executable()
        self._register_libraries()

        self._initialized = True
        if self.debugging:

            self._backend_of(GdbBackend).setup()
            # TODO: find the best place for this line
            if self._exe is not None: self.space.set_range(self._exe)

            if debug_from is not None:
                self._blocking_debug_from(debug_from, timeout=timeout, script=script)
            if from_entry:
                self._run_to_entry()

    ########################## CONSTRUCTION STEPS ##########################

    def _ensure_context(self) -> None:
        "Give pwntools' context the architecture of the executable if the script didn't set one"
        # NOTE: What happens when the user want's to debug different processes in the same script ? This may break when using a mix of architectures. [05/02/25]
        # Ensure that a context is defined. Must be set before running gdb to make sure to use the emulator if needed.
        if not context.copy().get("arch", False): # Empty context
            if self._exe is not None:
                # Setting context.binary was somehow leaking fds. They wouldn't get closed
                context.update(arch=self._exe.arch, bits=self._exe.bits, endian=self._exe.endian)
                log.info(f"context not set... Using {context}")
                self._context_params = context.copy()
            else:
                log.warn_once("No context set and no binary given. We recommend setting context.binary at the beginning of your script.")

    def _init_logger(self) -> None:
        "Create self.logger, named after the pid (\"Remote Debugger\" when there is none)"
        if self.pid is not None:
            self.logger = logging.getLogger(f"Debugger-{self.pid}")
        else:
            self.logger = logging.getLogger(f"Remote Debugger")
        self.logger.addHandler(ch)
        self.logger.setLevel(_logger.level)

    def _find_executable(self) -> Path | None:
        "Path of the executable of the process according to gdb's `info proc`, None if gdb doesn't report one"
        for line in self.execute("info proc").splitlines():
            if line.startswith("exe = "):
                file_name = line.split("'")[1]
                return Path(file_name)
        else:
            unexpected("can not find executable.", log) # Should be an error, but I don't want to break the debugger.
            return None

    def _resolve_missing_executable(self) -> None:
        "Without a binary, find the executable through gdb and load a local copy of it (see local_path)"
        # I wanted to move it inside _attach_gdb, but we don't have self.gdb defined yet to call download so I prefer to keep it here instead of assigning self.gdb inside the attach function [09/05/25]
        # What are the cases where _exe is None ? tuple or list without binary. So this can be either a local or remote process.
        # We will allow for not to not have a binary if we are debugging remotely, but it's not guaranteed to stay this way [17/10/26]
        if self._exe is None:
            if not self.local_debugging:
                log.warn_once("No file specified! What are we debugging ?")
            exe_path = self._find_executable()
            if exe_path is not None: # This should never fail
                local_path = self.local_path(exe_path)
                if local_path is not None: # This is already raising a warning if it fails
                    self._exe = EXE(local_path, checksec=False)
                    #self._exe = identify_executable(local_path)
                    if DEBUG: self.logger.debug("found executable: %s -> %s", exe_path, local_path)
                else:
                    unexpected(f"can not find copy of {exe_path}", log)

    def _register_libraries(self) -> None:
        "Record the libraries the executable needs, so that dbg.<name> (dbg.libc...) finds them once they are loaded"
        # TODO test with programs using dlopen
        if self._exe is not None and not self._exe.statically_linked:
            # This returns the names, but has no information on the path (compared to libs that has the exact path)
            # The problem with dbg.lib_name is that some names have version numbers such as libc-2.28.so
            # I will store the full name in libraries to make sure that we don't have conflicts when downloading multiple versions from different programs, but allow to access with a partial name
            libraries = enum_libs(self._exe)
            for library_name in libraries:
                self.space._libraries[library_name] = None

            for symbol_name in self._exe.plt:
                if (symbol := self._exe.symbols.get(symbol_name, None)) is not None:
                    del symbol

    # NOTE: Start debugging from a specific address. Wait timeout seconds for the program to reach that address. Is blocking so you may need to use context.Thread() in some cases
    # NOTE: WARNING don't use 'continue' in your gdbscript when using debug_from ! [17/04/23]
    # NOTE: I don't like that this is blocking, so you can't interact while waiting... Can we do it differently ? [17/04/23]
    def _blocking_debug_from(self, debug_from: int | str, *, timeout: float, script: str) -> None:
        """
        Debugger(debug_from=): write a sleep loop at debug_from, let the process run without gdb, and attach again every
        `timeout` seconds until the process is in the loop; then restore the code and continue from debug_from under gdb.
        """
        # NOTE: I can't attach again to the process if we are under an emulator
        assert context.native, "debug_from isn't supported in qemu"
        address_debug_from = self._parse_address(debug_from)
        backup = self.inject_sleep(address_debug_from)
        while True:
            self.detach()
            sleep(timeout)
            # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
            self.gdb = self._backend_of(GdbBackend).attach(self.pid, exe=self._exe, gdbscript=script) # P is gdbserver...
            self._backend_of(GdbBackend).setup()
            if self.instruction_pointer - address_debug_from in range(0, len(backup)): # I'm in the sleep shellcode
                self.write(address_debug_from, backup)
                self.jump(address_debug_from)
                break
            else:
                log.warn(f"{timeout}s timeout isn't enough to reach the code... Retrying...")

    def _run_to_entry(self) -> None:
        "Debugger(from_entry=True): if the process stopped in the loader, continue until the entry point of the exe"
        # This is here to have the libc always available [06/01/25]
        # self.instruction_pointer != self._exe.entry: May not have a loader and libc, but still be considered dynamically linked
        if self._exe is not None and not self._exe.statically_linked and self.ld is None:
            log.warn_once(f"{self._exe.name} is not marked as statically linked, but I can not find a loader!")
        elif self._exe is not None and self.ld is not None and self.instruction_pointer in self.ld:
            if not context.native:
                log.warn_once("Debugging from entry may fail with qemu. In case set Debugger(..., from_entry = False)")
            try:
                address = self._exe.entry
            except Exception:
                log.warn_once("Failed finding elf base address. Disabling from_entry...")
                return
            self.until(address)

    ########################## ATTRIBUTES ##########################

    def __getattr__(self, name: str) -> Any:
        # getattr is only called when an attribute is NOT found in the instance's dictionary
        # In the case of ./script.py REMOTE, if .remote() is not called we also return False because p hasn't been defined yet. Maybe that can be confusing ? [16/04/25]
        if name == "_initialized": #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self._registers in __setattr__
            return False

        if name in self._special_registers + self._registers + self._minor_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                res = 0
            else:
                res = self._backend.read_register(name)
            return res
        elif name in self._long_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                return 0
            else:
                return self._backend.read_long_register(name)
        elif (library_name := self.space.library_fullname(name)) is not None:
            with context.silent:
                library = self.libraries[library_name]
            if library is None and not self.debugging:
                log.error(f"I don't know the path to the {name} you want to use! Please set dbg.{name} = ELF(\"/path/to/lib\")")
            return library
        elif self.p and hasattr(self.p, name):
            return getattr(self.p, name)
        # May want to also expose in case you want to access something like inferiors() 
        elif self.gdb is not None and hasattr(self.gdb, name):
            return getattr(self.gdb, name)
        elif self.libdebug is not None and hasattr(self.libdebug, name):
            return getattr(self.libdebug, name)
        elif self.new_libdebug is not None and hasattr(self.new_libdebug, name):
            return getattr(self.new_libdebug, name)
        else:
            # Get better errors when can't resolve properties
            self.__getattribute__(name)

    # Consider checking if the value is an instance of ELF and in case look for the base address. This is useful when we need other libraries than libc. [11:45] 
    @context_decorator
    def __setattr__(self, name: str, value: Any) -> None:
        if not self._initialized:
            super().__setattr__(name, value)
        elif name in self._special_registers + self._registers + self._minor_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                return
            self._backend.write_register(name, value)
        elif name in self._long_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                return
            self._backend.write_long_register(name, value)
        elif (library_name := self.space.library_fullname(name)) is not None:
            self.space._libraries[library_name] = value # Allow to overwrite libraries (In case of remote path)
        else:
            super().__setattr__(name, value)

    def __repr__(self) -> str:
        # I'm afraid it may crash if used with remote [17/11/23]
        
        if (text := self._backend.repr()) is not None:
            return text

        if self.pid is None:
            return super().__repr__()

        if self.control.closed.is_set():
            msg = "<exited>"
        elif not self.debugging:
            msg = "<not debugged>"
        elif self.running:
            msg = "<running>"
        else:
            msg = f"<not running> {hex(self.instruction_pointer)}:{self.next_inst.toString()} [{self._stop_reason}]"
        return "Debugger [{:d}] {:s}".format(self.pid, msg)

    def __dir__(self) -> list[str]:
        return object.__dir__(self) + self._special_registers + self._registers + self._minor_registers

    def __enter__(self) -> Debugger:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
        # We should also close all children I think [17/11/23]
        for child in self.children.values():
            child.close()
