from __future__ import annotations

from typing import TYPE_CHECKING

from pwn import context, log

from gdb_plus.utils import DEBUG
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, NEEDS_LOCAL_PROCESS, context_decorator
from gdb_plus.debugger.engines import Backend, GdbBackend, LibdebugBackend, NewLibdebugBackend

if TYPE_CHECKING:
    from typing import Any
    from pwnlib.gdb import Gdb
    from libdebug.debugger.debugger import Debugger as NewLibdebugDebugger
    from libdebug_legacy import Debugger as LegacyLibdebugDebugger
    from gdb_plus.debugger.debugger import Debugger

class BackendsMixin(DebuggerBase):
    """
    The engines behind the Debugger: set up gdb, legacy libdebug or new libdebug on the attached process (the
    threads that wait for its stops, gdb's options, the watchdog that notices when gdb dies), and migrate() from one
    engine to another.
    """
    def _backend_of(self, kind: type[Backend]) -> Backend:
        """
        The backend of one engine, whichever is attached: for the code that names its engine, such as the setup of an
        engine just attached, or migrate(). Created on first use and kept in self._backends.
        """
        if (backend := self._backends.get(kind)) is None:
            backend = self._backends[kind] = kind(self)
        return backend
    def _set_engine(self, kind: type[Backend], handle: Any) -> None:
        """
        Store the handle of an engine in its backend: the setters of gdb, libdebug and new_libdebug. Setting a handle
        attaches that engine (self._backend); setting the handle of the attached engine to None leaves the Debugger
        without one.
        """
        backend = self._backend_of(kind)
        backend.handle = handle
        if handle is not None:
            self._backend = backend
        elif self._backend is backend:
            self._backend = self._backend_of(Backend)
    @property
    def gdb(self) -> Gdb | None:
        """The gdb attached to the process (pwntools' Gdb, through rpyc), None with another engine"""
        return self._backend_of(GdbBackend).handle
    @gdb.setter
    def gdb(self, handle: Gdb | None) -> None:
        self._set_engine(GdbBackend, handle)
    @property
    def libdebug(self) -> LegacyLibdebugDebugger | None:
        """The legacy libdebug attached to the process, None with another engine"""
        return self._backend_of(LibdebugBackend).handle
    @libdebug.setter
    def libdebug(self, handle: LegacyLibdebugDebugger | None) -> None:
        self._set_engine(LibdebugBackend, handle)
    @property
    def new_libdebug(self) -> NewLibdebugDebugger | None:
        """The new libdebug attached to the process, None with another engine"""
        return self._backend_of(NewLibdebugBackend).handle
    @new_libdebug.setter
    def new_libdebug(self, handle: NewLibdebugDebugger | None) -> None:
        self._set_engine(NewLibdebugBackend, handle)

    # È già successo che wait ritorni -1 e crashi libdebug [08/05/23]
    # Legacy callbacks won't be transferred over... It's really time to get rid of them [21/05/23]
    # BUG migrating back to gdb while emulating ptrace hangs because the program thinks the interrupt should be handled by waitpid [19/11/23]
    @context_decorator
    def migrate(self, *, gdb: bool = False, libdebug: bool = False, new_libdebug: bool = False, script: str = "") -> Debugger | None:
        """
        Switch the debugger being used on the backend. Current options are gdb and libdebug.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if not self.local_debugging:
            log.error(NEEDS_LOCAL_PROCESS.format("migrate()"))
        assert context.native, "migrate isn't supported in qemu"

        # Maybe put a try except to restore the backup in case of accident [06/06/23]
        if gdb:
            assert self.gdb is None
            self.detach(block=True)
            if DEBUG: self.logger.debug("migrating to gdb")
            self.libdebug = None
            self._detached  = False
            self.gdb = self._backend_of(GdbBackend).attach(self.pid, exe=self._exe, gdbscript=script)
            self._backend_of(GdbBackend).setup()
            # Catch SIGSTOP
            address = self.instruction_pointer
            
            # While ptrace is emulated the stop handlers give the signal stops to the tracer's waitpid: these steps must return here
            with self.ptrace.suspended(), context.silent:
                self.step(repeat=4)

            if address != self.instruction_pointer:
                log.warn("I made a mistake trying to catch the SIGSTOP after attaching with gdb")
            # I must get back before setting the breakpoints otherwise I may overwrite them
            for address in self.control.breakpoints:
                for breakpoint in self.control.breakpoints[address]:
                    bp = self._backend.native_breakpoint(address)
                    breakpoint.native_breakpoint = bp.server_breakpoint
        elif libdebug:
            assert not self.ptrace.syscall, "libdebug can't catch ptrace syscall. Emulate with syscall = False"
            if self.control.event_breakpoints:
                log.warn_once("you will lose all your syscall catchpoints!")
            try:
                from libdebug_legacy import Debugger as lib_Debugger
            except ImportError as e:
                print("libdebug_legacy is not installed")
                print("you can install it with: pip3 install git+https://github.com/Angelo942/libdebug.git")
                raise
            # Disable hook stop
            assert self.libdebug is None
            assert self.gdb is not None
            self.gdb.events.exited.disconnect(self.control.exit_handler)
            self.detach(block=True)
            if DEBUG: self.logger.debug("migrating to libdebug")
            self.gdb = None
            self._gef = False
            self._pwndbg = False
            self._detached  = False
            self.libdebug = lib_Debugger(multithread=False)
            counter = 0
            while not self.libdebug.attach(self.pid, options=False):
                if counter == 3:
                    log.error("Could not connect to libdebug")
                log.warn("error attaching with libdebug... Retrying...")
                counter += 1
            assert not self.libdebug.running
            self._backend_of(LibdebugBackend).setup()
            # Catch SIGSTOP
            address = self.instruction_pointer

            with self.ptrace.suspended(), context.silent:
                self.step()

            if address != self.instruction_pointer:
                log.warn("I made a mistake trying to catch the SIGSTOP after attaching with libdebug")
            # TODO Handle hb too 
            for address in self.control.breakpoints:
                for breakpoint in self.control.breakpoints[address]:
                    bp = self._backend.native_breakpoint(address)
                    breakpoint.native_breakpoint = bp
        elif new_libdebug:
            try:
                from libdebug import debugger as lib_Debugger
            except ImportError as e:
                print("libdebug is not installed")
                print("you can install it with: pip3 install libdebug")
                raise
            assert self.libdebug is None
            assert self.new_libdebug is None
            assert self.gdb is not None
            if self.ptrace.emulated:
                log.warn_once("We recommend libdebug over new_libdebug to emulate ptrace")
            self.gdb.events.exited.disconnect(self.control.exit_handler)
            address = self.instruction_pointer
            backup = self.inject_sleep(address) # The new libdebug can not handle the SIGSTOP of detach(block=True)
            self.detach(quit=False)
            self.gdb = None
            self.new_libdebug = lib_Debugger(self._exe.path, kill_on_exit = False)
            self.new_libdebug.attach(self.pid)
            self.write(address, backup)
            self.jump(address)
            self._backend_of(NewLibdebugBackend).setup()

            for address, breakpoints in self.control.breakpoints.items():
                for breakpoint in breakpoints:
                    bp = self._backend_of(NewLibdebugBackend).native_breakpoint(address, hw=breakpoint.hw) # by name: a legacy libdebug migrated from is still in self.libdebug
                    breakpoint.native_breakpoint = bp

            # TODO implement event migration
            if self.control.event_breakpoints:
                log.warn_once("you will lose all your syscall catchpoints!")

        else:
            raise NotImplementedError(f"migrate doesn't support the given debugger")
        return self
