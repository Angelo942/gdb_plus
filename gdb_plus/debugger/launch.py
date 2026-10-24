from __future__ import annotations

from threading import Event
from typing import TYPE_CHECKING

from pwn import ELF, args, context, gdb, log, process, remote, sleep
from pwnlib.exception import PwnlibException

from gdb_plus.utils import DEBUG
from gdb_plus.debugger.engines import GdbBackend
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, context_decorator, GdbDiedError

if TYPE_CHECKING:
    from typing import Callable
    from gdb_plus.debugger.debugger import Debugger
    from gdb_plus.debugger._base import P, R

class LaunchMixin(DebuggerBase):
    """
    Start the process or attach to it (a file, a pid, a pwntools process, a gdbserver, qemu-user, the REMOTE
    target), and release it: detach(), close(). Also debug_from() and execute(), the raw gdb command.
    """
    def _attach_gdbserver_target(self, target: tuple[str, int], script: str) -> None:
        if len(target) != 2:
            raise ValueError("What are you trying to do ? tuples (host, port) are only for connections to a gdbserver")

        self.p = None
        self.local_debugging = False

        self.gdb = self._backend_of(GdbBackend).attach(target, exe=self._exe, gdbscript=script)


        # Obtaining the inferior's PID may fail when the target is remote,
        # particularly when QEMU is involved.
        try:
            pid = self.current_inferior.pid
        except Exception:
            pid = None

        if pid not in (None, 1, 42000):
            self.pid = pid

        elif self.gdbserver_qemu is None:
            log.warn_once(
                "If you want to debug a remote program under QEMU, "
                "please also debug QEMU itself and pass the debugger "
                "as gdbserver_qemu=..."
            )
            log.warn_once(
                "I will not be able to access information about the "
                "memory layout and libraries used."
            )

    def _start_local_target(self, target: str | ELF | list[str], *, env: dict[str, str] | None, aslr: bool, from_start: bool, script: str) -> None:
        exe = self._exe

        if isinstance(target, list):
            command = target
        else:
            assert exe is not None, "Something went wrong finding the executable"
            command = exe.path

        # Mode 1: Run without tracing.
        if context.noptrace:
            self.p = self._silence(process, command, env=env, aslr=aslr)
            return

        # Mode 2: Start the program under GDB.
        if from_start:
            try:
                if not context.native and context.os != "baremetal":
                    self.p = self._silence(self._debug_under_qemu, command, env=env, gdbscript=script)
                else:
                    self.p = self._silence(gdb.debug, command, env=env, aslr=aslr, gdbscript=script, api=True)
            except PwnlibException:
                if not context.native:
                    log.error(f"Could not debug program for {context.arch}. Did you install qemu-user?")
                raise

            self.gdb = self.p.gdb

            # GDB can start without successfully debugging the target when
            # gdb-multiarch is unavailable for a non-native architecture.
            if not context.native:
                try:
                    self.execute("info tasks")
                except Exception:
                    log.error(
                        "You need to install gdb-multiarch "
                        "to debug binaries under qemu!"
                    )

            return

        # Mode 3: Start the process first and attach GDB afterwards.
        self.p = self._silence(process, command, env=env, aslr=aslr)
        self.gdb = self._backend_of(GdbBackend).attach(self.p, exe=exe, gdbscript=script)

    
    # We may want to also directly debug qemu since we are already controlling it. [19/10/26]
    def _debug_under_qemu(self, command: str | list[str], *, env: dict[str, str] | None, gdbscript: str) -> process:
        """
        gdb.debug(command, api=True) for a foreign architecture: start `qemu-<arch> -g <port>` and attach gdb to its
        gdbstub, without waiting for a gdbserver banner that qemu never prints.
        """
        import socket
        from pwnlib import qemu
        from pwnlib.util.misc import which

        argv = [command] if isinstance(command, (str, bytes)) else list(command)
        exe = which(argv[0] if isinstance(argv[0], str) else argv[0].decode())
        if not exe:
            log.error(f"Could not find executable {argv[0]!r}")
        qemu_user = qemu.user_path()
        if not qemu_user:
            log.error(f"Cannot debug {context.arch} binaries without appropriate QEMU binaries")
        sysroot = qemu.ld_prefix(env=env)

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        qemu_args = [qemu_user, "-g", str(port)]
        if sysroot:
            qemu_args += ["-L", sysroot]

        emulator = process(qemu_args + argv, env=env, aslr=True)
        emulator.executable = exe
        # qemu may not listen yet: gdb's `target remote` retries a refused connection (tcp auto-retry, on by default)
        _, emulator.gdb = gdb.attach(("127.0.0.1", port), exe=exe, gdbscript=gdbscript, sysroot=sysroot, api=True)
        return emulator

    @context_decorator
    def debug_from(self, location: int | str, *, event: Event | None = None, timeout: float = 0.5) -> Debugger | None:
        """
        Alternative debug_from which isn't blocking.
        call dbg.debug_from_done.wait() to know when to continue.

        event: optional event to signal that you have finished the actions you needed to perform. Otherwise a timeout will be used (default: 0.5s)
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            self.debug_from_done.set()
            return

        if not context.native:
            log.error("debug_from is not supported under QEMU")

        address = self._parse_address(location)

        def action() -> None:
            backup = self.inject_sleep(address)
            while True:  
                self.detach()
                if event is not None:
                    event.wait()
                    if DEBUG: self.logger.debug("user finished interaction. Proceeding with debug_from")
                else:
                    log.warn_once("you haven't set an event to let me know when you finished interacting with the process. I will give you half a second.")
                    sleep(timeout)
                # Maybe the process is being traced and I can't attach to it yet
                try:
                    # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
                    self.gdb = self._backend_of(GdbBackend).attach(self.p.pid, exe=self._exe, gdbscript=self.gdbscript) # P is gdbserver...
                except Exception as e:
                    if DEBUG: self.logger.debug("can't attach in debug_from because of %s... Retrying...", e)
                    continue
                self._backend_of(GdbBackend).setup()
                if self.instruction_pointer - address in range(0, len(backup)): # I'm in the sleep shellcode
                    self.write(address, backup)
                    self.jump(address)
                    self.debug_from_done.set()
                    break
                else:
                    log.warn(f"{timeout}s timeout isn't enough to reach the code... Retrying...")
        context.Thread(target=action, name=f"[{self.pid}] debug_from", daemon=True).start()
        return self

    # Still useful for cases where we don't have the binary to locate the entry point.
    # Especially when you are using a specific loader!
    def load_libc(self) -> Debugger:
        """
        Continue until the program has loaded the libc. Needed before setting breakpoints on libc functions.
        """
        self.catch("load")
        while self.libc is None:
            self.c()
        self.delete_catch("load")

        return self

    # Use as : dbg = Debugger("file").remote(IP, PORT)
    def remote(self, host: str, port: int) -> Debugger:
        """
        Define the connection to use when the script is called with argument REMOTE.
        """
        self._host = host
        self._port = port
        if args.REMOTE:
            self.p = self._silence(remote, host, port)
        return self

    setup_remote = remote

    def connect(self, *, overwrite: bool = True) -> Debugger:
        """
        Connect to remote server while keeping debugger active.
        if overwrite is False self.p will be preserved and the connection will be saved on self.r instead.
        """
        if self._host is None:
            raise Exception("host not set!")

        if overwrite:
            self._backup_p = self.p # Just make sure the connection doesn't die
            self.p = remote(self._host, self._port)
        else:
            self.r = remote(self._host, self._port)

        return self

    def detach(self, quit: bool = True, block: bool = False) -> None:
        """
        Detaches the debugger from the currently running process.

        Args:
            quit (bool, optional): If True, the program is terminated after detaching. Defaults to True.
            block (bool, optional): If True, prevent the process from continuing the execution when the debugger is not attached. Defaults to False.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        # Must be stopped
        try:
            self.interrupt()
        except:
            if DEBUG: self.logger.debug("process has already stopped")
        self._detached = True

        self._backend.detach(quit, block)

    # TODO set option to kill child processes ? [05/08/24]
    # TODO make sure it works when inside a read [16/04/25]
    def close(self) -> None:
        """
        Close process and debugger.
        Doesn't kill child processes.
        """

        self.detach(quit=True)
        # Yah, I should do it here, but I close the terminal in detach, so let's handle it there.
        #except:
        #    if DEBUG: self.logger.debug("can't detach because process has already exited")
        # Can't close the process if I just attached to the pid
        if self.p:
            self._silence(self.p.close)
        if self.r is not None:
            self._silence(self.r.close)
        if self._backup_p is not None:
            self._silence(self._backup_p.close)
        
        self._backend.close()

    def _silence(self, fun: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
        if self.silent:
            with context.silent:
                return fun(*args, **kwargs)
        else:
            return fun(*args, **kwargs)

    # Now we may have problems if the user try calling it...
    # should warn to use execute_action and wait if they are doing something that will let the process run
    def execute(self, code: str) -> str:
        """ 
        Execute a gdb command that does NOT require a wait later.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return ""

        if self._backend.died:
            raise GdbDiedError(f"GDB died. Can not execute {code!r}")
        
        return self.gdb.execute(code, to_string=True)

        
    # I want a function to restart the process without closing and opening a new one
    # Not working properly
    # Can use elf.entry to find entry point
    def reset(self, argv: list[str] | None = None, reload_elf: bool = False) -> None:
        ...
