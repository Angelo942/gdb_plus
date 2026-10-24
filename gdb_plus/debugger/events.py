from __future__ import annotations

from queue import Queue
from typing import TYPE_CHECKING

from elftools.elf.sections import SymbolTableSection
from pwn import context, log

from gdb_plus.utils import DEBUG, SIGNALS, SIGNALS_from_num, function_calling_convention, describe_syscall
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, context_decorator

if TYPE_CHECKING:
    from typing import Callable, Sequence
    from gdb_plus.debugger.debugger import Debugger

class EventsMixin(DebuggerBase):
    """
    Signals (handle_signal, signal), gdb catchpoints on syscalls and events (catch_syscall, catch_event), and the
    tracers built on them: set_strace, set_ltrace, set_ftrace.
    """
    def handle_signal(self, signal: int | str, callback: Callable[[Debugger], bool | None]) -> None:
        if isinstance(signal, str):
            signal = signal.upper()
        else:
            signal = SIGNALS_from_num[signal]
        self._backend.handle_signal(signal)
        self.control.handled_signals[SIGNALS[signal]] = callback

    def signal(self, n: int | str, /, *, handler: int | str | None = None, step: bool = False, timeout: float | None = None) -> Debugger:
        """
        Send a signal to the process and put and break returning from the handler
        Once sent the program will jump to the handler and continue running therefore We set a breakpoint on the next instruction before sending the signal.
        (If no handler is defined by the program remember that the process will die)
        You can put breakpoints in the handler and debug it as you please, but remember that there will always be a breakpoint when you return from the handler

        Parameters
        ----------
        n : INT or STRING
            Name or id of the signal.
        handler : POINTER, optional
            USE ONLY IF SIGNAL WILL MODIFY THE NEXT INSTRUCTION AND YOU CAN'T USE A HARDWARE BREAKPOINT
            Pointer to the last instruction of the signal handler. Will be used to set a breakpoint after the code has been modified
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self

        self.control.priority.check_can_resume("signal")

        # To send a signal ptrace has to resume the execution of the process so we put a breakpoint and wait for the handler to finish executing
        # If the code is self modifying you must use handler otherwise the breakpoint will be overwritten with bad code [26/02/23]
        # Now a hardware breakpoint should be enough, but I keep the handler if you don't have enough breakpoints. [30/07/23]
        if handler is None:
            #self.b(self.instruction_pointer, temporary=True, user_defined=False)
            # TODO warn if hw fails
            self.b(self.instruction_pointer, temporary=True, user_defined=False, hw=True)
        else:
            my_address = Queue()
            my_address.put(self.instruction_pointer)
            def callback(dbg: Debugger) -> bool:
                address = my_address.get()
                my_address.put(dbg.instruction_pointer)
                dbg.b(address, temporary=True, user_defined=False)
                return False  
            self.b(handler, callback=callback, temporary=True, user_defined=False)
        self._backend.signal(n, step, timeout)

        return self

    # We could do better regarding the num, like using the stop event to know which breakpoint we hit, but we'll think about it later [25/07/23]
    # Do we want a single callback per breakpoint or allow a list ?
    @context_decorator
    def catch_syscall(self, name: str, callback: Callable[[Debugger, bool], bool | int | None] = lambda dbg, entry: True) -> Debugger | None:
        """
        the callback must have the following form:
        def callback(dbg, entry):
            if entry:
                <code to execute when the syscall is called>
                <return SKIP_SYSCALL if should not call the syscall>
                <return SKIP_SYSCALL | True if should not call the syscall and stop>
            else:
                <code to execute when the syscall returns>
                <return False if should not stop after the syscall>

        If you decide to skip the syscall remember to set the right return value
        A catchpoint doesn't fire if you step
        """
        if context.arch in ["riscv32", "riscv64"]:
            log.warn_once("catch syscall not supported for RISCV")
            return None

        return self.catch_event("syscall " + name, callback)

    handle_syscall = catch_syscall

    def delete_catch_syscall(self, name: str) -> Debugger | None:
        return self.delete_catch("syscall " + name)

    # If you allow multiple callbacks on the same event you have to figure out a way to delete a specific catchpoint from the callback itself (ex ptrace detection) [18/01/25] 
    def catch_event(self, name: str, callback: Callable[..., bool | int | None] = lambda *args, **kwargs: True) -> Debugger:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self
        
        if self.gdb is None:
            raise Exception("not implemented in libdebug")

        # To avoid multiple breakpoints for the same syscall which may break my way of handling them [27/07/23]
        if name in self.control.event_table:
            log.warn("there is already a catchpoint for %s... Overwriting...", name)
            self.control.event_breakpoints[self.control.event_table[name]] = callback
        else:
            self.execute(f"catch {name}")
            # In old versions of gdb (bug found in ubuntu 20.4) breakpoints() only return the breakpoints, not the catchpoints. 27/04/24
            #num = self.gdb.breakpoints()[-1].number
            data = self.execute(f"info breakpoints").splitlines()
            for i in range(len(data)):
                try:
                    num = int(data[-i - 1].split()[0])
                    break
                except:
                    continue
            if DEBUG: self.logger.debug("setting catchpoint %s: %d", name, num)
            self.control.event_table[name] = num
            self.control.event_breakpoints[num] = callback

        return self

    catch = catch_event

    def delete_catch(self, name: str) -> Debugger | None:

        if DEBUG: self.logger.debug("deleting catchpoint %s", name)
        try:
            bp = self.control.event_table.pop(name)
        except KeyError:
            log.warn("%s is not being caught", name)
            return
        self.control.event_breakpoints.pop(bp)
        self.execute(f"delete {bp}")
        return self

        
    # Be careful about the interactions between finish and other user breakpoints
    # TODO print ascii strings instead of pointer
    @context_decorator
    def set_ftrace(self, *, calling_convention: list[str] | None = None, n_args: int = 3, no_return: bool = False, custom_callback: Callable[[Debugger, str], bool | None] | None = None, exclude: Sequence[str] = []) -> Debugger:
        """
        Can not always read the return value because some "functions" may not return but jump to another function. Use no_return in case of problem 
        """
        if calling_convention is None:
            calling_convention = function_calling_convention[context.arch]
        symtab = self._exe.get_section_by_name(".symtab")
        if not isinstance(symtab, SymbolTableSection):
            log.warn("Can not find symbols. If you added them yourself to the binary please raise an issue.")
            return self
        with log.progress("looking for functions in elf.symbols") as prog:
            for idx, symbol in enumerate(symtab.iter_symbols()):
                if symbol.name in exclude:
                    continue
                prog.status(f"{idx+1}/{symtab.num_symbols()}")
                if symbol.entry["st_info"]["type"] != "STT_FUNC":
                    continue
                address = self._exe.symbols.get(symbol.name, None)
                # is in the plt
                if address is None:
                    continue
                if custom_callback is None:
                    def callback(dbg: Debugger, name: str = symbol.name) -> bool:
                        print(f"{name}{[hex(getattr(dbg, calling_convention[i])) for i in range(n_args)]}")
                        if not no_return:
                            dbg.finish()
                            print(f"{name} -> {hex(dbg.return_value)}")
                        return False
                else:
                    callback = lambda dbg, name = symbol.name: custom_callback(dbg, name)
                bp = self.b(address, callback=callback, user_defined=False)
                self._ftrace_breakpoints.append(bp)
        return self

    def disable_ftrace(self) -> None:
        for bp in self._ftrace_breakpoints:
            self.delete_breakpoint(bp)

    # Be careful about the interactions between finish and other user breakpoints [31/07/24]
    # In particular consider skipping ptrace and wait functions if ptrace is emulated and we decide to move the breakpoints from the libc to the plt. [01/08/24]
    @context_decorator
    def set_ltrace(self, *, calling_convention: list[str] | None = None, n_args: int = 3, no_return: bool = False, exclude: Sequence[str] = []) -> Debugger:
        if self._exe.statically_linked:
            log.warn("The binary does not use libraries!")
            return self

        if calling_convention is None:
            calling_convention = function_calling_convention[context.arch]
        for name, address in self._exe.plt.items():
            if name in exclude:
                continue
            def callback(dbg: Debugger, name: str = name) -> bool: # Needed to save the correct name
                # TODO consider using a kind of context.calling_convention and use dbg.args here [32/07/24]
                print(f"{name}{[hex(getattr(dbg, calling_convention[i])) for i in range(n_args)]}", end=" ")
                if not no_return:
                    dbg.finish()
                    print(f"-> {hex(dbg.return_value)}")
                return False
            bp = self.b(address, callback=callback, user_defined=False)
            self._ltrace_breakpoints.append(bp)
        return self

    def disable_ltrace(self) -> None:
        for bp in self._ltrace_breakpoints:
            self.delete_breakpoint(bp)

    # I hate having to write so much code for the styling...
    @context_decorator
    def _describe_syscall(self) -> tuple[str, list[int], str]:
        """Read the registers of the syscall the process just entered.
        Returns (name, raw argument values, 'name(arg=value, ...)')."""
        name, call = describe_syscall(self.sys_num, self.syscall_args[:], self.safe_read, self.read_string)
        return name, self.syscall_args[:], call

    @context_decorator
    def set_strace(self, *, exclude: list[str] | None = None, only: list[str] | None = None) -> Debugger:
        def callback(dbg: Debugger, entry: bool) -> bool:
            name, values, call = self._describe_syscall()
            to_log = (only is not None and name in only) or (only is None and (exclude is None or name not in exclude))
            if entry:
                # Careful to not block. We can check the pipe on local programs, but I doubt we can call a syscall from here
                # to check it on a remote gdb_server [11/10/26]
                # TODO We still need to handle read even if we don't log.
                if to_log:
                    print(f"{self.instruction_pointer:#x}: {call}", end="", flush=True)
            else:
                if to_log:
                    # Could style it more
                    print(f" = {dbg.return_value}")
            return False

        self.catch_syscall("", callback)
        return self
