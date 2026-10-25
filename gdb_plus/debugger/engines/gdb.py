from __future__ import annotations

import os
import signal
import weakref
from queue import Queue
from threading import enumerate as enumerate_threads
from typing import TYPE_CHECKING

from pwn import ELF, context, gdb, log, process
from rpyc import BgServingThread

from gdb_plus.utils import DEBUG, PriorityEvent, Interrupted, DoneEvent, set_done_if_panic, Breakpoint, SIGNALS, SIGNALS_from_num
from gdb_plus.debugger._base import SHOULD_STOP, SKIP_SYSCALL, INTERRUPT_HIT_BREAKPOINT, lock_decorator, context_decorator, GdbDiedError, _kill_gdb, _logger
from gdb_plus.debugger.engines.base import Backend

if TYPE_CHECKING:
    from typing import Callable
    from gdb import Inferior, ContinueEvent, RegisterChangedEvent, NewInferiorEvent
    from pwnlib.gdb import Gdb, Breakpoint as GdbBreakpoint
    from gdb_plus.debugger.debugger import Debugger

class GdbBackend(Backend):
    """
    The engine is gdb: dbg.gdb, the gdb process driven through the rpyc connection of pwntools.
    It keeps what only gdb needs: the cache of the registers read since the last stop, the thread that serves the
    connection (watched to notice when gdb dies), and the finalizer that kills gdb when the Debugger goes away.
    """
    def __init__(self, dbg: Debugger) -> None:
        super().__init__(dbg)
        self.died = False
        self._cached_registers: dict[str, int] = {}
        self._server: BgServingThread | None = None # TODO find a better name for the thread
        self._finalizer: weakref.finalize | None = None
    def clear_register_cache(self) -> None:
        self._cached_registers = {}
    def delete_breakpoint(self, breakpoint: Breakpoint) -> None:
        breakpoint.native_breakpoint.delete() # Remove from dict and delete from gdb
    def alloc(self, n: int) -> int:
        dbg = self.dbg
        # Do we wan't to use call for both ? [10/05/23]
        return dbg.gdb_call("malloc", [n])
    def dealloc(self, pointer: int) -> None:
        dbg = self.dbg
        dbg.gdb_call("free", [pointer], cast="void")
    def stopped_pid(self) -> int:
        dbg = self.dbg
        return dbg.current_inferior.pid
    def stop_signal(self) -> int:
        dbg = self.dbg
        reason = dbg._stop_reason
        if reason == "SINGLE STEP":
            return 0x5
        if "BREAKPOINT" in reason:
            return 0x13 # This is wrong SIGSTOP (0x13) -> SIGTRAP (0x5) [20/06/25] TODO Check if anything depends on it.
        else:
            return SIGNALS[reason]
    def running(self) -> bool:
        dbg = self.dbg
        try:
            # We need a command that succeeds when the process exits, but fails when inside a callback [02/05/25]
            # accessing a register fails after we exit
            # info ... succeeds even inside a callback
            # in ubuntu 24 info program succeeds...
            res = dbg.execute("info program")
            return res.strip().endswith("is now running.")
        except:
            return not dbg.control.closed.is_set()
    def internal_wait(self) -> None:
        dbg = self.dbg
        return dbg.gdb.wait()
    def jump(self, address: int, internal: bool = False) -> None:
        # BUG setting rip this way may cause problems with si [30/04/23]
        #self.instruction_pointer = address
        dbg = self.dbg
        if not internal:
            dbg.control.priority.check_can_resume("jump")
        dbg.b(address, temporary=True, user_defined=False)
        event = dbg.execute_action(f"jump *{hex(address)}", sender="jump", internal=internal)
        dbg.control.priority_wait(comment="jump", priority=event)
    # current_inferior is super slow...
    def read_inferior(self, address: int, size: int, *, inferior: Inferior | None = None) -> bytes:

        dbg = self.dbg
        if inferior == None:
            inferior = dbg.current_inferior

        #if DEBUG: self.logger.debug("reading from inferior %d, [pid: %d]", inferior.num, inferior.pid)
        return inferior.read_memory(address, size).tobytes()
    # qemu doesn't allow writing in non writable pages [23/08/24]
    @context_decorator
    def write_inferior(self, address: int, data: bytes, *, inferior: Inferior | None = None) -> None:
        """
        Write `data` at `address` of `inferior` (the current one by default) through gdb.
        Under qemu-user the gdbstub refuses to write a guest page that isn't writable, and qemu write-protects every page
        it has translated code from, so mprotect isn't enough for the code being executed. The bytes of the current
        inferior are then written in the emulator's own memory; only when that isn't accessible (a remote qemu without
        gdbserver_qemu) does it try mprotect.
        """
        dbg = self.dbg
        current = inferior is None or inferior == dbg.current_inferior
        if inferior is None:
            inferior = dbg.current_inferior
        try:
            inferior.write_memory(address, data)
        except Exception as e: #gdb.MemoryError
            if context.native:
                raise
            if current and dbg._write_qemu_host(address, data):
                return
            log.warn_once("QEMU is preventing to write on the page. Changing permissions...") # Warn only once because QEMU will reset the protection at each step and it would spam the user of errors [16/01/25]
            dbg.make_page_rwx(address, len(data))
            inferior.write_memory(address, data)
            log.warn_once("Successfully changed permissions.")
    def write(self, address: int, data: bytes, inferior: Inferior | None, pid: int | None) -> int | None:
        dbg = self.dbg
        if inferior is None and pid is not None:
            inferior = dbg.inferior_from_pid(pid)
        self.write_inferior(address, data, inferior = inferior)
        return address
    def read(self, address: int, size: int, inferior: Inferior | None, pid: int | None) -> bytes:
        """
        Through gdb once the architecture is known (context.arch), through /proc/pid/mem before
        """
        if context.arch:
            return self.read_inferior(address, size, inferior=inferior)
        return super().read(address, size, inferior, pid)
    def kick(self) -> None:
        dbg = self.dbg
        # SIGSTOP is too common in gdb
        if dbg.local_debugging and context.native:
            os.kill(dbg.pid, signal.SIGINT)
        else:
            dbg.execute("interrupt")
    def resume_process(self, step: bool) -> None:
        dbg = self.dbg
        dbg.gdb.execute("si" if step else "continue")
    @set_done_if_panic
    def cont(self, force: bool, wait: bool, done: DoneEvent) -> None:
        # Do I check the address instead ? Like hidden_continue [09/06/23]
        # done is set by set_done_if_panic when the function returns. Until then the continue counts as a task (DoneEvent),
        # also between the step and the continue, when no PriorityEvent is waiting
        dbg = self.dbg
        with dbg.control.action_lock.log("_continue_gdb"):
            dbg.step(force=True)

            if dbg._stop_reason == "RUNNING":
                log.warn("Somehow we think that the process is still running...")
                if DEBUG: dbg.logger.debug(dbg.next_inst)

            elif dbg._stop_reason == "SIGINT":
                if DEBUG: dbg.logger.debug("syscall interrupted by user") # step doesn't return if we are on a read, so calling interrupt() would leave us here with a SIGINT
                # Should we return or not ?

            elif dbg._stop_reason != "SINGLE STEP" and not dbg.control.callback_return_overwritten:
                if "BREAKPOINT" in dbg._stop_reason:
                    if DEBUG: dbg.logger.debug("step in continue already reached the breakpoint")
                else:
                    log.warn(f"unknown interruption! {dbg._stop_reason}")
                return
            event = dbg.execute_action("continue", sender="continue")
        dbg.control.priority_wait(comment="continue", priority=event)
        done.interrupted = (event.reason or "").startswith("interrupted")
    def start_continue(self, force: bool, wait: bool, done: DoneEvent, signal: int) -> None:
        dbg = self.dbg
        # It would be better to close cleanly the thread when we close the debugger, but for now I just set daemon=True to at least not block the script.
        context.Thread(target=dbg.control.priority.inherit(self.cont, done), args=(force, wait, done), name=f"[{dbg.pid}] continue", daemon=True).start()
    @set_done_if_panic
    def continue_until(self, address: int, done: DoneEvent, force: bool, breakpoint: Breakpoint | None = None) -> None:
        #Force = True is not needed since once we step the sigint will be caught and continue won't stop. I disable the warning since the user can do nothing about it [08/05/23]
        #Force = True IS needed if you have a callback on that address... [10/05/23]
        # I will keep the step this way to warn the user
        dbg = self.dbg
        try:
            inner = dbg.cont(wait=False, force=force)
            inner.wait()
            # Should we take into consideration the inferior too ? [29/04/23]

            def has_callback() -> bool:
                for bp in dbg.control.breakpoints[dbg.instruction_pointer]:
                    if bp.callback is not None:
                        return True
                return False

            while dbg.instruction_pointer != address:
                if inner.interrupted:
                    raise Interrupted("continue_until")
                log.warn(f"[{dbg.pid}] stopped at {dbg.reverse_lookup (dbg.instruction_pointer)} for '{dbg._stop_reason}' instead of {dbg.reverse_lookup(address)}")
                if dbg._stop_reason == "BREAKPOINT" and has_callback(): # It would maybe be best to ban return None and force the user to set True or False. [23/01/25]
                    log.warn_once("The process stopped on a breakpoint with callback. If you wanted it to continue remember to make your callback return False")
                else:
                    log.warn_once("I assume this happened because you are using gdb manually. Finish what you are doing and let the process run. I will handle the rest")
                event = dbg.execute_action("", sender="continue just to reset the wait")
                dbg.control.priority_wait(comment="continue_until", priority=event)
                # TODO check that the process didn't exit. [21/10/23]
        except Interrupted:
            # Ended by interrupt(): remove the temporary breakpoint, otherwise it would stop the next action of the script
            dbg._forget_breakpoint(address, breakpoint)
            raise
    def start_continue_until(self, address: int, done: DoneEvent, force: bool, breakpoint: Breakpoint) -> None:
        dbg = self.dbg
        context.Thread(target=dbg.control.priority.inherit(self.continue_until, done), args=(address, done, force, breakpoint), name=f"[{dbg.pid}] continue_until", daemon=True).start()
    def native_breakpoint(self, address: int, legacy_callback: Callable[[Debugger], bool | int | None] | None = None, hw: bool = False) -> GdbBreakpoint:
        # Still needed for hidden breakpoint with return False when you want to also use gdb manually [17/04/23]
        dbg = self.dbg
        if legacy_callback is not None:
            log.warn_once("if your callbacks crash you may not notice it and you have to scroll a bit to find the error messages hidden in the gdb terminal")
            # I don't know yet how to handle the conn if I don't go through self.gdb.Breakpoint so I create the class here :(
            class MyBreakpoint(dbg.gdb.Breakpoint):
                def __init__(_self, address: str, hw: bool) -> None:
                    if hw:
                        super().__init__(address, type=dbg.gdb.BP_HARDWARE_BREAKPOINT)
                    else:
                        super().__init__(address)
                    _self.callback = legacy_callback
                # WARNING IF A TEMPORARY BREAKPOINT DOESN'T STOP IT WON'T COUNT AS HIT AND STAY ACTIVE. May cause problems with the callback if you pass multiple times [26/02/23]
                def stop(_self) -> bool | int:
                    _break = _self.callback(dbg) 
                    if _break is None:
                        return True
                    return _break
            res = MyBreakpoint(f"*{hex(address)}", hw)

        else:
            if hw:
                res = dbg.gdb.Breakpoint(f"*{hex(address)}", type=dbg.gdb.BP_HARDWARE_BREAKPOINT)
            else:
                res = dbg.gdb.Breakpoint(f"*{hex(address)}")
        return res
    def breakpoint(self, address: int, legacy_callback: Callable[[Debugger], bool | int | None] | None, callback: Callable[[Debugger], bool | int | None] | None, temporary: bool, user_defined: bool, hw: bool) -> Breakpoint:
        return Breakpoint(self.native_breakpoint(address, legacy_callback, hw=hw).server_breakpoint, address, callback, temporary, user_defined, hw)
    def saved_ip(self, link_register: str | None) -> int:
        dbg = self.dbg
        stack_frame = dbg.gdb.newest_frame().older()
        if stack_frame is not None and stack_frame.pc() != 0:
            return stack_frame.pc()
        # Fail if call return on __start symbol
        if link_register is not None:
            return getattr(dbg, link_register)
        else:
            return 0
    def step(self, signal: int | str, timeout: float | None, internal: bool) -> tuple[PriorityEvent | None, bool]:
        dbg = self.dbg
        if signal:
            dbg.signal(signal, step=True, timeout=timeout) # This calls step again
            return None, True
        event = dbg.execute_action("si", sender="step", internal=internal, step=True)
        finished = dbg.control.priority_wait(comment="step", priority=event, timeout=timeout)
        return event, finished
    def signal(self, n: int | str, step: bool, timeout: float | None) -> None:
        dbg = self.dbg
        if type(n) is int:
            log.warn_once("Remember that gdb uses a different order for the signals. It is advised to use directly the name of the signal")
        if step:
            dbg.execute(f"queue-signal {n}")
            dbg.step(timeout=timeout)
        else:
            priority = dbg.execute_action(f"signal {n}", sender="signal")
            dbg.control.priority_wait(comment=f"signal {n}", priority = priority)
    def queue_signal(self, n: int) -> None:
        dbg = self.dbg
        # gdb numbers the signals its own way: give it the name. queue-signal 0 discards the signal of the stop
        name = SIGNALS_from_num[n] if n else "0"
        try:
            dbg.execute(f"queue-signal {name}")
        except Exception as e:
            # gdb refuses a signal set to nopass (`handle`), like the ones of emulate_ptrace(signals=...)
            log.warn(f"[{dbg.pid}] gdb can not deliver {name}: {e}")
    def stop_reason(self) -> str:
        dbg = self.dbg
        try:
            res = dbg.execute("info program").splitlines()
        except:
            return "RUNNING" if dbg.running else "NOT RUNNING"
        if not res:
            return "NOT RUNNING"

        for line in res:
            line = line.strip()
            if line.startswith("It stopped with signal "):
                return line.replace("It stopped with signal ", "").split(",", 1)[0]
            if line == "The program being debugged is not being run.":
                return "NOT RUNNING"
            if line == "It stopped at a breakpoint that has since been deleted.":
                return "TEMPORARY BREAKPOINT"
            if line.startswith("It stopped at breakpoint "):
                return "BREAKPOINT"
            if line == "It stopped after being stepped.":
                return "SINGLE STEP"
            if line.endswith("is now running."):
                return "RUNNING"

        return "STOPPED"
    def detach(self, quit: bool, block: bool) -> None:
        dbg = self.dbg
        # They will be lost
        dbg.control.event_breakpoints = {}
        dbg.control.event_table = {}
        self.unwatch()
        dbg.control.kill_threads.set()
        dbg.gdb.stopped.set()

        try:
            if block:
                os.kill(dbg.pid, signal.SIGSTOP)
            dbg.execute("detach")
        except:
            if DEBUG: dbg.logger.debug("process already stopped")
        try:
            dbg.execute("quit") # Doesn't always work if after interacting manually
        except EOFError:
            if DEBUG: dbg.logger.debug("GDB successfully closed")
        if self._finalizer is not None:
            self._finalizer() # In case quit didn't work. Runs only once
            self._finalizer = None
        self._cached_registers = {}
    def stop_splitting(self) -> None:
        dbg = self.dbg
        dbg.execute("set detach-on-fork on")
        #if self.symbols["fork"] in self.breakpoints:
        #    self.breakpoints["fork"].enabled = False
        #    del self.breakpoints["fork"]

        # Will break if not set on before
        dbg.gdb.events.new_inferior.disconnect(dbg.fork_handler)
    def start_splitting(self, interrupt: bool, script: str) -> None:
        dbg = self.dbg
        dbg.execute("set detach-on-fork off")

        # The interrupt may give me problems with continue_until
        def fork_handler(event: NewInferiorEvent) -> None:
            inferior = event.inferior
            pid = inferior.pid        
            #self.to_split.put(pid)
            def split(inferior: Inferior) -> None:
                # Runs in its own HandlerContext, like a stop: interrupt() waits for it, and the stops it delivers go to
                # the action that was running when the fork happened
                stopped = dbg._interrupt_inner()
                log.info(f"splitting child: {inferior.pid}")
                dbg.children[pid] = dbg._silence(dbg._split_child, inferior=inferior, script=script)
                dbg.split.put(pid)
                if not stopped:
                    # Someone else stopped the process and will decide what happens next
                    return
                if interrupt:
                    dbg.control.set_stop("forked")
                elif stopped & INTERRUPT_HIT_BREAKPOINT:
                    # Our interrupt took the stop of a breakpoint: give it to the action waiting for it
                    dbg.control.set_stop("We hit a breakpoint while interrupting the process. Handle it!")
                else:
                    dbg._hidden_continue()

            ## Non puoi eseguire azioni dentro ad un handler degli eventi quindi lancio in un thread a parte
            dbg.control.spawn_handler(split, inferior, name=f"[{dbg.pid}] split_fork", handler_context=dbg.control.priority.open_context("split"))

        dbg.fork_handler = fork_handler
        dbg.gdb.events.new_inferior.connect(dbg.fork_handler)
    def read_register(self, name: str) -> int:
        dbg = self.dbg
        if self.died:
            raise GdbDiedError(f"GDB died. Can not read {name}")
        res = self._cached_registers.get(name, None)
        if res is not None:
            return res
        try:
            reg = dbg.gdb.parse_and_eval(f"${name}")
        except:
            log.warn("error reading register. Retrying...")
            reg = dbg.gdb.parse_and_eval(f"${name}")
        # .bytes is not supported yet in ubuntu 22
        #res = unpack(reg.bytes, "all")
        res = int(reg) & ((1 << reg.type.sizeof * 8) - 1)
        self._cached_registers[name] = res
        return res
    def write_register(self, name: str, value: int) -> None:
        dbg = self.dbg
        if name.lower() in ["eip", "rip", "pc"]:
            # GDB has a bug when setting rip ! [09/06/23]
            dbg.jump(value)
        else:  
            if DEBUG: dbg.logger.debug(" setting %s to %x", name, value)
            # NOTE: a single reference to a gdb.Value of a register can be used to assign the value (no need for modulo). `self.gdb.parse_and_eval(f"${name}").assign(value)`. It would be nice to have only a list of references to all registers and use them, but while they can be used to assign values, you can not read values updated during the execution. [13/08/24]
            # We keep the % to convert types such as pwn.Constant to ints 
            # We did test that it doesn't create problems with negative values on 32 bit registers in 64 bit programs
            dbg.execute(f"set ${name.lower()} = {value % 2**context.bits}")
        # NOTE: Currently setting a register will cause a clear_cache [06/02/25]
        # TODO: Change clear_cache to leave it when we are the one setting a register
        # self._cached_registers[name] = value % 2**context.bits # I can not guarantee that this will be correct
    # We stopped using gdb's implementation of temporary breakpoints so that we can differentiate an interruption caused by my debugger and cause by the manual use of gdb 
    # Event could tell me which breakpoint has been hit or which signal cause the interruption
    # For ptrace emulation if the interruption is caused by a breakpoint, a step or an interrupt we stop the process. Otherwise we let the master decide in waitpid depending on the settings if we should return the control to the user [23/07/23]. This may cause problems though if waitpid is never called
    # Stop handlers run in a normal thread, so they don't have access to the correct context. We could copy it as an object variable, but do we really need it here ? [29/12/23]
    # Yes, to access self.ip! [29/12/23]
    @lock_decorator
    @context_decorator
    def handle_stop(self) -> None:
        """
        Actions that the debugger performs every time the process is interrupted except when exiting
        Handle temporary breakpoints and callbacks
        """
        # Current inferior will change to the inferior who stopped last
        dbg = self.dbg
        ip = dbg.instruction_pointer
        breakpoints = dbg.control.breakpoints[ip]

        if DEBUG: _logger.debug("[%d] stopped at address: %s for %s", dbg.current_inferior.pid, dbg.reverse_lookup(ip), dbg._stop_reason)
            
        # Warn that if a parent has to listen for a signal you must tell your handler to stop the execution [22/07/23]
        # NOTE under ptrace emulation the signal should always be passed first to the parent and we should run the callbacks only if the parent passes it. This means that we should also be careful about hot it's passed back, probably in PTRACE_CONT [20/10/26]
        # NOTE Should we handle PASS / NOPASS from the callback ? Right now the signals are just ignored, right ? 
        if dbg._stop_reason in SIGNALS and SIGNALS[dbg._stop_reason] in dbg.control.handled_signals:
            should_stop = dbg.control.handled_signals[SIGNALS[dbg._stop_reason]](dbg)
            if should_stop == False:
                dbg._hidden_continue()
            else:
                if not dbg.ptrace.take_stop(verbose=True):
                    dbg.control.set_stop(f"signal {dbg._stop_reason} handled")
            return  

        # We could also pass the stop event and read the breakpoint from there... But it would only be useful to know that it is a catchpoint and which one, so who cares [25/07/23]
        # We have a problem with multiple catchpoints for the same syscall... [26/07/23]
        # Can we get the reason from the StopEvent ?
        # TODO WARNING stepping over a syscall doesn't trigger these callbacks! [21/06/25]
        if dbg._stop_reason == "BREAKPOINT" and (callback := dbg.control.event_breakpoints.get(dbg._details_breakpoint_stopped, None)) is not None:
            if DEBUG: dbg.logger.debug("stopped for catchpoint at %x", dbg.instruction_pointer)
            name = list(dbg.control.event_table.keys())[list(dbg.control.event_table.values()).index(dbg._details_breakpoint_stopped)]
            # Syscalls have to be handled differently because we break both when calling it and when returning
            if name.startswith("syscall "):
                if dbg.control.syscall_return:
                    # This used to be hit when we were running the syscall with continue because it triggered the catchpoint, but now step just flies over it. I keep it to remember in case we revert to a continue(force=False) [21/06/25]
                    # The advantage of keeping this instead of stepping would be that we don't have to handle a special step where we ignore the breakpoints.
                    # Still reachable: execve clears the single step flag, so the si() ends on the syscall-exit catchpoint instead of a step trap [11/10/26]
                    if DEBUG: dbg.logger.debug("step out of the syscall stopped on the return catchpoint")
                    dbg.control.set_stop("returned from syscall")
                    return

                saved_return_value = dbg.return_value
                should_skip = callback(dbg, entry=True)
                if should_skip is not None and should_skip & SKIP_SYSCALL:
                    if DEBUG: dbg.logger.info("skipping syscall")
                    if dbg.return_value == saved_return_value:
                        log.warn_once("You skipped the syscall execution, but didn't set the return value. This may break the process")# so I will set it to 0.")
                        # self.return_value = 0
                    # On x86 the proper way would be to set orig_*ax to -1
                    # Apparently the jump works only by a side effect because it sets orig_*ax to -1
                    # On arm it wouldn't work TODO check
                    # RISCV and MIPS want us to set a7, v0 to -1
                    # internal=True: the jump is part of handling this stop, so it runs even if interrupt() suspended this stop
                    self.jump(dbg.instruction_pointer, internal=True)
                    # This will not save you from manual interactions unfortunately, but it's still better than anything
                    if not should_skip & SHOULD_STOP and len(breakpoints) == 0:
                        if DEBUG: dbg.logger.info("resuming execution")
                        dbg._hidden_continue()
                    else:
                        # Wait I must stop for the user, not the emulator...
                        # I should tell any wait() that I stopped, but not waitpid...
                        # if self._ptrace_emulated:
                        #     self._ptrace_has_stopped.set()
                        #else:
                        #    # TODO TEST IT [26/07/23]
                        dbg.control.set_stop("stopped after skipping syscall")
                else:
                    dbg.control.syscall_return = True
                    # address = self.instruction_pointer
                    if DEBUG: dbg.logger.info("executing syscall")
                    try:
                        with context.silent:
                            dbg._step(internal=True) # Consider implementing a self.c(force=False) that doesn't step
                            # A signal (the SIGINT of interrupt()) stopped the syscall before it ended: the kernel runs it again
                            # with the next step. Not internal: if interrupt() suspended this stop, it waits for resume()
                            while dbg.control.syscall_restarts():
                                dbg._step()
                        # if address != self.instruction_pointer:
                        #     log.warn("The execution of the syscall didn't go as planned.")
                        should_stop = callback(dbg, entry=False)
                    finally:
                        dbg.control.syscall_return = False
                    if should_stop == False and len(breakpoints) == 0:
                        if DEBUG: dbg.logger.info("resuming execution")
                        dbg._hidden_continue()
                    else:
                        if should_stop is None:
                            log.warn_once("You didn't specify a behaviour leaving the syscall. By default I will stop.")
                        dbg.control.set_stop("returned from syscall")
            else:
                should_stop = callback(dbg)
                should_stop = True if should_stop is None else should_stop
                if should_stop:
                    should_continue = False
                    dbg.control.set_stop("event callback returned True or None")
                else:
                    if DEBUG: dbg.logger.debug("[%d] callback returned False", dbg.pid)
                    dbg._hidden_continue()
                    return
            if len(breakpoints) == 0:
                return
        
        # Don't execute callbacks when we are finishing the execution of a syscall. This will be handled after.
        if len(breakpoints) == 0 or dbg.control.syscall_return:
            # Is it right to catch SIGSTOP and SIGTRAP ? [04/06/23]
            #if self._stop_reason == "SIGSEGV":
            #    self._exit_handler(...)
            # I put the signal first because I may have PTRACE_CONT be called on a SIGILL and I must tell the master that we stopped. I hope it won't cause problems with the different SIGSTOP that gdb puts in the way. [23/06/23]
            if dbg.control.interrupted and dbg._stop_reason == "SIGINT":
                dbg.control.interrupted_stop()
            
            # Are we able to distinguish this from normal interactions with gdb ? Are there cases where instead a signal is seen as a normal interaction ?
            elif dbg._stop_reason in SIGNALS:
                # I hope that the case where we step and still end up on a breakpoint won't cause problems because we would not reset stepped... [29/04/23]
                if not dbg.ptrace.take_stop(verbose=True):
                    dbg.control.set_stop(f"signal: {dbg._stop_reason}")
            # self._stepped must only set by step() and can't be set by PTRACE_SINGLESTEP [23/07/23]
            elif dbg.control.stepped:
                dbg.control.stepped = False
                dbg.control.set_stop("stepped")
            else:
                if DEBUG: dbg.logger.debug("stopped for a manual interaction")
                dbg.control.enforce_stop("manual interaction")
            return

        # Doesn't handle the case where we use ni and hit the breakpoint though... [17/04/23] TODO!
        # Doesn't even handle the case where I step, but I'm waiting in continue until
        # Damn, gdb detects the breakpoint even if we don't run over the INT3... so this doesn't work. We never have reason SINGLE STEP with a breakpoint. We need another indication [10/05/23]
        dbg.control.spawn_handler(dbg.control.handle_breakpoints, breakpoints, name=f"[{dbg.pid}] handle breakpoint {hex(ip)}")
    def on_died(self) -> None:
        """
        Called from the BgServingThread when the connection to gdb breaks without detach()
        """
        dbg = self.dbg
        gdb = dbg.gdb
        log.warning(f"[{dbg.pid}] GDB died! The process is no longer debugged")
        self.died = True
        self.forget()
        self._cached_registers = {}
        dbg.control.kill_threads.set()
        dbg.control.closed.set()
        gdb.stopped.set() # Let loop_stop_handler_gdb exit
        dbg.ptrace.on_exit()
        dbg.control.priority.abort() # Wake whoever is waiting, at any priority
    def optimize(self) -> None:
        dbg = self.dbg
        assert dbg.gdb is not None # Just for static checks to be happy. We already know that it's true
        # pwntools wastes a lot of time waiting to serve responses [17/10/26]
        dbg.gdb.execute("python GdbConnection.SERVE_TIME = 0.001; GdbConnection.IDLE_TIME = 0.001", to_string=True)
        for thread in enumerate_threads():
            server = getattr(getattr(thread, "_target", None), "__self__", None)
            if isinstance(server, BgServingThread) and server._conn is dbg.conn:
                # Block in poll() instead of serve(0) + sleep(0.1). rpyc routes the replies of the other threads to them
                self._server = server
                self._server._serve_interval, self._server._sleep_interval = 1.0, 0.0
                break

        # pwntools' Gdb.__getattr__ fetches conn.root.Agdb again on every access: 4 round trips per self.gdb.execute()
        gdb_module = dbg.conn.root.gdb
        for name in ["execute", "parse_and_eval", "selected_inferior", "selected_thread"]:
            setattr(dbg.gdb, name, getattr(gdb_module, name))
    def watch(self) -> None:
        """
        pwntools serves the rpyc connection to gdb in a BgServingThread. When gdb dies the socket closes, serve() raises EOFError
        and the thread calls its callback once. pwntools sets it to `lambda: None`, we put ours.
        """
        dbg = self.dbg
        server = self._server
        if server is None:
            if DEBUG: dbg.logger.debug("BgServingThread of gdb not found. We won't detect if gdb dies")
            return
        server._callback = lambda: self.on_died()
        # gdb may have died before we set the callback
        if not server._active:
            self.on_died()
    def unwatch(self) -> None:
        """
        Called by detach() before closing gdb on purpose, so that its connection closing is not taken for a death
        """
        dbg = self.dbg
        if self._server is not None:
            self._server._callback = lambda: None # pwntools' default
            self._server = None
    def forget(self) -> None:
        """
        Called once gdb is closed or dead: the pid may be reused by another process before python exits
        """
        dbg = self.dbg
        if self._finalizer is not None:
            self._finalizer.detach()
            self._finalizer = None
    def kill_at_exit(self) -> None:
        """
        pwntools kills the terminal of gdb at exit, but it only has the pid of the command it launched. gnome-terminal hands the window
        to gnome-terminal-server and exits at once, so the kill misses and gdb stays open with its terminal.
        Kill gdb itself when the Debugger is garbage collected or python exits. Not when the script raises: in an interactive session
        (python -i) the Debugger is still usable after the exception.
        """
        dbg = self.dbg
        self.forget()
        try:
            gdb_pid = int(dbg.gdb.execute("python print(__import__('os').getpid())", to_string=True))
        except (ValueError, EOFError):
            if DEBUG: dbg.logger.debug("can't get the pid of gdb. It may stay open at exit")
            return
        self._finalizer = weakref.finalize(dbg, _kill_gdb, gdb_pid)
    # TODO look into peda someday
    def detect_extension(self) -> None:
        """
        Determine which extension of gdb is being used between GEF and pwndbg
        """
        dbg = self.dbg
        try:
            dbg.execute("gef")
            dbg._gef = True
            if DEBUG: _logger.debug("user is using gef")
            return
        except:
            if DEBUG: _logger.debug("user isn't using gef")
        try:
            dbg.execute("pwndbg")
            dbg._pwndbg = True
            if DEBUG: _logger.debug("user is using pwndbg")
            return
        except:
            if DEBUG: _logger.debug("user isn't using pwndbg")
    @context_decorator
    def setup(self) -> None:
        """
        setup of gdb's events
        """
        dbg = self.dbg
        assert dbg.gdb is not None # Just for static checks to be happy. We already know that it's true
        self.optimize()

        def loop_handler() -> None:
            while True:
                dbg._internal_wait() # Move the wait here to se look only when needed [09/07/24]
                if DEBUG: dbg.logger.debug("GDB stopped somewhere.")
                # I ended up setting the stopped event when I close the debugger to stop the wait.
                # The idea was that close() would cause a stop event, but this is not true if we stopped already, so we need to timeout the wait instead
                if dbg.control.kill_threads.is_set() or dbg.control.closed.is_set():
                    if DEBUG: dbg.logger.debug("exiting loop handler")
                    break
                # Open the context here, before the thread starts: interrupt() must never see a stop that nobody handles yet
                stop = dbg.control.priority.stop_detected("gdb stop")
                dbg.control.spawn_handler(self.handle_stop, name=f"[{dbg.pid}] stop_handler_gdb", handler_context=stop)
        # daemon: python joins non-daemon threads before running atexit, so this wait would block the exit and pwntools would never close the gdb terminal
        context.Thread(target=loop_handler, name=f"[{dbg.pid}] loop_stop_handler_gdb", daemon=True).start()
        self.watch()
        self.kill_at_exit()
        
        # We should consider setting again a events.stop to have access to event.inferior_thread.inferior instead of needing current_inferior()

        dbg.gdb.events.exited.connect(dbg.control.exit_handler)
        def clear_cache(event: ContinueEvent | RegisterChangedEvent) -> None:
            if DEBUG: dbg.logger.debug("GDB clearing register cache")
            self._cached_registers = {}
            dbg.control.callback_return_overwritten = False
        dbg.gdb.events.cont.connect(clear_cache)
        # Could be improved clearing only event.regnum, but you need a map to which register corresponds to which number for each architecture [08/07/24]
        dbg.gdb.events.register_changed.connect(clear_cache)
        #self.execute("set write on")

        # Track the commands typed in gdb that resume the process. Our own resumes are already marked as running
        def resumed(event: ContinueEvent) -> None:
            dbg.control.priority.resumed_externally()
        dbg.gdb.events.cont.connect(resumed)

        dbg.ptrace.warn_if_used()

        # Manually set by split_child
        dbg.split = Queue()

        dbg.control.closed.clear()
        dbg.control.kill_threads.clear()
        dbg.control.priority.pid = dbg.pid
        dbg.control.priority.aborted = False # Only set once gdb died
        dbg.control.priority.running = False # We just attached: the process is stopped
        self.died = False

        self.detect_extension()

        if not context.native and dbg._gef:
            log.warn_once("Using GEF with qemu. In case of bugs try pwndbg")

        if dbg._pwndbg:
            # because for some reason they set the child...
            # But this breaks any gdbscript with set follow-fork-mode to child... [17/11/23]
            if "set follow-fork-mode" not in dbg.gdbscript:
                dbg.execute("set follow-fork-mode parent")      
    # Here to have only one check that we can indeed attach to the process
    @context_decorator
    def attach(self, target: int | process | tuple[str, int], gdbscript: str | None = None, exe: str | ELF | None = None) -> Gdb:
        dbg = self.dbg
        if isinstance(exe, ELF):
            exe = exe.path
        if not context.native and dbg.local_debugging:
            log.error("We can not attach to a process under QEMU")
        _, debugger = dbg._silence(gdb.attach, target, gdbscript=gdbscript, exe=exe, api=True)
        try: 
            debugger.execute("info tasks", to_string=True)
        except Exception as e:
            print(e)
            if isinstance(target, tuple):
                log.error("Can not connect to gdbserver. Are you sure it is running ?")
            elif exe is None:
                log.error("Your version of pwntools requires setting the binary you are debugging.")
            else:
                log.error("Can not attach to process! Did you set ptrace scope to 0 ? (/etc/sysctl.d/10-ptrace.conf)")
        return debugger
    def send_command(self, command: str | Callable[[], object]) -> None:
        dbg = self.dbg
        dbg.execute(command)
    def call_mprotect(self, page_address: int, length: int) -> None:
        dbg = self.dbg
        dbg.execute(f"call (void)mprotect({page_address}, {length}, 0x7)")
    def catch_pending_sigint(self) -> int:
        dbg = self.dbg
        if DEBUG: dbg.logger.warning("We hit a breakpoint before the SIGINT... I will continue stepping to catch them.")
        address = dbg.instruction_pointer
        saved_callbacks = []
        for bp in dbg.control.breakpoints[address]:
            saved_callbacks.append(bp.callback)
            bp.callback = None
        steps = -1
        try:
            with context.silent:
                for i in range(5):
                    dbg._step(internal=True) # internal=True: split() calls it while handling a stop that interrupt() may suspend
                    if dbg._stop_reason == "SIGINT":
                        steps = i
                        break
        finally:
            for bp, callback in zip(dbg.control.breakpoints[address], saved_callbacks):
                bp.callback = callback
        if address != dbg.instruction_pointer:
            log.warn("Oups, I made a mistake trying to catch the SIGINT...")
        elif steps == -1:
            log.warn("What the fuck happened with the SIGINT ? I never found it...")
        else:
            if DEBUG: dbg.logger.info(f"found SIGINT in {steps} steps.")
        dbg.control.interrupted = False # Never leave it set: the next SIGINT of the program would be taken for ours
        return INTERRUPT_HIT_BREAKPOINT
    def handle_signal(self, signal: str) -> None:
        dbg = self.dbg
        dbg.execute(f"handle {signal} stop nopass")
    def close(self) -> None:
        dbg = self.dbg
        # Is this really needed ? Currently seems to break the interrupt inside detach by not detecting the interruption [05/01/25]
        # Yes it is needed to make sure that the loop_stop_handler exits [01/05/25] We can try to move it after detach though
        dbg.gdb.stopped.set() 
    def read_long_register(self, name: str) -> int:
        dbg = self.dbg
        return int(dbg.execute(f"p ${name}.uint128").split(" = ")[-1])
    def write_long_register(self, name: str, value: int) -> None:
        dbg = self.dbg
        if DEBUG: dbg.logger.debug(" setting %s to %x", name, value)
        # gdb can't parse 128 bit constants: write the two 64 bit halves
        value %= 2**128
        for i, half in enumerate([value % 2**64, value // 2**64]):
            if half >= 2**63:
                half -= 2**64
            dbg.execute(f"set ${name}.v2_int64[{i}] = {half}")
