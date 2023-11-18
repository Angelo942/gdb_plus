from pwn import *
import pwn
import os
from time import sleep
from functools import partial
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_ARCH_RISCV, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC
from threading import Event
from queue import Queue
from gdb_plus.utils import *
from collections import defaultdict
from queue import Queue
from math import ceil
from multiprocessing import Process, Event as p_Event, Queue as p_Queue, cpu_count
import re
import logging as _logging


_logger = _logging.getLogger("gdb_plus")
ch = _logging.StreamHandler()
formatter = _logging.Formatter("%(name)s:%(funcName)s:%(message)s")
ch.setFormatter(formatter)
_logger.addHandler(ch)

DEBUG_OFF = "Debug is off, commands won't be executed"

SHOULD_STOP = 0b1
SKIP_SYSCALL = 0b10
# Constants for interrupt
INTERRUPT_SENT = 0b1 # We sent the signal
INTERRUPT_HIT_BREAKPOINT = 0b10 # The process stopped for a breakpoint instead of our signal.


def lock_decorator(func):
    def parse(self, *args, **kwargs):
        with self.ptrace_lock:#log(func.__name__):
            result = func(self, *args, **kwargs)
            return result
    return parse

class Debugger:
    # If possible patch the rpath (spwn and pwninit do it automatically) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target: [int, process, str, list], env={}, aslr:bool=True, script:str="", from_start:bool=True, binary:str=None, debug_from: int=None, timeout: int=0.5, base_elf=None):
        _logger.debug("debugging %s using arch: %s [%dbits]", target if binary is None else binary, context.arch, context.bits)

        self._capstone = None #To decompile assembly for next_inst
        self._auxiliary_vector = None #only used to locate the canary
        self._base_libc = None
        self._base_elf = base_elf
        self._canary = None
        self._args = None
        self._sys_args = None
        self.closed = Event()
        self.parent = None
        self.children = {} # Maybe put {self.pid: self} as first one
        self.slaves = {} # I keep it to be sure I am tracing them 
        self.ptrace_breakpoints = []
        self.ptrace_backups = {}

        self.pid = None

        self.gdb = None
        self.libdebug = None

        self.gef = False
        self.pwndbg = False

        self._backup_p = None
        self.r = None
        self._host = None
        self._port = 0

        # Ptrace_cont
        self.out_of_breakpoint = Event()
        self.ptrace_emulated = False
        self.ptrace_syscall = False
        self.ptrace_lock = MyLock(self.out_of_breakpoint, owner=self)
        self.ptrace_can_continue = Event()
        self.ptrace_has_stopped = Event()  
        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        # Do we want to save temporary breakpoints too ? [17/04/23]
        self.breakpoints = defaultdict(list)
        # Let's try to reduce race conditions [19/06/23]
        self.stops_to_enforce = 0
        self.breakpoint_handled = Event()

        self.handled_signals = {}
        self.gdbscript = script # For non blocking debug_from
        self.debug_from_done = Event()

        # MyEvent allows calls to wait in parallel
        self.myStopped = MyEvent() # Include original event
        self.myStopped.set() # we call __setup_gdb after an attach so the process isn't running. Make just sure this doesn't cause troubles [17/04/23]

        # To know that I'm responsible for the interruption even if there is no callback
        self.stepped = False
        self.interrupted = False
        self.detached = False
        # Maybe not needed (see set_split_on_fork)
        self.last_breakpoint_deleted = 0 # Keep track of the last temporary breakpoint deleted if we realy have to know if we hit something

        self.syscall_table = {}
        self.syscall_breakpoints = {}
        self.syscall_return = False

        if args.REMOTE or context.noptrace:
            self.debugging = False
            self.children = defaultdict(lambda: self)
        else:
            self.debugging = True

        # The idea was to let gdb interrupt only one inferior while letting the other one run, but this doesn't work [29/04/23]
        #script = "set target-async on\nset pagination off\nset non-stop on" + script

        if type(target) is int:
            self.p = None
            self.pid = target
            assert binary is not None, "I need a file to work from a pid" # Not really... Let's keep it like this for now, but continue assuming we don't have a real file
            self.elf = ELF(binary, checksec=False)
            # We may want to run the script only at the end in case the user really insists on putting a continue in it. [17/11/23]
            _, self.gdb = gdb.attach(target, gdbscript=script, api=True)

        elif type(target) is process:
            self.p = target
            _, self.gdb = gdb.attach(target, gdbscript=script, api=True)

        elif args.REMOTE:
            self.elf = ELF(target, checksec=False) if binary is None else ELF(binary, checksec=False)

        elif context.noptrace:
            self.p = process(target, env=env, aslr=aslr)
        
        elif from_start:
            self.p = gdb.debug(target, env=env, aslr=aslr, gdbscript=script, api=True)
            self.gdb = self.p.gdb

        else:
            self.p = process(target, env=env, aslr=aslr)
            _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)

        if type(self.p) is process:
            self.pid = self.p.pid
            self.elf = self.p.elf if binary is None else ELF(binary, checksec=False)

        if self.pid is not None:
            self._logger = _logging.getLogger(f"Debugger-{self.pid}")
        else:
            self._logger = _logging.getLogger(f"Remote Debugger")
        self._logger.addHandler(ch)
        self._logger.setLevel(_logger.level)

        # pwntools symbols duplicate every entry in the plt and the got. This breaks my version of symbols because they have the same name as the libc [25/03/23]
        # This may break not stripped statically linked binaries, just wait for the libc to be loaded and those symbols will be overshadowed [25/03/23]
        # Let's still do it for dynamically linked binaries [04/04/23]
        if self.elf and not self.elf.statically_linked:
            for symbol_name in list(self.elf.symbols.keys()):
                if (symbol_name.startswith("plt.") or symbol_name.startswith("got.")) and (name := symbol_name[4:]) in self.elf.symbols:
                    del self.elf.symbols[name]

        # Because pwntools context isn't perfect
        if self.elf.arch == "em_riscv":
            self.elf.arch = "riscv"
        self.restore_arch()

        if self.debugging:
            self.elf.address = self.get_base_elf()
            self.__setup_gdb()

            # Start debugging from a specific address. Wait timeout seconds for the program to reach that address. Is blocking so you may need to use context.Thread() in some cases
            # WARNING don't use 'continue' in your gdbscript when using debug_from ! [17/04/23]
            # I don't like that this is blocking, so you can't interact while waiting... Can we do it differently ? [17/04/23]
            if debug_from is not None:
                # I can't attach again to the process
                assert context.arch != "aarch64", "debug_from isn't supported in qemu"
                address_debug_from = self.parse_address(debug_from)
                backup = self.inject_sleep(address_debug_from)
                while True:  
                    self.detach()
                    sleep(timeout)
                    # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
                    _, self.gdb = gdb.attach(self.pid, gdbscript=script, api=True) # P is gdbserver...
                    self.__setup_gdb()
                    if self.instruction_pointer - address_debug_from in range(0, len(backup)): # I'm in the sleep shellcode
                        self.write(address_debug_from, backup)
                        self.jump(address_debug_from)
                        break
                    else:
                        log.warn(f"{timeout}s timeout isn't enought to reach the code... Retrying...")

    def __handle_breakpoints(self, breakpoints):
        should_continue = self._stop_reason != "SINGLE STEP" # Versione semplice. Se vengo da uno step non devo mai continuare e almeno adesso è già salvato [05/06/23]
        # I don't set stop after each breakpoint to avoid letting a script continue while another callback is running [06/06/23]
        set_stop = []
        address = self.instruction_pointer
        self._logger.debug("0x%x: %d %s", address, len(breakpoints), breakpoints)
        # Copy because the list will be modified by delete() [06/06/23]
        for breakpoint in breakpoints.copy():
            if breakpoint.temporary:
                self.delete_breakpoint(breakpoint)

            if breakpoint.callback is None:
                should_continue = False
                # Must be set for each breakpoint for the library funtions to work [05/06/23]
                # Check that the priorities can't be broken by a breakpoint set by the user... [05/06/23]
                set_stop.append(f"No callback")
            else:           
                should_stop = breakpoint.callback(self)
                should_stop = True if should_stop is None else should_stop
                if should_stop:
                    should_continue = False
                    set_stop.append(f"callback returned True or None")  

                else:
                    should_continue &= True
                    self._logger.debug("[%d] callback returned False", self.pid)

        # Be sure to be in the last stop
        if address == self.instruction_pointer:
            self._logger.debug("saving remaining stops: %d", len(set_stop))
            self.stops_to_enforce = len(set_stop)

        # Come funziona ancora questo ? Deve controllare i breakpoint multipli ed evitare che mandiamo un segnale sbagliato, però se nessuno aspetta dopo devo andare avanti...
        for i, stop_reason in enumerate(set_stop):
            self.breakpoint_handled.clear()
            self.__set_stop(stop_reason)
            # Se stai gestendo l'ultimo vai avanti e basta
            if i + 1 < len(set_stop):
                self.breakpoint_handled.wait()
            #self.__enforce_stop(stop_reason)

        # TODO IMPROVE THIS [06/06/23]
        # We have a problem. If I do a next() and hit a breakpoint with a finish(); return False, How should I know not to continue after the finish ?
        # If this is the only breakpoint that stop we can continue [19/06/23]
        if should_continue and self.stops_to_enforce <= 1:#not self.myStopped.enforce_stop: 
            self.__hidden_continue()
        self._logger.debug("setting breakpoint handled")
        self.breakpoint_handled.set()

    # We stopped using gdb's implementation of temporary breakpoints so that we can differentiate an interruption caused by my debugger and cause by the manual use of gdb 
    # Event could tell me which breakpoint has been hit or which signal cause the interruption
    # For ptrace emulation if the interuption is caused by a breakpoint, a step or an interrupt we stop the process. Otherwise we let the master decide in waitpid depending on the settings if we should return the control to the user [23/07/23]. This may cause problems though if waitpid is never called
    @lock_decorator
    def __stop_handler_gdb(self):
        """
        Actions that the debugger performs every time the process is interrupted
        Handle temporary breakpoints and callbacks
        """
        self.restore_arch()

        # Current inferior will change to the inferior who stopped last
        ip = self.instruction_pointer
        breakpoints = self.breakpoints[ip]

        _logger.debug("[%d] stopped at address: %s for %s", self.current_inferior.pid, self.reverse_lookup(ip), self._stop_reason)
        
        # Warn that if a parent has to listen for a signal you must tell your handler to stop the execution [22/07/23]
        if self._stop_reason in SIGNALS and SIGNALS[self._stop_reason] in self.handled_signals:
            should_stop = self.handled_signals[SIGNALS[self._stop_reason]](self)
            if should_stop == False:
                self.__hidden_continue()
            else:
                if self.ptrace_emulated:
                    self._logger.debug("stop will be handle by waitpid")
                    self.ptrace_has_stopped.set()
                else:
                    self.__set_stop(f"signal {self._stop_reason} handled")
            return  

        # We could also pass the stop event and read the breakpoint from there... But it would only be usefull to know that it is a catchpoint and which one, so who cares [25/07/23]
        # We have a problem with multiple catchpoints for the same syscall... [26/07/23]
        # Can we get the reason from the StopEvent ?
        if self._stop_reason == "BREAKPOINT" and (callback := self.syscall_breakpoints.get(self._details_breakpoint_stopped, None)) is not None:
            if self.syscall_return == False: 
                # Make sure we don't miss the return
                # Put above to avoid race condition after the jump
                self.raise_priority("handling syscall")
                should_skip = callback(self, entry=True)
                if should_skip is not None and should_skip & SKIP_SYSCALL:
                    self.jump(self.instruction_pointer)
                    if not should_skip & SHOULD_STOP:
                        self.__hidden_continue()
                    else:
                        # Wait I must stop for the user, not the emulator...
                        # I should tell any wait() that I stopped, but not waitpid...
                        #if self.ptrace_emulated:
                        #    self.ptrace_has_stopped.set()
                        #else:
                        #    # TODO TEST IT [26/07/23]
                        self.__set_stop("stopped after skipping syscall")
                    self.lower_priority("syscall skipped")    
                    return
                # hit the return
                self.syscall_return = True
                self.c()
                should_stop = callback(self, entry=False)
                self.lower_priority("syscall handled")
                self.syscall_return = False
                if should_stop == False:
                    self.__hidden_continue()
                else:
                    self.__set_stop("returned from syscall")
            else:
                self.__set_stop("returned from syscall")
            return
            
        if len(breakpoints) == 0:
            # Is it right to catch SIGSTOP and SIGTRAP ? [04/06/23]
            #if self._stop_reason == "SIGSEGV":
            #    self.__exit_handler(...)
            # I put the signal first because I may have PTRACE_CONT be called on a SIGILL and I must tell the master that we stopped. I hope it won't cause problems with the different SIGSTOP that gdb puts in the way. [23/06/23]
            if self.interrupted and self._stop_reason == "SIGINT":
                self.interrupted = False
                self.__set_stop(f"interrupted")
            
            elif self._stop_reason in SIGNALS:
                # I hope that the case where we step and still end up on a breakpoint won't cause problems because we would not reset stepped... [29/04/23]
                if self.ptrace_emulated:
                    self._logger.debug("stop will be handle by waitpid")
                    self.ptrace_has_stopped.set()
                else:
                    self.__set_stop(f"signal: {self._stop_reason}")
            # self.stepped must only set by step() and can't be set by PTRACE_SINGLESTEP [23/07/23]
            elif self.stepped:
                self.stepped = False
                self.__set_stop("stepped")
            else:
                self._logger.debug("stopped for a manual interaction")
                self.__enforce_stop("manual interaction")
            return            
        
        # Doesn't handle the case where we use ni and hit the breakpoint though... [17/04/23] TODO!
        # Doesn't even handle the case where I step, but I'm waiting in continue until
        # Damn, gdb detects the breakpoint even if we don't run over the INT3... so this doesn't work. We never have reason SINGLE STEP with a breakpoint. We need another indication [10/05/23]
        self.__handle_breakpoints(breakpoints)

    @lock_decorator
    def __stop_handler_libdebug(self):
        """
        Actions that the debugger performs every time the process is interrupted
        Handle temporary breakpoints and callbacks
        """
        self.restore_arch()

        # If we detach there will be a step to shutdown waitpid, but libdebug will have detached before we can execute the handler, so let's just skip it.
        if self.detached:
            self._logger.debug("libdebug stopped waitpid")
            return

        # Current inferior will change to the inferior who stopped last
        ip = self.instruction_pointer
        breakpoints = self.breakpoints[ip]

        _logger.debug("[%d] stopped at address: 0x%x with status: 0x%x", self.libdebug.cur_tid, ip, self.libdebug.stop_status)
        
        if self._stop_reason in SIGNALS and SIGNALS[self._stop_reason] in self.handled_signals:
            should_stop = self.handled_signals[SIGNALS[self._stop_reason]](self)
            if should_stop == False:
                self.__hidden_continue()
            else:
                if self.ptrace_emulated:
                    self._logger.debug("stop will be handle by waitpid")
                    self.ptrace_has_stopped.set()
                else:
                    self.__set_stop(f"signal {self._stop_reason} handled")
            return  
        # I hope I won't touch a breakpoint at the same time
        # Usually if I hit a breakpoint it should stop again. At least with step we have the step and then the sigchld 
        # Will be a problem while stepping, but amen
        elif self.libdebug.stop_status == 0x117f:
            log.warn("the child stopped and libdebug caught it. Let's continue waiting for Mario to change the options...")
            # We have problems with the wait after the step...
            #self.libdebug.cont(blocking=False)
            #return
        
        if len(breakpoints) == 0:
            if self.stepped or self.interrupted:
                self.stepped = False
                self.interrupted = False
                if self.stop_signal not in [0x5, 0x2, 0x13]:
                    log.warn(f"I wanted to step or interrupt, but stopped due to signal: {self._stop_reason}")
                    if self.ptrace_emulated:
                        self._logger.debug("stop will be handle by waitpid")
                        self.ptrace_has_stopped.set()
                        return
            # This should now be handled by libdebug [08/06/23]
            #elif self.libdebug.stop_status == 0x57f:
            #    # Look into how to handle steps in libdebug [21/05/23]
            #
            #    log.warn("I supose libdebug just stepped so let's pretend nothing happened")
            #    return
            else:
                # Once to let know there may be a problem, but not spamming when it is part of the challenge.
                log.warn_once(f"why did I stop ??? [{hex(self.libdebug.stop_status)}]")
                if self.ptrace_emulated:
                    self._logger.debug("stop will be handle by waitpid")
                    self.ptrace_has_stopped.set()
                    return
            self.__set_stop("no breakpoint")
            return            
        
        self.__handle_breakpoints(breakpoints)
        #context.Thread(target=self.__handle_breakpoints, args=(breakpoints,)).start()

    def __exit_handler(self, event):
        # Should I kill all children ? []
        # Waiiiiit, this is called even if we detach from the child in split()! [25/07/23] 
        # Yes, fuck [14/08/23]
        self._logger.debug("setting stop because process [%d] exited", event.inferior.pid)
        self.myStopped.pid = self.current_inferior.pid
        self.__clear_stop("exited")
        self.myStopped.set()
        self.closed.set()
        self.ptrace_has_stopped.set()

    def __test_debugger(self):
        try:
            self.execute("stub")
            self.gef = True
            _logger.debug("user is using gef")
            return
        except:
            _logger.debug("user isn't using gef")
        try:
            self.execute("telescope")
            self.pwndbg = True
            _logger.debug("user is using pwndbg")
            return
        except:
            _logger.debug("user isn't using pwndbg")

        
    def __setup_gdb(self):
        """
        setup of gdb's events
        """
        self.gdb.events.stop.connect(lambda event: context.Thread(target=self.__stop_handler_gdb, name=f"[{self.pid}] stop_handler_gdb").start())
        self.gdb.events.exited.connect(self.__exit_handler)
        #self.execute("set write on")

        # I still don't know how to disable it to let ptrace_emulate work in peace [26/07/23]
        def callback_ptrace(self, entry):
            if entry:
                log.warn_once(f"THE PROCESS [{self.pid}] USES PTRACE!")
            # Do we also want to delete the breakpoint once we know we are using ptrace ? [13/08/23]
            else:
                self.delete_catch("ptrace")        
            return False
        self.catch_syscall("ptrace", callback_ptrace)

        # Manually set by split_child
        self.split = Queue()
        self.closed.clear()

        self.myStopped.pid = self.pid
        self.__test_debugger()
        if self.pwndbg:
            # because for some reason they set the child...
            # But this breaks any gdbscript with set follow-fork-mode to child... [17/11/23]
            if "set follow-fork-mode" not in self.gdbscript:
                self.execute("set follow-fork-mode parent")      

    def __setup_libdebug(self):
        self.libdebug.handle_stop = self.__stop_handler_libdebug

        self.libdebug.handle_exit = self.__exit_handler
        
        self.closed.clear()


    # È già successo che wait ritorni -1 e crashi libdebug [08/05/23]
    # Legacy callbacks won't be transfered over... It's really time to get rid of them [21/05/23]
    def migrate(self, *, gdb=False, libdebug=False, script=""):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        assert context.arch != "aarch64", "migrate isn't supported in qemu"

        # Maybe put a try except to restore the backup in case of accident [06/06/23]
        if gdb:
            assert self.gdb is None
            self.detach(block=True)
            self._logger.debug("migrating to gdb")
            self.libdebug = None
            self.detached  = False
            _, self.gdb = pwn.gdb.attach(self.pid, gdbscript=script, api=True)
            self.__setup_gdb()
            # Catch SIGSTOP
            address = self.instruction_pointer
            with context.silent:
                self.step(repeat=4)
            if address != self.instruction_pointer:
                log.warn("I made a mistake trying to catch the SIGSTOP after attaching with gdb")
            # I must get back before setting the breakpoints otherwise I may overwrite them
            for address in self.breakpoints:
                for breakpoint in self.breakpoints[address]:
                    bp = self.__breakpoint_gdb(address)
                    breakpoint.native_breakpoint = bp
        elif libdebug:
            assert not self.ptrace_syscall, "libdebug can't catch ptrace syscall. Emulate with syscall = False"
            if self.syscall_breakpoints:
                log.warn_once("you will lose all your syscall catchpoints!")
            from libdebug import Debugger as lib_Debugger
            # Disable hook stop
            assert self.libdebug is None
            assert self.gdb is not None
            self.gdb.events.exited.disconnect(self.__exit_handler)
            self.detach(block=True)
            self._logger.debug("migrating to libdebug")
            self.gdb = None
            self.detached  = False
            self.libdebug = lib_Debugger(multithread=False)
            while not self.libdebug.attach(self.pid, options=False):
                log.warn("error attaching with libdebug... Retrying...")
                continue
            assert not self.libdebug.running
            self.__setup_libdebug()
            # Catch SIGSTOP
            address = self.instruction_pointer
            with context.silent:
                self.step()
            if address != self.instruction_pointer:
                log.warn("I made a mistake trying to catch the SIGSTOP after attaching with libdebug")
            # TODO Handle hb too 
            for address in self.breakpoints:
                for breakpoint in self.breakpoints[address]:
                    bp = self.__breakpoint_libdebug(address)
                    breakpoint.native_breakpoint = bp
        else:
            ...
        return self

    # Because pwntools isn't perfect
    def restore_arch(self):
        """
        check that the context used by pwntools is correct
        """
        global context
        if self.elf is not None and context.arch != self.elf.arch:
            self._logger.debug("wrong context ! Updating...")
        context.arch = self.elf.arch
        context.bits = self.elf.bits

    def debug_from(self, location: [int, str], *, event=None, timeout=0.5):
        """
        Alternative debug_from which isn't blocking
        wait dbg.debug_from_done to know when to continue

        event: optional event to signal that you have finished the actions you needed to perform. Otherwise a timeout of 0.5s will be used
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            self.debug_from_done.set()
            return

        address = self.parse_address(location)

        def action():
            backup = self.inject_sleep(address)
            while True:  
                self.detach()
                if event is not None:
                    event.wait()
                    self._logger.debug("user finished interaction. Proceeding with debug_from")
                else:
                    log.warn_once("you haven't set an event to let me know when you finished interactiong with the process. I will give you half a second.")
                    sleep(timeout)
                # Maybe the process is being traced and I can't attach to it yet
                try:
                    # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
                    _, self.gdb = gdb.attach(self.p.pid, gdbscript=self.gdbscript, api=True) # P is gdbserver...
                except Exception as e:
                    self._logger.debug("can't attach in debug_from because of %s... Retrying...", e)
                    continue
                self.__setup_gdb()
                if self.instruction_pointer - address in range(0, len(backup)): # I'm in the sleep shellcode
                    self.write(address, backup)
                    self.jump(address)
                    self.debug_from_done.set()
                    break
                else:
                    log.warn(f"{timeout}s timeout isn't enought to reach the code... Retrying...")
        context.Thread(target=action, name=f"[{self.pid}] debug_from").start()
        return self

    # Use as : dbg = Debugger("file").remote(IP, PORT)
    def remote(self, host: str, port: int):
        """
        Define the connection to use when the script is called with argument REMOTE
        """
        self._host = host
        self._port = port
        if args.REMOTE:
            self.p = remote(host, port)
        return self

    def connect(*, overwrite=True):
        """
        Connect to remote server while keeping debugger active.
        if overwrite is False self.p will be preserved and the connection will be saved on self.r instead 
        """
        if self._host is None:
            raise Exception("host not set!")

        if overwrite:
            self._backup_p = self.p # Just make sure the connection doesn't die
            self.p = remote(self._host, self._port)
        else:
            self.r = remote(self._host, self._port)

        return self

    def detach(self, quit = True, block = False):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        # Must be stopped
        try:
            self.interrupt()
        except:
            self._logger.debug("process has already stopped")
        self.detached = True

        if self.gdb is not None:
            # They will be lost
            self.syscall_breakpoints = {}
            self.syscall_table = {}

            try:
                if block:
                    os.kill(self.pid, signal.SIGSTOP)
                self.execute("detach")
            except:
                self._logger.debug("process already stopped")
            try:
                self.execute("quit") # Doesn't always work if after interacting manually
            except EOFError:
                self._logger.debug("GDB successfully closed")

        elif self.libdebug is not None:
            self.libdebug.detach()
            if not block:
                os.kill(self.pid, signal.SIGCONT)

        else:
            ...

    def close(self):
        self.detach()
        # Yah, I should do it here, but I close the terminal in detach, so let's handle it there.
        #except:
        #    self._logger.debug("can't detach because process has already exited")
        # Can't close the process if I just attached to the pid
        if self.p:
            self.p.close()
        if self.r is not None:
            self.r.close()
        if self._backup_p is not None:
            self._backup_p.close()

    # Now we may have problems if the user try calling it...
    # should warn to use execute_action and wait if they are doing something that will let the process run
    def execute(self, code: str):
        """ 
        Execute a command that does NOT require a wait later
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return ""
        
        return self.gdb.execute(code, to_string=True)
        
    # I want a function to restart the process without closing and opening a new one
    # Not working properly
    def reset(self, argv=None, reload_elf=False):
        ...

    # Since reset doesn't work
    # Could be expanded with memory regions
    def backup(self) -> list:
        """
        Save the state of all registers
        """
        if not self.debugging:
            return

        values = []
        for register in self.special_registers + self.registers: # include ip, setattr will cut it out if not needed
            values.append(getattr(self, register))
        return values
        
    def restore_backup(self, backup: list):
        """
        Reset the state of all registers from a backup
        """
        if not self.debugging:
            return

        for name, value in zip(self.special_registers + self.registers, backup):
                setattr(self, name, value)

    # Return old_inferior to know where to go back
    def switch_inferior(self, n: int) -> int:
        """
        For multi-process applications change the process you are working with in gdb
        """
        if not self.debugging:
            return

        # May not be accurate if you switched manually before
        old_inferior = self.current_inferior
        while self.current_inferior.num != n:
            self._logger.debug("switching to inferior %d", n)
            self.execute(f"inferior {n}")
            inferior = self.gdb.selected_inferior()
            self._logger.debug("I'm inferior %d, [pid: %d]", inferior.num, inferior.pid)
            sleep(0.1)
        self.pid = self.current_inferior.pid
        return old_inferior

    @property
    def inferiors(self):
        return {inferior.num: inferior for inferior in self.gdb.inferiors()}
        #return (None,) + self.gdb.inferiors()

    @property
    def current_inferior(self):
        if not self.debugging:
            return

        if self.gdb is not None:
            return self.gdb.selected_inferior()

        #elif self.libdebug is not None:
        #   return ... 

    inferior = current_inferior
        
    @property
    def args(self):
        """
        Access arguments of the current function
        Can be use to read and write
        Can only access a single argument at a time
        dbg.args[5] = 1 # Valid
        a, b = dbg.args[:2] # Not valid!
        """
        if not self.debugging:
            return

        if self._args is None:
            self._args = Arguments(self)
        return self._args 

    @property
    def syscall_args(self):
        """
        Access arguments of the current function
        Can be use to read and write
        Can only access a single argument at a time
        dbg.args[5] = 1 # Valid
        a, b = dbg.args[:2] # Not valid!
        """
        if not self.debugging:
            return

        if self._sys_args is None:
            self._sys_args = Arguments_syscall(self)
        return self._sys_args 

    sys_args = syscall_args

    # Taken from GEF to handle slave interruption
    @property
    def _stop_reason(self) -> str:
        if self.gdb is not None:
            try:
                res = self.gdb.execute("info program", to_string=True).splitlines()
            except:
                return "NOT RUNNING"
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

            return "STOPPED"

        # TODO handle it correctly. Is Ox5 only used for step or also breakpoints ? Do we have access to libdebug's stepped variable ? (I would prefer that one at least) [05/06/23]
        elif self.libdebug is not None:
            if self.stepped:
                return "SINGLE STEP"
            # Check 0x5 as step or breakpoint ?
            else:
                return SIGNALS_from_num[self.stop_signal]

        else:
            ...

    @property
    def stop_signal(self) -> int:
        if self.gdb is not None:
            reason = self._stop_reason
            if reason == "SINGLE STEP":
                return 0x5
            if "BREAKPOINT" in reason:
                return 0x13 # Not sure
            else:
                return SIGNALS[reason]
        elif self.libdebug is not None:
            return self.libdebug.stop_status >> 0x8
        else:
            ...

    @property
    def _details_breakpoint_stopped(self) -> str:
        """
        If the program stopped at a breakpoint, return the id of that breakpoint
        This can be used to identify caught syscall
        """
        res = self.gdb.execute("info program", to_string=True).splitlines()
        if not res:
            raise Exception("NOT RUNNING")

        for line in res:
            line = line.strip()
            #It stopped at breakpoint 2.
            if line.startswith("It stopped at breakpoint "):
                return int(line.split(".")[0][len("It stopped at breakpoint "):])
        else:
            log.warn("process didn't stop for a breakpoint")


   ########################## CONTROL FLOW ##########################

    # For commands that will make the process run and should handle priority
    def execute_action(self, command, sender=None):
        """
        Wrapper around execute to handle commands that will require a wait
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        priority = self.raise_priority(sender)
        self.__clear_stop(sender if sender is not None else command)
        if self.gdb is not None:
            self.execute(command)
        elif self.libdebug is not None and command != "":
            command()
        else:
            ...
        return priority

    # Simplify continue after callback so that it can still work after migrating inside the callback
    @lock_decorator
    def __hidden_continue(self, force=False):
        # The step is not needed if we set handle SIGSTOP nopass
        #address = self.instruction_pointer
        #if force:
        #    self.step(force=True)
        #    if address == self.instruction_pointer:
        #        log.debug(f"[{self.pid}] I think I stopped my step for a good reason so I won't continue")
        #        return
        self._logger.debug("hidden continue")
        sleep(0.02)
        if self.gdb is not None:
            self.gdb.execute("continue")
        elif self.libdebug is not None:
            self.libdebug.cont(blocking=False)
        else:
            ...

    def __continue_gdb(self, force, wait, done):
        # Do I check the address instead ? Like hidden_continue [09/06/23]
        with self.ptrace_lock.log("__continue_gdb"):
            priority = self.raise_priority("avoid race condition in continue")
            self.step(force=True)
            if self._stop_reason != "SINGLE STEP":
                if "BREAKPOINT" not in self._stop_reason:
                    log.warn(f"unknown interuption! {self._stop_reason}")
                self._logger.debug("step in continue already reached the breakpoint")
                self.lower_priority("avoid race condition in continue")
                done.set()
                return
            self.execute_action("continue", sender="continue")
        # Damn, I may not want to wait at all... [22/05/23]
        # Keep priority intact, so I have to wait
        #if wait:
        self.priority_wait(comment="continue", priority = priority + 1)
        done.set()
        # The problem is that this has to be set after wait() [29/07/23 21:45]
        self.lower_priority("avoid race condition in continue")

    def __continue_libdebug(self, force, wait, done, signal):
        # Continue in libdebug is already stepping [21/05/23]
        # Maybe keep the step if force = True [22/O5/23]
        #self.step(force=force)
        ## I hit a breakpoint
        #if self.instruction_pointer in self.breakpoints or self.instruction_pointer == self.last_breakpoint_deleted:
        #    return
        # I don't need the thread, right ? And this way I can lock the step [12/06/23]
        with self.ptrace_lock.log("__continue_libdebug"):
            self.execute_action(lambda: self.libdebug.cont(blocking=False, signal=signal), sender="continue")
        #if wait:
        self.priority_wait(comment="continue")
        done.set()
        
    # TODO make the option to have "until" be non blocking with an event when we reach the address [28/04/23] In other words migrate wait=False to wait=Event()
    def c(self, *, wait=True, force = False, signal=0x0):
        """
        Continue execution of the process

        Arguments:
            wait: Should block your script until the next interruption ?
            until: Continue until a specified location. Your script will wait if you have to play with gdb manually.

            force: gdb may bug and keep you at the same address after a jump or if the stackframe as been edited. If you notice this problem use force to bypass it. If you don't worry about a callback being called twice don't bother
        """
        self.restore_arch()

        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        # I have to use an event instead of priority_wait() because I may have to stop after the step [22/05/23]
        done = Event()

        if self.gdb is not None:
            context.Thread(target=self.__continue_gdb, args=(force, wait, done), name=f"[{self.pid}] continue").start() 

        elif self.libdebug is not None:
            context.Thread(target=self.__continue_libdebug, args=(force, wait, done, signal), name=f"[{self.pid}] continue").start() 

        else:
            ...

        if wait:
            done.wait()
            return self
        else:
            #pass
            # I would like to return done too, but I'm sure the average user will try dbg.wait instead of done.wait 
            # dbg.wait() would bring priority to -1, but it is still more intuitive than done.wait() so I will try to change _continue_* to allow the user to use wait() [29/07/23 21:30]
            # Nope, too many problems with priority so I get back to the event. Later we will think about separating wait and priority_wait [29/07/23 21:40]
            return done

    cont = c

    def __continue_until_gdb(self, address, done, force):
        #Force = True is not needed since once we step the sigint will be caught and continue won't stop. I disable the warning since the user can do nothing about it [08/05/23]
        #Force = True IS needed if you have a callback on that address... [10/05/23]
        # I will keep the step this way to warn the user
        priority = self.raise_priority("avoid race condition in continue until")
        self.cont(wait=True, force=force)
        # Should we take into consideration the inferior too ? [29/04/23]
        while self.instruction_pointer != address:
            log.info(f"[{self.pid}] stopped at {self.reverse_lookup (self.instruction_pointer)} for '{self._stop_reason}' instead of {self.reverse_lookup(address)}")
            log.warn_once("I assume this happened because you are using gdb manually. Finish what you are doing and let the process run. I will handle the rest")
            wont_use_this_priority = self.execute_action("", sender="continue just to reset the wait")
            # I don't trust the previous priority, while the first one should be safe
            self.priority_wait(comment="continue_until", priority = priority + 1)
            # TODO check that the process didn't exit. [21/10/23]
        self.lower_priority("avoid race condition in continue until")
        done.set()

    def __continue_until_libdebug(self, address, done, force):
        self.cont(wait=True, force=force)
        while self.instruction_pointer != address:
            log.critical("error in continue until")
            log.warn(f"[{self.pid}] stopped at {self.reverse_lookup(self.instruction_pointer)} with status {hex(self.libdebug.stop_status)} instead of {self.reverse_lookup(address)}")
            # Not tested yet [22/07/23]. I just want to avoid having the debugger crash while emulating ptrace because the process is sent a SIGSTOP
            sleep(1)
        done.set()
            
    # I'm worried about how to handle the lock in this case [12/06/23] I want to block until I send the continue
    # I would like to keep the same priority for step and continue [18/06/23]
    def continue_until(self, location, /, *, wait=True, force=False, loop = False, hw=False):
        """
        Continue until a specific address
        can be blocking or non blocking thanks to wait
        It the function is called from the address you want to reach the intended behaviour is to do nothing and return. Set loop=True to continue anyway
        
        """ 
        with self.ptrace_lock.log("continue_until"):
            done = Event()

            if not self.debugging:
                done.set()
                log.warn_once(DEBUG_OFF)
                return done

            self.restore_arch()

            address = self.parse_address(location)
            if not loop and address == self.instruction_pointer:
                log.warn(f"I'm already at {self.reverse_lookup(address)}")
                log.warn_once("Be careful that the default behaviour changed. Use loop=True if you want to continue anyway")
                return
                
            self.b(address, temporary=True, user_defined=False, hw=hw)
            self._logger.debug("continuing until %s", self.reverse_lookup(address))

            if self.gdb is not None:
                context.Thread(target=self.__continue_until_gdb, args=(address, done, force), name=f"[{self.pid}] continue_until").start()
            elif self.libdebug is not None:
                context.Thread(target=self.__continue_until_libdebug, args=(address, done, force), name=f"[{self.pid}] continue_until").start()
            else:
                ...
            # Wait for the next lock to be set
            sleep(0.02)

        if wait:
            done.wait()
            return self
        else:
            return done

    until = continue_until


    def wait(self, timeout=None, legacy=False):
        """
        Wait for the process to stop after an action.
        Won't return until all future actions have been handled so that you can use it at the same time in your script and in a breakpoint
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if legacy:
            self.myStopped.wait(timeout)
        else:
            self.priority_wait("standard wait")

    # This should only be used under the hood, but how do we let the other one to the user without generating problems ? [14/04/23]
    def priority_wait(self, comment="?", priority=None):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self.myStopped.priority_wait(comment, priority)
            
    # problems when I haven't executed anything
    @property
    def running(self):
        with context.silent:
            if self.gdb is not None:
                try:
                    getattr(self, self.registers[0])
                    return False
                except:
                    return True
            elif self.libdebug is not None:
                return not self.libdebug._test_execution()
            else:
                ...

    @property
    def priority(self):
        return self.myStopped.priority

    @priority.setter
    def priority(self, value):
        self.myStopped.priority = value

    def raise_priority(self, comment):
        self.myStopped.raise_priority(comment)
        return self.priority

    def lower_priority(self, comment):
        self.myStopped.lower_priority(comment)
        return self.priority

    def __clear_stop(self, name="someone", /):
        if self.gdb is not None:
            pid = self.current_inferior.pid
        elif self.libdebug is not None:
            pid = self.pid # Handle thread
        else:
            ...

        if self.myStopped.is_set():
            #self._logger.debug("[%d] stopped has been cleared by %s", pid, name)
            self.myStopped.clear(name)

    #def __hidden_stop(self, name="someone", /):
    #    if self.gdb is not None:
    #        pid = self.current_inferior.pid
    #    elif self.libdebug is not None:
    #        pid = self.pid # Handle thread
    #    else:
    #        ...
    #    if self.myStopped.is_set():
    #        log.debug(f"[{pid}] stopped has been hidden_cleared by {name}")
    #        self.myStopped.hidden_clear()

    def __set_stop(self, comment = ""):
        if self.gdb is not None:
            pid = self.current_inferior.pid
        elif self.libdebug is not None:
            pid = self.pid # Handle thread
        else:
            ...        
        if comment:
            self._logger.debug("[%d] setting stopped in 0x%x for %s", pid, self.instruction_pointer, comment) # no reverse lookup ? [13/08/23]
        else:
            self._logger.debug("[%d] setting stopped in 0x%x", pid, self.instruction_pointer)
        # handle case where no action are performed after the end of a callback with high priority 
        self.myStopped.pid = pid
        self.__clear_stop(comment)
        self.myStopped.set()

    def __enforce_stop(self, comment):
        self.myStopped.flag_enforce_stop = self.myStopped.priority
        self._logger.debug("enforcing stop from level %d for reason: %s", self.myStopped.flag_enforce_stop, comment)

    #def wait_fork(self):
    #    self.gdb.forked.wait()
    #    self.gdb.forked.clear()

    def wait_split(self):
        """
        Wait for the process to fork
        set_split_on_fork() must be set before the call to fork

        Return:
            pid: pid of the child process
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        pid = self.split.get()
        if pid == 0:
            raise Exception("What the fuck happened with split ???")
        return pid

    # For now is handled by simple wait [06/03/23]
    def wait_exit(self):
        self.closed.wait()

    def wait_master(self):
        self.ptace_can_continue.wait()
        self.ptace_can_continue.clear()

    # TODO make sure the slave didn't stop for a user breakpoint !
    # Handle all options: https://stackoverflow.com/questions/21248840/example-of-waitpid-in-use
    def wait_slave(self, options=0x40000000):
        if options == 0x1: # WHNOHANG
            log.info("waitpid WNOHANG! Won't stop")
            # Check first that the slave isn't running in case ptrace_has_stopped hasn't been cleared correctly ? Clear it in hidden_continue instead of PTRACE_CONT ? [27/06/23]
            stopped = self.ptrace_has_stopped.is_set()
        else: 
            self.ptrace_has_stopped.wait()
            stopped = True

        # I can't clear it only here ! A wrong SIGSTOP in the step before a continue would set it again [22/07/23] 
        if stopped:
            self.ptrace_has_stopped.clear()

        return stopped

    def __interrupt_gdb(self):
        pass

    def __interrupt_libdebug(self):
        pass

    # Maybe should be the one returning if the process did stop due to the interrupt or not [13/06/23]
    # Breakpoint callbacks should be handled before the interruption to simplify the logic and I guess that if we reach a breakpoint and still send a SIGINT the signal will arive later 
    @lock_decorator
    def interrupt(self, strict=True):
        # claim priority asap
        priority = self.raise_priority("interrupt")
        self.restore_arch()
        
        if not self.debugging:
            # Who cares, right ?
            #self.lower_priority("no process to interrupt")
            log.warn_once(DEBUG_OFF)
            return

        if not self.running:
            self.lower_priority("release interrupt")
            # Must go after the lower_priority() to let other threads see it [19/06/23]
            # Do I really need a set stop ?? [26/07/23]
            self.__set_stop("Release interrupt. I didn't have to stop")
            return False

        self.interrupted = True
        self._logger.debug("interrupting [pid:%d]", self.pid)
        # SIGSTOP is too common in gdb
        self._logger.debug("sending SIGINT")
        os.kill(self.pid, signal.SIGINT)
        self.priority_wait(comment="interrupt", priority = priority)
        # For now it will be someone else problem the fact that we sent the SIGINT when we arived on a breakpoint or something similar. [21/07/23] Think about how to catch it without breaking the other threads that are waiting
        # TODO check that we did indeed took over the control [17/10/23] (BUG interrupt while reading doesn't work)
        if self._stop_reason != "SIGINT":
            # Catch del SIGINT
            self._logger.debug("We hit a breakpoint before the SIGINT... I will continue stepping to catch them.")
            
            # I must make sure the callbacks aren't called each time!
            address = self.instruction_pointer
            saved_callbacks = []
            for bp in self.breakpoints[address]:
                saved_callbacks.append(bp.callback)
                bp.callback = None
            
            # After this we finaly reached the signal, so we are good to continue
            res = self.step_until_condition(lambda dbg: dbg._stop_reason == "SIGINT", limit=5)
            if address != self.instruction_pointer:
                log.warn("Oups, I made a mistake trying to catch the SIGINT...")
            elif res == -1:
                log.warn("What the fuck happened with the SIGINT ? I never found it...")
            for bp, callback in zip(self.breakpoints[address], saved_callbacks):
                bp.callback = callback
            return INTERRUPT_SENT | INTERRUPT_HIT_BREAKPOINT

        return INTERRUPT_SENT

    manual = interrupt


    def _step(self, signal=0x0):
            address = self.instruction_pointer

            self._logger.debug("stepping from 0x%x", self.instruction_pointer)
            if self.gdb is not None:
                if signal:
                    self.signal(signal, step=True)
                else:
                    priority = self.execute_action("si", sender="step")
            elif self.libdebug is not None:
                priority = self.execute_action(lambda: self.libdebug.step(signal=signal), sender="step")
            else:
                ...
            
            self.priority_wait(comment="step", priority = priority)
            
            return address != self.instruction_pointer


    # Next may break again on the same address, but not step
    # Why isn't force = True the default behaviour ? [29/04/23]
    # I don't use force=True by default because there are instructions that keep the instruction pointer at the same address even if executed [05/05/23]
    # You need force=True on continue to avoid double call to callbacks [30/05/23]
    @lock_decorator
    def step(self, repeat:int=1, *, force=False, signal=0x0):
        """
        execute a single instruction

        Argument:
            repeat: step n times
            force : if the stackframe has been tampered with gdb may stay stuck on the current instruction. Use force to handle this bug in gdb
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self.restore_arch()
        # Should only be the first step, right ? [08/05/23]
        if force:
            self.__broken_step()
            repeat -= 1

        for _ in range(repeat):
        
            self.stepped = True

            if not self._step(signal):
                log.warn("You stepped, but the address didn't change. This may be due to a bug in gdb. If this wasn't the intended behaviour use force=True in the function step or continue you just called")

        return self

    si = step

    # I should catch SIGSTOP, but not other exceptions
    def __broken_step(self):
        old_ip = self.instruction_pointer
        callback = None

        # Remove callback to avoid calling it twice (Nice, this wasn't possible with legacy_callbacks) (I'm not sure if we could simply disable a breakpoint for a turn)
        saved_callbacks = []
        for breakpoint in self.breakpoints[old_ip]:
            saved_callbacks.append(breakpoint.callback)
            breakpoint.callback = None
        with context.silent:
            # Let's talk... Usually the problem is with SIGSTOP, right ? There are cases where we jump on a signal, so we won't always have a SINGLE STEP. 
            #n = self.step_until_condition(lambda self: self.instruction_pointer != old_ip or self._stop_reason == "SINGLE STEP", limit=5)
            # I don't understand how you can have a stop for single step without changing, but it happens [12/06/23]
            n = self.step_until_condition(lambda self: self.instruction_pointer != old_ip or self._stop_reason not in ["SIGSTOP", "SINGLE STEP"], limit=5)
        if n == -1:
            raise Exception("Could not force step!")
        if n > 0:
            self._logger.debug("Bug still present. Had to force %d time(s)", n)

        for breakpoint, callback in zip(self.breakpoints[old_ip], saved_callbacks):
            breakpoint.callback = callback

    # For backward compatibility
    exit_broken_function = __broken_step

    # Should I implement a wait = False here to in case an input is needed ? [28/04/23] (In the meanwhile handle it in the callback)
    def step_until_address(self, location: [int, str], callback=None, limit:int=10_000) -> int:
        """
        step until a particular address is reached.
        Useful to analyse self modifying functions.
        
        Arguments:
            location: address or symbol to reach
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        address = self.parse_address(location)
        for i in range(limit):
            if callback is not None:
                callback(self)
            if self.instruction_pointer == address:
                return i
                break
            self.step()
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the address you are looking for...")
            return -1

    # May be wrong for RISC-V
    def step_until_ret(self, callback=None, limit:int=10_000) -> int:
        """
        step until the end of the function

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            if callback is not None:
                callback(self)
            if self.next_inst.mnemonic == "ret":
                return i
                break
            self.step()
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the end of the function...")
            return -1

    def step_until_condition(self, condition, limit=10_000):
        """
        Step until condition(self) returns True or limit exceeded
        The condition will be tested after the first step
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            self.step()
            if condition(self):
                return i

        # Why not raise exception ? [10/05/23]
        log.warn_once(f"I made {limit} steps and haven't found what you are looking for...")
        return -1

    def step_until_call(self, callback=None, limit=10_000):
        """
        step until a call to a function
        will look inside the function if the first instruction is already a call

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            self.step()
            if callback is not None:
                callback(self)
            if self.next_inst.is_call:
                return i
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the end of the function...")
            return -1

    def __next(self, repeat, done):
        for _ in range(repeat):
            next_inst = self.next_inst
            if next_inst.is_call:
                self.continue_until(self.instruction_pointer+next_inst.size)
            else:
                self.step()
        done.set()

    # May not want to wait if you are going over a functions that need user interaction
    def next(self, wait:bool=True, repeat:int=1):
        done = Event()

        if not self.debugging:
            done.set()
            log.warn_once(DEBUG_OFF)
            return done
        
        context.Thread(target=self.__next, args=(repeat, done), name=f"[{self.pid}] next").start()
        if wait:
            done.wait()
            return self
        else:
            return done

    ni = next

    def next_until_call(self, callback=None, limit=10_000):
        """
        step until the end of the function
        will continue over the first function if called when already before a call

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for i in range(limit):
            self.next()
            if callback is not None:
                callback(self)
            if self.next_inst.is_call:
                return i
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the end of the function...")
            return -1

    def __finish(self, repeat, force, done):
        # Should be possible to take immediatly the corresponding stack frame instead of using a loop [28/04/23]
        for _ in range(repeat):
            ip = self.__saved_ip
            self._logger.debug("finish found next ip : 0x%x", ip)
            if ip == 0:
                raise Exception("stack frame is broken or we are not in a function")
            if ip == self.instruction_pointer:
                log.warn(f"wait, we already are at the address {hex(ip)}!")
                log.warn("Trying experimental finish. Use dbg.execute('finish') if this doesn't work")
                ip = self._find_rip()
            self.continue_until(ip, force=force)
        if done is not None:
            done.set()

    # May be dependent on the stack frame and cause problems after a jump [27/04/23]
    def finish(self, *, wait:bool=True, repeat = 1, force = False):
        done = Event()    
        
        if not self.debugging:
            done.set()
            log.warn_once(DEBUG_OFF)
            return done
        
        context.Thread(target=self.__finish, args=(repeat, force, done), name=f"[{self.pid}] finish").start()
        if wait:
            done.wait()
            return self
        else:
            return done

    def __jump_gdb(self, address):
        # BUG setting rip this way may cause problems with si [30/04/23] 
        #self.instruction_pointer = address
        self.b(address, temporary=True, user_defined=False)
        priority = self.execute_action(f"jump *{hex(address)}", sender="jump")
        self.priority_wait(comment="jump", priority = priority)

    def __jump_libdebug(self, address):
        self.instruction_pointer = address

    # How to handle a jump no wait without destroying the priority queue ? [17/04/23]
    # Don't let it as an option... [17/04/23]
    def jump(self, location: [int, str]):
        """
        Jump to specified location
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self.restore_arch()

        #log.warn_once("jump is deprecated. Overwrite directly the instruction pointer instead")
        address = self.parse_address(location)

        # I end up allowing it because to skip a syscall I have to jump, but gdb thinks I'm already at the next instruction [26/07/23]
        #if address == self.instruction_pointer:
        #    self._logger.debug("not jumping because I'm already at %s", self.reverse_lookup(address))
        #    return
        
        self._logger.debug("jumping to %s", self.reverse_lookup(address))
        if self.gdb is not None:
            self.__jump_gdb(address)
        elif self.libdebug is not None:
            self.__jump_libdebug(address)
        else:
            ...
        return self
        
    # Now can return from anywhere in the function
    # Works only for standard functions (push rbp; mov rbp, rsp; ...; leave; ret;). May crash if used in the libc
    # Can't I use __saved_ip now ? [28/04/23]
    def ret(self, value: int = None):
        """
        Exit from current function without executing it. 

        Warning: Experimental and depends on the stack frame
        """
        raise Exception("Not implemented yet")
        if self.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
            pass
        elif self.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
            self.pop() # Remove the base pointer # No need to place it back in rbp
        else:
            self.stack_pointer = self.base_pointer
            self.base_pointer = self.pop()
        ret_address = self.pop()
        self.jump(ret_address)
        if value is not None:
            self.return_value = value
        return self

    # For some reasons we get int3 some times
    # Now it's even worse. SIGABORT after that...
    def gdb_call(self, function: str, args: list, *, cast = "long"):
        if not self.elf.statically_linked:
            try:
                ans = self.execute(f"call ({cast}) {function} ({', '.join([hex(arg) for arg in args])})")
                if cast == "void":
                    ret = None
                else:
                    ans = ans.split()[-1]
                    # GEF prints logs as base 16, but pwndbg as base 10
                    ret = int(ans, 16) if "0x" in ans else int(ans)
            except Exception: #gdb.error: The program being debugged was signalled while in a function called from GDB.
                self._logger.debug("gdb got int3 executing %s. Retrying...", function)
                self.finish()
                # For some reason I just get 0x0
                #return self.return_value()
                ret = self.gdb_call(function, args) # Should work this time
        elif function in self.symbols:
            ret = self.call(self.symbols[function], args)
            
        else:
            raise Exception(f"I don't know how to handle this function! {function} not in symbols")

        return ret

    def __convert_args(self, args, heap = True):
        """
        Save any string present in the args and return a pointer to it instead
        """
        parsed_args, to_free = [], []
        
        for arg in args:
            if type(arg) is str:
                arg = arg.encode() + b"\x00"
            
            if type(arg) is bytes:
                if heap:
                    log.warn_once("I'm calling malloc to save your data. Use heap=False if you want me to save it in the BSS (experimental)")
                pointer = self.alloc(len(arg), heap=heap) # I should probably put the null byte only for string in case I have to pass a structure...
                to_free.append((pointer, len(arg))) #I include the length to virtually clear the bss too if needed (I won't set it to \x00 though)
                self.write(pointer, arg)
                arg = pointer

            parsed_args.append(arg)

        return parsed_args, to_free

    def __continue_call(self, backup, to_free, heap, end_pointer, return_value, alignement):
        #if end_pointer == self.instruction_pointer: # We called the function while on the first instruction, let's just step and continue normaly [21/05/23] Wait, why bother ?
        # But this only works for intel processors. Use loop=True instead and you won't care if you started on the first instruction
        self.continue_until(end_pointer, loop=True)
        #while unpack(self.read(self.stack_pointer - context.bytes, context.bytes)) != end_pointer:
        #    assert self.instruction_pointer == end_pointer, "Something strange happened in a call"
        #    log.warn_once("Are you sure you called the function from outside ?")
        #    self.continue_until(end_pointer)

        self._logger.debug("call finished")
                
        res = self.return_value
        for _ in range(alignement):
            self.pop()
        self.restore_backup(backup)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        return_value.put(res) # will be the event that tells me I finished

    # I still need end_pointer even if I would like to put the breakpoint on the address from which we call the function because I can't be sure that someone won't want to call a function from inside 
    # Wait, finish is doing it anyway... So let's require that call isn't used while you are inside the function, but still handle it just in case. Like a check that *(rsp - bytes) -> rip. It's not perfect, but it should at least always be true if we used the function properly [21/05/23]
    def call(self, function: [int, str], args: list = [], *, heap=True, wait = True):
        """
        Call any function in the binary with the parameters you want

        Parameters
        ----------
        function : [str, int]
            Pointer to the function to call
        args : list[int | str | bytes]
            List of parameters to pass to the function
            All strings passed this way will be saved in the binary with a null terminator
            Byte arrays will be saved as they are
        end_pointer : int, optional
            The function will run with a 'finish' command. If you aren't calling a standard function use this parameter. (I currently expect it to be a ret and will step on it to leave)
        heap : bool, optional
            Byte arrays and strings passed to the functions are by default saved on the heap with a malloc(). If you can't set this to False to save them on the bss (WARNING I can't guaranty I won't overwrite data this way)
        
        Return:
        return_value: [int, Queue]
        if wait = True the functions return the content of rax, othewise the queue where it will be put once the function finishes
        """
        self.restore_arch()
        
        if not self.debugging:
            log.warn_once(DEBUG_OFF)

        address = self.parse_address(function)
        self._logger.debug("calling %s", self.reverse_lookup(address))

        args, to_free  = self.__convert_args(args, heap)

        #save registers 
        backup = self.backup()    
        
        for register in function_calling_convention[context.arch]:
            if len(args) == 0:
                break
            self._logger.debug("%s setted to %s", register, args[0])
            setattr(self, register, args.pop(0))
            
        #Should I offset the stack pointer to preserve the stack frame ? No, right ?
        for arg in args:
            self.push(arg)
        
        return_address = self.instruction_pointer
        
        # Libc functions may die otherwise
        alignement = 0
        while self.stack_pointer % 0x10 != 0x0:
            self.push(0)
        if context.arch in ["i386", "amd64"]:
            self.push(return_address)
        elif context.arch == "aarch64":
            self.x30 = return_address
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            self.ra = return_address

        self.jump(address)
        
        return_value = Queue()
        context.Thread(target=self.__continue_call, args=(backup, to_free, heap, return_address, return_value, alignement), name=f"[{self.pid}] call").start()
        if wait:
            return return_value.get()
        else:
            log.warn_once("you decided not to wait for the call to finish. I return a queue to the return value of the function. When you need it use .get() to wait for the call to finish")
            return return_value

    def handle_signal(self, signal: [int, str], callback):
        if type(signal) is str:
            signal = signal.upper()
        else:
            SIGNALS_from_num[signal]
        if self.gdb is not None:
            self.execute(f"handle {signal} stop nopass")
        self.handled_signals[SIGNALS[signal]] = callback

    def signal(self, n: [int, str], /, *, handler : [int, str] = None, step=False):
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

        # To send a signal ptrace has to resume the execution of the process so we put a breakpoint and wait for the handler to finish executing
        # If the code is self modifying you must use handler otherwise the breakpoint will be overwritten with bad code [26/02/23]
        # Now a hardware breakpoint should be enough, but I keep the handler if you don't have enough breakpoints. [30/07/23]
        if handler is None:
            #self.b(self.instruction_pointer, temporary=True, user_defined=False)
            # TODO warn if hw fails
            self.b(self.instruction_pointer, temporary=True, user_defined=False, hw=True)
        else:
            from queue import Queue
            my_address = Queue()
            my_address.put(self.instruction_pointer)
            def callback(dbg):
                address = my_address.get()
                my_address.put(dbg.instruction_pointer)
                dbg.b(address, temporary=True, user_defined=False)
                return False  
            self.b(handler, callback=callback, temporary=True, user_defined=False)
        if self.gdb is not None:
            if type(n) is int:
                log.warn_once("Remember that gdb uses a different order for the signals. It is advised to use directly the name of the signal")
            if step:
                self.execute(f"queue-signal {n}")
                self.step()
            else:
                priority = self.execute_action(f"signal {n}", sender="signal")
                self.priority_wait(comment=f"signal {n}", priority = priority)
        elif self.libdebug is not None:
            if type(n) is str:
                n = n.upper()
                n = SIGNALS[n]
            self._logger.debug("sending signal 0x%x -> %s", n, SIGNALS_from_num[n])
            if step:
                self.step(signal=n)
            else:
                self.c(signal=n)
        else:
            ...

        return self

    def syscall(self, code: int, args: list, *, heap = True):
        self._logger.debug("syscall %d: %s", code, args)
        
        args = [code] + args

        shellcode = shellcode_syscall[context.arch]
        calling_convention = syscall_calling_convention[context.arch]

        assert len(args) <= len(calling_convention), "too many arguments for syscall"

        backup_registers = self.backup()
        return_address = self.instruction_pointer
        # GDB has a bug with QEMU where I can't patch the code
        if context.arch in ["aarch64", "riscv"]:
            # Doesn't work because I can't get the base of the binary from qemu
            address = self.elf.data.find(shellcode) 
            self.jump(address)
        else:
            backup_memory = self.read(return_address, len(shellcode))
            self.write(return_address, shellcode)

        args, to_free = self.__convert_args(args, heap)

        for register, arg in zip(calling_convention, args):
            self._logger.debug("%s setted to %s", register, arg)
            setattr(self, register, arg)
    
        self.step()
        res = self.return_value
        self.restore_backup(backup_registers)
        if context.arch not in ["aarch64", "riscv"]:
            self.write(return_address, backup_memory)
        self.jump(return_address)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        
        return res

    # We could do better regarding the num, like using the stop event to know which breakpoint we hit, but we'll think about it later [25/07/23]
    # Do we want a single callback per breakpoint or allow a list ?
    def catch_syscall(self, name: str, callback):
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
        """
        if self.gdb is None:
            raise Exception("not implemented yet in libdebug")

        if context.arch in ["riscv", "riscv32", "riscv64"]:
            log.warn_once("catch syscall not supported for RISCV")
            return None

        # To avoid multiple breakpoints for the same syscall which may break my way of handling them [27/07/23]
        if name in self.syscall_table:
            self._logger.debug("there is already a catchpoint for %s... Overwriting...", name)
            self.syscall_breakpoints[self.syscall_table[name]] = callback
        else:
            self.execute(f"catch syscall {name}")
            num = self.gdb.breakpoints()[-1].number
            self.syscall_table[name] = num
            self.syscall_breakpoints[num] = callback

        return self

    handle_syscall = catch_syscall

    def delete_catch(self, name: str):
        self._logger.debug("deleting syscall %s", name)
        try:
            bp = self.syscall_table.pop(name)
        except KeyError:
            log.warn("syscall %s is not being catched", name)
            return
        self.syscall_breakpoints.pop(bp)
        self.execute(f"delete {bp}")
        return self

    # TODO take a library for relative addresses like libdebug
    def parse_address(self, location: [int, str]) -> str:
        """
        parse symbols and relative addresses to return the absolute address
        """
        if type(location) is int:
            address = location
            if location < 0x010000:
                address += self.base_elf

        elif type(location) is str:
            function = location
            offset = 0
            if "+" in location:
                # die if more than 1 +, but that's your fault
                function, offset = [x.strip() for x in location.split("+")]
                offset = int(offset, 16) if "0x" in offset.lower() else int(offset)
            address = self.symbols[function] + offset

        else:
            raise Exception(f"parse_breakpoint is asking what is the type of {location}")
        
        return address

    # Legacy
    parse_for_breakpoint = parse_address

    def reverse_lookup(self, address: [int, str]) -> str:
        if type(address) is str:
            return address
        elif type(address) is int:
            if address in self.symbols.values():
                function = list(self.symbols.keys())[list(self.symbols.values()).index(address)]
                return f"{function}({hex(address)})"
            else:
                return hex(address)
        else:
            ...

    def __breakpoint_gdb(self, address, legacy_callback=None, hw=False):
        # Still needed for hidden breakpoint with return False when you want to also use gdb manually [17/04/23]
        if legacy_callback is not None:
            log.warn_once("if your callbacks crash you may not notice it and you have to scroll a bit to find the error messages hidden in the gdb terminal")
            # I don't know yet how to handle the conn if I don't go through self.gdb.Breakpoint so I create the class here :(
            class MyBreakpoint(self.gdb.Breakpoint):
                def __init__(_self, address, hw):
                    if hw:
                        super().__init__(address, type=self.gdb.BP_HARDWARE_BREAKPOINT)
                    else:
                        super().__init__(address)
                    _self.callback = legacy_callback
                # WARNING IF A TEMPORARY BREAKPOINT DOESN'T STOP IT WON'T COUNT AS HIT AND STAY ACTIVE. May cause problems with the callback if you pass multiple times [26/02/23]
                def stop(_self, *args):
                    _break = _self.callback(self) 
                    if _break is None:
                        return True
                    return _break
            res = MyBreakpoint(f"*{hex(address)}", hw)

        else:
            if hw:
                res = self.gdb.Breakpoint(f"*{hex(address)}", type=self.gdb.BP_HARDWARE_BREAKPOINT)
            else:
                res = self.gdb.Breakpoint(f"*{hex(address)}")
        return res

    def __breakpoint_libdebug(self, address, hw=False):
        return self.libdebug.breakpoint(address, hw=hw)

    # May want to put breakpoints relative to the libc too?
    # I want to keep legacy breakpoints for the ones I set with the library because we must be able to work manually when emulating ptrace [23/03/23]
    # legacy_callback will be deprecated once I can overwrite gdb's nexti to keep his breakpoint even if the process gets interrupted [27/04/23]
    def b(self, location: [int, str], callback=None, legacy_callback=None, temporary=False, user_defined=True, hw=False):
        """
        Set a breakpoint in your process.

        Parameters
        ----------
        address : int or str
            If address is and integer smaller than 0x10000 the address will be interpreted as a relative address
            Breakpoints are accessible from self.breakpoints as a dictionary where the key is hex(address) or the name of the function
        callback : FUNCTION, optional
            Pass a function to execute when the breakpoint is reached.
            callback takes a pointer to the debugger as parameter and should return True if you want to interrupt the execution and False otherwise. If you forget a return value the default behaviour is to interrupt the process when reaching the breakpoint
            You can use Queue to pass data between your exploit and the callbacks
        temporary : BOOL, optional
            Don't save the breakpoint and disable it when hit
        user_defined : BOOL, restricted
            Flag to identify breakpoints set by the library from the ones used by the users. Don't touch it.

        Returns
        -------
        Breakpoint
            Return a pointer to the breakpoint set
            I don't see when you would need it, but here it is
        """

        # Move from callback to real_callback
        # real_callbacks have problems, but with features not even available with simple callbacks. Furthermore now you can use return False with temporary breakpoints
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        address = self.parse_address(location)

        if hw:
            self._logger.debug("putting hardware breakpoint in %s", self.reverse_lookup(address))
        else:
            self._logger.debug("putting breakpoint in %s", self.reverse_lookup(address))
        
        if self.gdb is not None:
            breakpoint = Breakpoint(self.__breakpoint_gdb(address, legacy_callback, hw=hw).server_breakpoint, address, callback, temporary, user_defined)
        elif self.libdebug is not None:
            if legacy_callback is not None:
                callback = legacy_callback
            breakpoint = Breakpoint(self.__breakpoint_libdebug(address, hw=hw), address, callback, temporary, user_defined)
        else:
            ...

        self.breakpoints[address].append(breakpoint)
        return breakpoint
        
    breakpoint = b

    def tb(self, *args, **argw):
        return self.b(*args, **argw, temporary=True)

    def delete_breakpoint(self, breakpoint: [int, str, Breakpoint]) -> bool:
        """
        Delete a particular breakpoint
        If an address (or symbol) is passed the only user defined at that address will be deleted
        
        If possible pass the breakpoint itself
        """

        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if type(breakpoint) is not Breakpoint:
            location = breakpoint
            address = self.parse_address(location)
            # Is there a case where it isn't ?? [17/04/23]
            user_breakpoints = [b for b in self.breakpoints[address] if b.user_defined]
            if len(user_breakpoints) == 0:
                raise Exception(f"No breakpoint at address {hex(address)}")
            if len(user_breakpoints) > 1:
                raise Exception(f"You set multiple breakpoint at {hex(address)}! Which one should I delete ???")
            breakpoint = user_breakpoints[0]

        self.breakpoints[breakpoint.address].pop(self.breakpoints[breakpoint.address].index(breakpoint))
        if self.gdb is not None:
            breakpoint.native_breakpoint.delete() # Remove from dict and delete from gdb
        elif self.libdebug is not None:
            self.libdebug.del_bp(breakpoint.native_breakpoint)
        else:
            ...

    def __bruteforce(self, init, setup, _to, check, range, backup, result, shutdown, libdebug):
        self.restore_arch()
        # Riconnetti gli eventi di gdb con il nuovo processo 
        self.migrate(libdebug=True)
        if not libdebug:
            self.migrate(gdb=True)
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

    def __bruteforce(self, threads, init, setup, _to, check, backup, result, shutdown, libdebug):
        self.restore_arch()
        # Riconnetti gli eventi di gdb con il nuovo processo 
        for child, _ in threads:
            child.migrate(libdebug=True)
            if not libdebug:
                child.migrate(gdb=True)
        for child, range in threads:
            context.Thread(target=child.__bruteforce_thread, args=(init, setup, _to, check, range, backup, result, shutdown, libdebug), name=f"[{self.pid}] bruteforce [{range.start}:{range.stop}]").start()
        shutdown.wait()

    def __bruteforce_thread(self, init, setup, _to, check, range, backup, result, shutdown, libdebug):
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

    def bruteforce(self, _to, check, _from=None, setup=None, init=None, limit=1000, backup = [], libdebug=False, n_threads=1, n_processes=cpu_count()):
        log.warn("Bruteforce is experimental! Function may break and names may change")
        parallel = n_threads * n_processes
        result = p_Queue()
        shutdown = p_Event()
        processes = []
        if _from is not None:
            self.jump(_from)
        _to = self.parse_address(_to)
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
            processes.append(Process(target=child.__bruteforce, args=(threads, init, setup, _to, check, backup, result, shutdown, libdebug)))
        progress.success("all threads are ready")
        self.detach()
        #if libdebug:
        #    log.debug(f"{self.gdb=}")
        #    self.migrate(libdebug=True)
        #processes.append(context.Thread(target=self.__bruteforce, args=(init, setup, _to, check, range(n), backup, result, shutdown, libdebug)))
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

    ########################## MEMORY ACCESS ##########################

    def __read_gdb(self, address: int, size: int, *, inferior = None) -> bytes:

        if inferior == None:
            inferior = self.current_inferior

        #self._logger.debug("reading from inferior %d, [pid: %d]", inferior.num, inferior.pid)
        return self.inferiors[inferior.num].read_memory(address, size).tobytes()

    def read(self, address: int, size: int, *, inferior = None, pid = None) -> bytes:
        if inferior is not None:
            pid = inferior.pid
        if pid is None:
            pid = self.pid

        if self.gdb is not None and context.arch:
            return self.__read_gdb(address, size, inferior=inferior)

        # Can not read inside qemu
        with open(f"/proc/{pid}/mem", "r+b") as fd:
            fd.seek(address)
            return fd.read(size)

    def __write_gdb(self, address: int, byte_array: bytes, *, inferior = None):

        if inferior == None:
            inferior = self.current_inferior
        
        try:
            inferior.write_memory(address, byte_array)
        except Exception as e: #gdb.MemoryError
            log.warn(e)


    # How to handle multiple processes ?
    def __write_libdebug(self, address: int, byte_array: bytes, *, pid = None):
        if pid is not None:
            ...

    # Do we want to handle here that if address is none we allocate ourself a pointer ? [17/11/23]
    def write(self, address: int, byte_array: bytes, *, inferior = None, pid = None):
        if inferior is not None:
            pid = inferior.pid
        if pid is None:
            pid = self.pid

        self._logger.debug("writing %s at 0x%x", byte_array.hex(), address)
        
        # BUG: GDB writes in the wrong inferior...
        if self.gdb is not None and inferior is None:
            return self.__write_gdb(address, byte_array)

        # Fail if area not writable
        with open(f"/proc/{pid}/mem", "r+b") as fd:
            fd.seek(address)
            fd.write(byte_array)

    # Names should be singular or plurals ? I wanted singular for read and plural for write but it should be consistent [02/06/23]
    # I assume little endianess [02/06/23]
    def read_ints(self, address: int, n: int) -> list:
        address = self.parse_address(address)
        data = self.read(address, n*4)
        return [u32(data[i*4:(i+1)*4]) for i in range(n)]
    
    def read_int(self, address: int) -> int:
        return self.read_ints(address, 1)[0]

    def read_longs(self, address: int, n: int) -> list:
        address = self.parse_address(address)
        data = self.read(address, n*8)
        return [u64(data[i*8:(i+1)*8]) for i in range(n)]

    def read_long(self, address: int) -> int:
        return self.read_longs(address, 1)[0]

    def read_pointers(self, address: int, n: int) -> list:
        return self.read_longs(address, n) if context.bits == 64 else self.read_int(address, n)
    
    def read_pointer(self, address: int) -> int:
        return self.read_pointers(address, 1)[0]

    # Should we return the null bytes ? No, consistent with write_strings [02/06/23]
    def read_strings(self, address: int, n: int) -> list:
        address = self.parse_address(address)
        chunk = 0x100
        data = b""
        i = 0
        while data.count(b"\x00") <= n:
            data += self.read(address + chunk*i, chunk)
            i += 1
        return data.split(b"\x00")[:n]
        
    def read_string(self, address: int) -> bytes:
        return self.read_strings(address, 1)[0]

    def write_ints(self, address: int, values: list, *, heap = True) -> int:
        data = b"".join([p32(x) for x in values])
        if address is None:
            address = self.alloc(len(data), heap=heap)
        else:
            address = self.parse_address(address)
        self.write(address, data)
        return address

    def write_int(self, address: int, value: int, *, heap = True) -> int:
        return self.write_ints(address, [value], heap = heap)

    def write_longs(self, address: int, values: list, *, heap = True) -> int:
        data = b"".join([p64(x) for x in values])
        if address is None:
            address = self.alloc(len(data), heap=heap)
        else:
            address = self.parse_address(address)
        self.write(address, data)
        return address

    def write_long(self, address: int, value: int, *, heap = True) -> int:
        return self.write_longs(address, [value], heap = heap)

    def write_pointers(self, address: int, values: list, *, heap = True) -> list:
        return self.write_longs(address, values, heap = heap) if context.bits == 64 else self.write_int(address, values, heap = heap)
    
    def write_pointer(self, address: int, value: int, *, heap = True) -> int:
        return self.write_pointers(address, [value], heap = heap)

    # If the user has a byte array and doesn't want the null byte he would just write it himself, right ? [17/11/23] 
    def write_strings(self, address, values: list, *, heap = True) -> int:
        """
        save a list of strings after adding a null byte to all of them. 
        
        If address in None a pointer to the first string will be returned.
        """
        values = [value.encode() if type(value) is str else value for value in values]
        data = b"\x00".join(values) + b"\x00" # Better be safe than sorry. We are working with strings anyway, so who cares if we have one more byte [21/10/23]
        
        if address is None:
            address = self.alloc(len(data), heap=heap)
        else:
            address = self.parse_address(address)
        self.write(address, data)
        return address

    def write_string(self, address: int, value: str, *, heap = True) -> int:
        """
        save a string after adding a null byte to it. 

        If address in None a pointer to the string will be returned.
        """
        return self.write_strings(address, [value], heap = heap)

    def push(self, value: int):
        """
        push value (must be uint) on the stack
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self._logger.debug("pushing 0x%x", value)
        self.stack_pointer -= context.bytes
        self.write(self.stack_pointer, pack(value))

    def pop(self) -> int:
        """
        pop value (uint) from the stack
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        data = self.read(self.stack_pointer, context.bytes)
        self.stack_pointer += context.bytes
        return unpack(data)

    # alloc and dealloc instead of malloc and free because you may want to keep those names for function in your exploit

    # what is this error ??? [04/03/23]
    #gdb.error: The program being debugged was signaled while in a function called from GDB.
    #GDB remains in the frame where the signal was received.
    #To change this behavior use "set unwindonsignal on".
    #Evaluation of the expression containing the function
    #(__GI___libc_malloc) will be abandoned.
    #When the function is done executing, GDB will silently stop.
    
    def alloc(self, n: int, /, *, heap=True) -> int:
        """
        Allocate N bytes in the heap or [if really needed] the bss

        Parameters
        ----------
        n : int
            Size to allocate
        heap : bool, optional
            Set to False if you can't use the heap
            This way it will return a pointer to an area of the bss
        Returns
        -------
        pointer
        """
        if heap and "malloc" not in self.symbols:
            log.warn("Can not find malloc. Data will be allocated on the BSS!")
            heap = False

        if heap:
            if self.gdb is not None:
                # Do we wan't to use call for both ? [10/05/23]
                ret = self.gdb_call("malloc", [n])
            elif self.libdebug is not None:
                ret = self.call("malloc", [n])
            else:
                ...
        else:
            if self._free_bss is None:
                self._free_bss = self.elf.bss() # I have to think about how to preserve eventual data already present
            self._free_bss += n
            ret = self._free_bss
        
        return ret

    def dealloc(self, pointer: int, len=0, heap=True):
        
        if heap:    
            if self.gdb is not None:
                self.gdb_call("free", [pointer], cast="void")
            elif self.libdebug is not None:
                self.call("free", [pointer])
            else:
                ...
        else:
            # MMMMMMM, not perfect for different inferiors
            self._free_bss -= len
            #I know it's not perfect, but damn I don't want to implement a heap logic for the bss ahahah
            #Just use the heap if you can

    def nop(self, address, instructions = 1):
        self.restore_arch()
        address = self.parse_address(address)
        code = self.disassemble(address, instructions*10)
        size = 0
        for i in range(instructions):
            size += next(code).size
        backup = self.read(address, size)
        self.write(address, nop[context.arch] * (size // len(nop[context.arch])))
        return backup


    # Quick attempt to find maps
    @property
    def maps(self):
        maps_raw = open(f"/proc/{self.pid}/maps").read()
        maps = {}
        for line in maps_raw.splitlines():
            line = line.split()
            start, end = line[0].split("-")
            maps[int(start, 16)] = int(end, 16) - int(start, 16)
        return maps

    # I copied it from pwntools to have access to it even if I attach directly to a pid
    # The problem is that with qemu we get the addresses in qemu and not in the virtual memory... [01/08/23]
    def libs(self):
        """libs() -> dict
        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.
        """
        try:
            maps_raw = open(f"/proc/{self.pid}/maps").read()
        except IOError:
            maps_raw = None

        # Enumerate all of the libraries actually loaded right now.
        maps = {}
        for line in maps_raw.splitlines():
            if '/' not in line: continue
            path = line[line.index('/'):]
            path = os.path.realpath(path)
            if path not in maps:
                maps[path]=0

        for lib in maps:
            path = os.path.realpath(lib)
            for line in maps_raw.splitlines():
                if line.endswith(path):
                    address = line.split('-')[0]
                    maps[lib] = int(address, 16)
                    break

        return maps
    
    # get base address of libc
    def get_base_libc(self):
        if self.libc is None:
            log.warn_once("I don't see a libc ! Set dbg.libc = ELF(<path_to_libc>)")
            return 0
        maps = self.libs()
        if "/usr/bin/qemu" in "".join(maps.keys()):
            log.warn("I don't know how to access the libraries in qemu :(")
            self.libc = None
            return 0
        if len(maps) != 0:
            return maps[self.libc.path]
        else:
            log.warn("I can't access /proc/%d/maps", self.pid)
            #data = self.execute("info files")
            #for line in data.split("\n"):
            #    line = line.strip()
            #    if "libc" in line and line.startswith("0x"):
            #        address = int(line.split()[0], 16)
            #        return address - address % 0x1000

    @property
    def base_libc(self):
        if self._base_libc is None:
            self._base_libc = self.get_base_libc()
        return self._base_libc

    # get base address of binary
    # Wrong for qemu
    def get_base_elf(self):
        maps = self.libs()
        # Not perfect, but is a first filter
        if "/usr/bin/qemu" in "".join(maps.keys()):
            log.warn("process is running under qemu! I hope you are using pwndbg...")
            log.warn("I don't know how to access the libraries in qemu :(")
            self.libc = None
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            data = ansi_escape.sub('', self.execute("vmmap"))
            for line in data.splitlines():
                if self.elf.path.split("/")[-1] in line:
                    return int(line.strip().split()[0], 16)
            raise Exception("can't find binary address")

        if len(maps) != 0:
            return maps[self.elf.path]
        
        else:
            log.warn("I can't access /proc/%d/maps", self.pid)
            # The following part doesn't work properly [28/02/23]
            #data = self.execute("info files")
            #for line in data.split("\n"):
            #    line = line.strip()
            #    if line.startswith("Entry point:"):
            #        address = int(line.split()[-1], 16)
            #        log.debug(f"Entry point = {hex(address)}")
            #        return address - address%0x1000 #Not always true...
                    

    @property # I don't wan't to rely on self.elf.address which isn't set by default for PIE binaries
    def base_elf(self):
        # I don't want to set it myself either because I want to be able to test leak == dbg.base_elf during my exploit
        #if self.elf.address == 0:
        #    self.elf.address = self.get_base_elf()
        #return self.elf.address
        if self._base_elf is None:
            self._base_elf = self.get_base_elf()
        return self._base_elf

    # TODO handle multiple libraries
    @property
    def symbols(self):
        if hasattr(self, "libc") and self.libc is not None and self.libc is not False: # If I attack to a pid I self.p doesn't have libc = None
            # WARNING >= 3.9
            #return self.elf.symbols | self.libc.symbols
            return {**self.elf.symbols, **self.libc.symbols} # Should work in 3.8
        else:
            return self.elf.symbols

    # taken from GEF to locate the canary
    @property
    def auxiliary_vector(self):
        if not self._auxiliary_vector:
            auxiliary_vector = {}
            auxv_info = self.execute("info auxv")
            if "failed" in auxv_info:
                err(auxv_info)
                return None
            for line in auxv_info.splitlines():
                line = line.split('"')[0].strip()  # remove the ending string (if any)
                line = line.split()  # split the string by whitespace(s)
                if len(line) < 4:
                    continue
                __av_type = line[1]
                __av_value = line[-1]
                auxiliary_vector[__av_type] = int(__av_value, base=0)
            self._auxiliary_vector = auxiliary_vector
        return self._auxiliary_vector

    # The canary is constant right ? This way you can also set it after a leak and access it from anywhere
    @property
    def canary(self):
        if self._canary is None:
            auxval = self.auxiliary_vector
            canary_location = auxval["AT_RANDOM"]
            canary = self.read(canary_location, context.bytes)
            self._canary = b"\x00"+canary[1:]
        return self._canary
     
    @property
    def special_registers(self):
        if context.arch in ["i386", "amd64"]:
            return ["eflags", "cs", "ss", "ds", "es", "fs", "gs"]
        elif context.arch == "aarch64":
            return ["cpsr", "fpsr", "fpcr", "vg"]
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            return []
        else:
            raise Exception(f"what arch is {context.arch}")

    # WARNING reset expects the last two registers to be sp and ip. backup expects the last register to be ip
    @property
    def registers(self):
        if context.arch == "aarch64":
            return [f"x{i}" for i in range(31)] + ["sp", "pc"]
        elif context.arch == "i386":
            return ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]
        elif context.arch == "amd64":
            return ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp", "rip"]
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            return [f"t{i}" for i in range(7)] + [f"s{i}" for i in range(12)] + [f"a{i}" for i in range(8)] + ["ra", "gp", "tp", "sp"] + ["pc"]
        else:
            raise Exception(f"what arch is {context.arch}")

    # Making ax accessible will probably be faster that having to write 
    @property
    def minor_registers(self):
        if context.arch == "aarch64":
            return [f"w{x}" for x in range(31)]
        elif context.arch == "i386":    
            return ["ax", "al", "ah",
        "bx", " bh", "bl",
        "cx", " ch", "cl",
        "dx", " dh", "dl",
        "si", "sil",
        "di", "dil",
        "sp", "spl",
        "bp", "bpl"]
        elif context.arch == "amd64":
            return ["ax", "al", "ah",
        "bx", " bh", "bl",
        "cx", " ch", "cl",
        "dx", " dh", "dl",
        "si", "sil",
        "di", "dil",
        "sp", "spl",
        "bp", "bpl"] + ["eax", "ebx", "ecx", "edx", "esi", "edi",
            "r8d", "r8w", "r8l",
            "r9d", "r9w", "r9l",
            "r10d", "r10w", "r10l",
            "r11d", "r11w", "r11l",            
            "r12d", "r12w", "r12l",
            "r13d", "r13w", "r13l",
            "r14d", "r14w", "r14l",
            "r15d", "r15w", "r15l"]
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            return []
        else:
            raise Exception(f"what arch is {context.arch}")

    @property
    def next_inst(self):
        inst = next(self.disassemble(self.instruction_pointer, 16)) #15 bytes is the maximum size for an instruction in x64
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        if context.arch in ["amd64", "i386"]:
            inst.is_call = inst.mnemonic == "call"
        elif context.arch == "aarch64":
            inst.is_call = inst.mnemonic == "bl"
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            inst.is_call = inst.mnemonic == "jal"
        else:
            ...
        return inst

    # May be usefull for Inner_Debugger
    def disassemble(self, address, size):
        if self._capstone is None:
            if context.arch == "amd64":
                self._capstone = Cs(CS_ARCH_X86, CS_MODE_64)
            elif context.arch == "i386":
                self._capstone = Cs(CS_ARCH_X86, CS_MODE_32)
            elif context.arch == "aarch64":
                self._capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            elif context.arch in ["riscv", "riscv32", "riscv64"]:
                self._capstone = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC) #CS_MODE_RISCV32 if context.bits == 32 else CS_MODE_RISCV64)
            else:
                raise Exception(f"what arch is {context.arch}")

        return self._capstone.disasm(self.read(address, size), address)

    ########################## Generic references ##########################

    @property
    def return_value(self):
        if context.arch == "amd64":
            return self.rax
        elif context.arch == "i386":
            return self.eax
        elif context.arch == "aarch64":
            return self.x0 # Not always true
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            return self.a0
        else:
            ...

    @return_value.setter
    def return_value(self, value):
        if context.arch == "amd64":
            self.rax = value
        elif context.arch == "i386":
            self.eax = value
        elif context.arch == "aarch64":
            self.x0 = value # Not always true
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            self.a0 = value # Sometimes a1 is also used
        else:
            ...


    @property
    def stack_pointer(self):
        if context.arch == "amd64":
            return self.rsp
        elif context.arch == "i386":
            return self.esp
        elif context.arch == "aarch64":
            return self.sp
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            return self.sp
        else:
            ...

    # issue: setting $sp is not allowed when other stack frames are selected... https://sourceware.org/gdb/onlinedocs/gdb/Registers.html [04/03/23]
    @stack_pointer.setter
    def stack_pointer(self, value):
        # May move this line to push and pop if someone can argue a good reason to.
        if context.arch == "amd64":
            self.rsp = value
        elif context.arch == "i386":
            self.esp = value
        elif context.arch == "aarch64":
            self.sp = value
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            self.sp = value
        else:
            ...
        while self.stack_pointer != value:
            if self.gdb is None:
                raise Exception("Error setting stack pointer!")

            self._logger.debug("forcing last frame")
            self.execute("select-frame 0") # I don't know what frames are for, but if you need to push or pop you just want to work on the current frame i guess ? [04/03/23]

            if context.arch == "amd64":
                self.rsp = value
            elif context.arch == "i386":
                self.esp = value
            elif context.arch == "aarch64":
                self.sp = value
            elif context.arch in ["riscv", "riscv32", "riscv64"]:
                self.sp = value
            else:
                ...

    @property
    def base_pointer(self):
        if context.arch == "amd64":
            return self.rbp
        elif context.arch == "i386":
            return self.ebp
        elif context.arch == "aarch64":
            ...
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            ...
        else:
            ...
    
    @base_pointer.setter
    def base_pointer(self, value):
        if context.arch == "amd64":
            self.rbp = value
        elif context.arch == "i386":
            self.ebp = value
        elif context.arch == "aarch64":
            ...
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            ...
        else:
            ...

    # Prevent null pointers
    @property
    def instruction_pointer(self):
        ans = 0
        while ans == 0:
            # what about self.gdb.newest_frame().pc() ? [28/04/23]
            if context.arch == "amd64":
                ans = self.rip
            elif context.arch == "i386":
                try:
                    ans = self.eip
                except Exception as e:
                    print(e)
                    pwn.log.error("I failed retriving eip! make sure you are using the right context.arch")
            elif context.arch == "aarch64":
                ans = self.pc
            elif context.arch in ["riscv", "riscv32", "riscv64"]:
                ans = self.pc
            else:
                ...
            if ans == 0:
                log.warn("null pointer in ip ! retrying...")
        return ans

    @instruction_pointer.setter
    def instruction_pointer(self, value):
        if context.arch == "amd64":
            self.rip = value
        elif context.arch == "i386":
            self.eip = value
        elif context.arch == "aarch64":
            self.pc = value
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            self.pc = value
        else:
            ...

    def _find_rip(self):
        self.restore_arch()
        # experimental, but should be better that the native one for libdebug        
        if self.base_pointer:
            if self.next_inst.toString() in ["endbr64", "push rbp", "push ebp", "ret"]:
                return_pointer = self.read(self.stack_pointer, context.bytes)
            elif self.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                return_pointer = self.read(self.stack_pointer + context.bytes, context.bytes) # Remove the base pointer # No need to place it back in rbp
            else:
                return_pointer = self.read(self.base_pointer + context.bytes, context.bytes)

        else:
            # At least, this is the case with fork and works better than gdb.
            return_pointer = self.read(self.stack_pointer, context.bytes)
        
        return unpack(return_pointer)       

    @property
    def __saved_ip(self):
        if context.arch == "aarch64":
            return self.x30
        elif context.arch in ["riscv", "riscv32", "riscv64"]:
            return self.ra

        # Doesn't work with qemu [05/07/23]
        elif self.gdb is not None:
            return self.gdb.newest_frame().older().pc()

        elif self.libdebug is not None:
            return self._find_rip()     

        else:
            ...

        ## rip = 0x7ffff7fe45b8 in _dl_start_final (./elf/rtld.c:507); saved rip = 0x7ffff7fe32b8
        #data = self.execute("info frame 0").split("\n")
        #log.debug(data)
        #for line in data:
        #    if " saved " in line and "ip = " in line:
        #        ip = line.split("saved ")[-1].split("= ")[-1]
        #        if "<" in ip:
        #            return 0
        #        return int(ip, 16)

    @property
    def return_pointer(self):
        return self.__saved_ip

    ########################## FORKS ##########################
    # TODO find a better name [28/02/23]
    # TODO make inferior and n the same parameter ? [04/03/23]

    # Call shellcode has problems: https://sourceware.org/gdb/onlinedocs/gdb/Registers.html. Can't push rip
    # Warn that the child will still be in the middle of the fork [26/04/23]
    # TODO support split for libdebug [02/06/23] (Will require a new patch to libdebug)
    # I thought about setting emulate_ptrace for the child if it is set in the parent, but I want to let the user free of chosing the parameters they wants [23/07/23]
    def split_child(self, *, pid = None, inferior=None, n=None, script=""):
        self.restore_arch()
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
                    raise Exception(f"How am I expected to find which child you whant ??")

        self._logger.debug("splitting inferior %d, [pid: %d]", inferior.num, inferior.pid)
        n = inferior.num
        pid = inferior.pid
        old_inferior = self.switch_inferior(n)
        ip = self.instruction_pointer
        backup = self.inject_sleep(ip)
        self.switch_inferior(old_inferior.num)
        self._logger.debug("detaching from child [%d]", pid)
        self.execute(f"detach inferiors {n}")
        child = Debugger(pid, binary=self.elf.path, script=script)
        # needed even though by default they both inherit the module's priority since the user may change the priority of a specific debugger. [17/11/23]
        child._logger.setLevel(self._logger.level)
        # TODO copy all sycall handlers in the parent ? [31/07/23]
        # Copy libc since child can't take it from process [04/06/23]
        child.libc = self.libc
        # Set parent for ptrace [08/06/23]
        child.parent = self
        _logger.debug("new debugger opened")
        child.write(ip, backup)
        child._logger.debug("shellcode patched")
        child.jump(ip)

        # GEF puts a breakpoint after the fork...
        if self.gdb is not None and self.gef:
            bps = child.gdb.breakpoints()
            if len(bps) > 0:
                bp = bps[-1]
                if bp.location == "*" + hex(child.instruction_pointer + 1):
                    bp.delete()
        
        return child  
    
    # entrambi dovrebbero essere interrotti, il parent alla fine di fork, il child a metà
    # Ho deciso di lasciare correre il parent. Te la gestisci te se vuoi mettere un breakpoint mettilo dopo
    # I just discovered "gdb.events.new_inferior"... I can take the pid from event.inferior.pid, but can I do more ?
    def set_split_on_fork(self, off=False, c=False, keep_breakpoints=False, interrupt=False, script=""):
        """
        split out a new debugging session for the child process every time you hit a fork

        Arguments:
            off: disable feature
            interrupt: stop parent when forking

        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self

        if off:
            self.execute("set detach-on-fork on")
            #if self.symbols["fork"] in self.breakpoints:
            #    self.breakpoints["fork"].enabled = False
            #    del self.breakpoints["fork"]

            # Will break if not set on before
            self.gdb.events.new_inferior.disconnect(self.fork_handler)
                
        else:
            self.execute("set detach-on-fork off")

            # The interrupt may give me problems with continue_until
            def fork_handler(event):
                inferior = event.inferior
                pid = inferior.pid        
                #self.to_split.put(pid)
                def split(inferior):
                    # claim priority asap
                    self.raise_priority("split")

                    self.restore_arch()
                    
                    log.info(f"splitting child: {inferior.pid}")
                    # Am I the reason why the process stopped ?
                    stopped = self.interrupt()
                    self.children[pid] = self.split_child(inferior=inferior, script=script)
                    # Should not continue if I reached the breakpoint before the split
                    self.lower_priority("release split")
                    self.split.put(pid)
                    if not interrupt and stopped & INTERRUPT_SENT and not stopped & INTERRUPT_HIT_BREAKPOINT:
                        self.__hidden_continue()
                    elif interrupt:
                        self.__set_stop("forked")
                    else:
                        self.__set_stop("We hit a breakpoint while interrupting the process. Handle it!")
                            
                ## Non puoi eseguire azioni dentro ad un handler degli eventi quindi lancio in un thread a parte
                context.Thread(target=split, args = (inferior,), name=f"[{self.pid}] split_fork").start()

            self.fork_handler = fork_handler
            self.gdb.events.new_inferior.connect(self.fork_handler)
            
            return self

    split_on_fork = set_split_on_fork

    # Take all processes related
    @property
    def ptrace_group(self):
        if self.parent is not None:
            return self.parent.ptrace_group

        return {p.pid: p for p in self.recursive_children}

    # Take all grand-children
    @property
    def recursive_children(self):
        group = {self}
        for child in self.children.values():
            group |= child.recursive_children
        return group

    # I want a single function so that each process can be both master and slave [08/06/23]
    # I use real callback as long as we are breaking on the function it should work. The problem is if we start catch the syscall instead [08/06/23] Why ? [28/07/23]
    # Should we split the "manual" between ptrace and waitpid ? So that I can only wait for the later ? For now I will put the breakpoint a bit later so that you can do continue_until("waitpid") [28/07/23]
    # TODO teach how to add symbols in a binary for the functions if the code is statically linked and stripped
    def emulate_ptrace(self, *, off=False, wait_fun="waitpid", wait_syscall="wait4", manual=False, silent=False, signals = ["SIGSTOP"], syscall=False):
        self.restore_arch()

        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return self
        
        if off:
            if self.ptrace_syscall:
                log.warn("I still don't know how to disable the emulation with syscall")
                return

            for bp in self.ptrace_breakpoints:
                self.delete_breakpoint(bp)

            for address, backup in self.ptrace_backups.items():
                self.write(address, backup)
            self.ptrace_emulated = False
            return

        self.ptrace_emulated = True
        if syscall:
            assert self.gdb is not None, "libdebug can't catch ptrace syscall. Emulate with syscall = False"
            self.ptrace_syscall = True
        
        # TODO HANDLE CATCHPOINTS AS BREAKPOINTS TO DELETE THEM
        if len(self.ptrace_breakpoints):
            log.warn(f"[{self.pid}] is already emulating ptrace")
            return

        self._logger.debug("emulating ptrace")

        if self.gdb is not None:
            # When emulating ptrace SIGSTOP is suposed to be used between the processes and catched by waitpid, so I don't pass it to the process to avoid problems [22/07/23]
            # https://stackoverflow.com/questions/10415739/gdb-gives-me-infinite-program-received-signal-sigtstp-when-i-try-to-resume
            for signal in signals:
                self.execute(f"handle {signal} stop nopass")

        # Waiting for pwntools update
        constants.PTRACE_SEIZE = 0x4206
        if context.arch == "amd64":
            constants.PTRACE_GETREGS = 12
            constants.PTRACE_SETREGS = 13
            constants.PTRACE_SETOPTIONS = 0x4200 # really ??
            constants.PTRACE_O_EXITKILL = 0x00100000
            constants.PTRACE_O_SUSPEND_SECCOMP = 0x00200000
            constants.PTRACE_O_MASK     = 0x003000ff


        ptrace_dict = {constants.PTRACE_TRACEME: self.PTRACE_TRACEME,
            constants.PTRACE_POKEDATA: self.PTRACE_POKETEXT,
            constants.PTRACE_POKETEXT: self.PTRACE_POKETEXT, 
            constants.PTRACE_PEEKTEXT: self.PTRACE_PEEKTEXT, 
            constants.PTRACE_PEEKDATA: self.PTRACE_PEEKTEXT, 
            constants.PTRACE_GETREGS: self.PTRACE_GETREGS, 
            constants.PTRACE_SETREGS: self.PTRACE_SETREGS,
            constants.PTRACE_ATTACH: self.PTRACE_ATTACH,
            constants.PTRACE_SEIZE: self.PTRACE_SEIZE,
            constants.PTRACE_CONT: self.PTRACE_CONT,
            constants.PTRACE_DETACH: self.PTRACE_DETACH,
            constants.PTRACE_SETOPTIONS: self.PTRACE_SETOPTIONS,
            constants.PTRACE_SINGLESTEP: self.PTRACE_SINGLESTEP,}
        
        if syscall:
            def callback_wait(dbg, entry):
                def callback(dbg): 
                    pid = dbg.syscall_args[0]
                    status_pointer = dbg.syscall_args[1]
                    options = dbg.syscall_args[2]
 
                    if pid == 2**32 - 1:
                        assert len(dbg.slaves) == 1, "For now I can only handle waitpid(-1) if there is only one slave"
                        pid = list(dbg.slaves.keys())[0]
                        self._logger.debug("waiting for -1...")
                    
                    log.info(f'waitpid for process [{pid}]')
                    if pid not in self.ptrace_group:
                        raise Exception(f"We reached waitpid but we didn't have time to split the new process! Please stop the process earlier")
                    if pid not in self.slaves:
                        log.warn("The process hasn't called TRACEME yet. I will wait... (just make sure you didn't setup ptrace_emulation too late)")
                    while pid not in self.slaves:
                        sleep(0.2)
                    tracee = dbg.slaves[pid]
                    stopped = tracee.wait_slave(options)

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
                    log.info(f"setting status waitpid: {hex(status_pointer)} -> [{hex(status)}]")
                    dbg.write(status_pointer, p32(status))
                    # I don't handle the errors yet [19/06/23]
                    # I would have liked it, but for now we have a bug if ret jumps on an address where we have a breakpoint that should stop, but our return False let the process run anyway [09/06/23]
                    # Now it should work, but I don't want to risk it ahah [23/06/23]
                    #dbg.ret()
                    # Don't stop for a NOHANG [09/06/23]


                    # For some reason after the setoption it continues even with manual = False, but stops after continue... 
                    if manual and stopped:
                        tracee.__set_stop("waitpid asked to stop")
                        return True
                    else:
                        return False

                if silent:
                    with context.silent:
                        should_stop = callback(dbg)
                else:
                    should_stop = callback(dbg)
                return SKIP_SYSCALL | should_stop
            self.catch_syscall(wait_syscall, callback_wait)

            def ptrace_callback(dbg, entry):
                def callback(dbg):
                    ptrace_command = dbg.syscall_args[0]
                    pid = dbg.syscall_args[1]
                    arg1 = dbg.syscall_args[2]
                    arg2 = dbg.syscall_args[3]
                    
                    log.info(f"[{dbg.pid}] ptrace {pid} -> {ptrace_command}: ({hex(arg1)}, {hex(arg2)})")
                    action = ptrace_dict[ptrace_command]

                    if ptrace_command == constants.PTRACE_TRACEME:
                        tracer = dbg if dbg.parent is None else dbg.parent
                        
                        if dbg.pid not in tracer.slaves:
                            log.info(f"TRACEME: [{dbg.pid}] will be trace by [{tracer.pid}]")
                            should_stop = action(tracer, manual=manual)
                            return SKIP_SYSCALL | manual

                        else:
                            log.warn(f"[{dbg.pid}] is already traced !")
                            dbg.return_value = -1
                            return SKIP_SYSCALL | manual

                    elif ptrace_command in [constants.PTRACE_ATTACH, constants.PTRACE_SEIZE]:
                        
                        if pid in dbg.slaves:
                            log.warn(f"[{pid}] is already traced !")
                            dbg.return_value = -1
                            return SKIP_SYSCALL | manual

                        else:
                            tracee = dbg.ptrace_group[pid]
                            should_stop = action(pid, arg2, slave=tracee, manual=manual)

                    else:
                        tracee = dbg.slaves[pid]
                        should_stop = action(arg1, arg2, slave=tracee, manual=manual)

                    return should_stop

                if silent:
                    with context.silent:
                        should_stop = callback(dbg)
                else:
                    should_stop = callback(dbg)
                return SKIP_SYSCALL | should_stop
            self.catch_syscall("ptrace", ptrace_callback)

        else:
            shellcode = nop[context.arch] + return_instruction[context.arch]
            address = self.parse_address(wait_fun)
            backup = self.read(address, len(shellcode))
            self.write(address, shellcode)
            self.ptrace_backups[address] = backup

            def callback_wait(dbg):
                def callback(dbg):
                    pid = dbg.args[0]
                    status_pointer = dbg.args[1]
                    options = dbg.args[2]

                    if pid == 2**32 - 1:
                        assert len(dbg.slaves) == 1, "For now I can only handle waitpid(-1) if there is only one slave"
                        pid = list(dbg.slaves.keys())[0]
                        self._logger.debug("waiting for -1...")
                    
                    log.info(f'waitpid for process [{pid}]')
                    if pid not in self.ptrace_group:
                        raise Exception(f"We reached waitpid but we didn't have time to split the new process! Please stop the process earlier")
                    if pid not in self.slaves:
                        log.warn("The process hasn't called TRACEME yet. I will wait... (just make sure you didn't setup ptrace_emulation too late)")
                    while pid not in self.slaves:
                        sleep(0.2)
                    tracee = dbg.slaves[pid]
                    stopped = tracee.wait_slave(options)

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
                    log.info(f"setting status waitpid: {hex(status_pointer)} -> [{hex(status)}]")
                    dbg.write(status_pointer, p32(status))
                    # I don't handle the errors yet [19/06/23]
                    # I would have liked it, but for now we have a bug if ret jumps on an address where we have a breakpoint that should stop, but our return False let the process run anyway [09/06/23]
                    # Now it should work, but I don't want to risk it ahah [23/06/23]
                    #dbg.ret()
                    # Don't stop for a NOHANG [09/06/23]
                    if manual and stopped:
                        slave.__set_stop("waitpid asked to stop")
                        return True
                    else:
                        return False

                if silent:
                    with context.silent:
                        return callback(dbg)
                else:
                    return callback(dbg)

            self.ptrace_breakpoints.append(self.b(wait_fun + "+1", callback=callback_wait, user_defined=False))

            address = self.parse_address("ptrace")
            backup = self.read(address, len(shellcode))
            self.write(address, shellcode)
            self.ptrace_backups[address] = backup

            def ptrace_callback(dbg):
                def callback(dbg):
                    ptrace_command = dbg.args[0]
                    pid = dbg.args[1]
                    arg1 = dbg.args[2]
                    arg2 = dbg.args[3]
            # Legacy_callback so that the program does run off if we step over the breakpoint manualy
            # Is this still needed ? [05/05/23] # Yes, you have to patch gdb's implementation of nexti and finish first
            # I will use a normal callback. Just use IPython dbg.next() if you have to step manually [08/06/23]
                    
                    log.info(f"[{dbg.pid}] ptrace {pid} -> {ptrace_command}: ({hex(arg1)}, {hex(arg2)})")
                    action = ptrace_dict[ptrace_command]

                    if ptrace_command == constants.PTRACE_TRACEME:
                        tracer = dbg if dbg.parent is None else dbg.parent
                        
                        if dbg.pid not in tracer.slaves:
                            log.info(f"TRACEME: [{dbg.pid}] will be trace by [{tracer.pid}]")
                            action(tracer, manual=manual)
                            return False

                        else:
                            log.warn(f"[{dbg.pid}] is already traced !")
                            dbg.return_value = -1
                            return False

                    elif ptrace_command in [constants.PTRACE_ATTACH, constants.PTRACE_SEIZE]:
                        
                        if pid in dbg.slaves:
                            log.warn(f"[{pid}] is already traced !")
                            dbg.return_value = -1
                            return False

                        else:
                            tracee = dbg.ptrace_group[pid]
                            should_stop = action(pid, arg2, slave=tracee, manual=manual)

                    else:
                        tracee = dbg.slaves[pid]
                        should_stop = action(arg1, arg2, slave=tracee, manual=manual)

                    return should_stop

                if silent:
                    with context.silent:
                        return callback(dbg)
                else:
                    return callback(dbg)

            # Legacy_callback so that the program does run off if we step over the breakpoint manualy
            # Is this still needed ? [05/05/23] # Yes, you have to patch gdb's implementation of nexti and finish first
            # I will use a normal callback. Just use IPython dbg.next() if you have to step manually [08/06/23]
            self.ptrace_breakpoints.append(self.b("ptrace+1", callback=ptrace_callback, user_defined=False))

        return self

    ########################## PTRACE EMULATION ##########################
    # If attach and interrupt stop the process I want continue and detach to let it run again, otherwise just set ptrace_can_continue [08/06/23]
    # Should we handle the interruptions in a special way ? Like adding a priority when attaching ? [08/06/23] (But how to handle stop due to a SIGNAL ?)

    # We could do a return False or True depending on if we interrupted the process or not. A small indication if we are debugging manually or not [08/06/23]
    def PTRACE_ATTACH(self, pid, _, *, slave, **kwargs):
        log.info(f"pretending to attach to process {pid}")
        self.slaves[pid] = slave
        #if slave.running:
        #    log.info(f"attach will interrupt the slave")
        #    slave.interrupt()
        #    # It makes no sense because any signal interruption would not be hable to distinguish if we were manually debugging or not [08/06/23] (Not really, but it would require a lot of work)
        #    #slave.ptrace_interrupted = True
        self.PTRACE_INTERRUPT(..., ..., slave=slave)
        slave.ptrace_has_stopped.set()
        self.return_value = 0
        return False

    def PTRACE_SEIZE(self, pid, options, *, slave, **kwargs):
        log.info(f"pretending to seize process {slave.pid}")
        self.PTRACE_SETOPTIONS(pid, options, slave=slave)
        self.slaves[pid] = slave
        self.return_value = 0x0
        return False

    # Only function called by the slave
    def PTRACE_TRACEME(self, tracer, **kwargs):
        log.info("slave wants to be traced")
        tracer.slaves[self.pid] = self
        log.info(f"setting {self.pid} as slave for {tracer.pid}")
        self.return_value = 0
        # dirt left by ptrace that could be checked
        # Only do it if we don't handle the syscall... [26/07/23]
        #if context.arch == "amd64":
        #    self.r8 = -1
        tracer.ptrace_has_stopped.set()
        return False

    def PTRACE_CONT(self, _, __, *, slave, manual, **kwargs):
        if not manual:
            log.info(f"[{self.pid}] PTRACE_CONT will let the slave [{slave.pid}] continue")
            slave.ptrace_has_stopped.clear()
            slave.__hidden_continue(force=True)
        else:
            slave.ptrace_can_continue.set()
            log.info("slave can continue !")
        self.return_value = 0x0
        return manual

    def PTRACE_DETACH(self, _, __, *, slave, manual, **kwargs):
        log.ingo(f"ptrace detached from {slave.pid}")
        self.slaves.pop(pid)
        slave.ptrace_can_continue.set()
        if not manual:
            log.info(f"detach will let the slave continue")
            self.__hidden_continue(force=True)
        self.return_value = 0x0
        return False

    def PTRACE_POKETEXT(self, address, data, *, slave, **kwargs):
        log.info(f"poking {hex(data)} into process {slave.pid} at address {hex(address)}")
        slave.write(address, pack(data))
        self.return_value = 0 # right ?
        return False

    def PTRACE_PEEKTEXT(self, address, _, *, slave, **kwargs):
        data = unpack(slave.read(address, context.bytes))
        log.info(f"peeking {hex(data)} from process {slave.pid} at address {hex(address)}")
        self.return_value = data
        return False

    def PTRACE_GETREGS(self, _, pointer_registers, *, slave, **kwargs):
        registers = user_regs_struct()
        for register in slave.registers:
            value = getattr(slave, register)
            self._logger.debug("reading [%d]'s register %s: 0x%x", slave.pid, register, value)
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            setattr(registers, register, value)
        self.write(pointer_registers, registers.get())
        self.return_value = 0 # right ?
        return False

    # ATTENTO CHE setattr ritorna prima che vanga fatto correttamente la jump per mettere rip. Quindi potresti avere una race condition [09/06/23]
    def PTRACE_SETREGS(self, _, pointer_registers, *, slave, **kwargs):
        registers = user_regs_struct()
        registers.set(self.read(pointer_registers, registers.size))
        for register in slave.registers:
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            value = getattr(registers, register)
            self._logger.debug("setting [%d]'s register %s: 0x%x", slave.pid, register, value)
            setattr(slave, register, value)
        self.return_value = 0 
        return False

    def PTRACE_SETOPTIONS(self, _, options, *, slave, **kwargs):
        self._logger.debug("0x%x", options)
        if options & constants.PTRACE_O_EXITKILL:
            options -= constants.PTRACE_O_EXITKILL
            log.info("Option EXITKILL set")
            #self._logger.debug("They want to kill the slave if you remove the master")
            self._logger.debug("0x%x", options)
        
        if options & constants.PTRACE_O_TRACESYSGOOD:
            options -= constants.PTRACE_O_TRACESYSGOOD
            log.info("Option TRACESYSGOOD set")
            #log.debug("")
            self._logger.debug("0x%x", options)
            
        if options != 0:
            raise Exception(f"{hex(options)}: Not implemented yet")

        self.return_value = 0x0
        return False

    def PTRACE_SINGLESTEP(self, _, __, *, slave, **kwargs):
        log.info(f"ptrace single step from {slave.reverse_lookup(slave.instruction_pointer)}")
        slave.step()
        self._logger.debug("Telling the slave that it has stopped")
        slave.ptrace_has_stopped.set()
        self.return_value = 0x0
        return False
        
    # NOT TESTED YET
    def PTRACE_INTERRUPT(self, _, __, *, slave, **kwargs):
        # Should I just send a SIGSTOP ? Using interrupt won't make it accessible to waitpid! [23/07/23]
        self._logger.debug("waiting out of breakpoint")
        slave.out_of_breakpoint.wait()
        self._logger.debug("out of breakpoint waited")
        ## 1) does it make sense ? If someone will try running while I interrupt it will try again just after. But this would break any action the master is trying to perform [21/06/23 14:00]
        ## 2) We can't have both this and the lock_wrapper for interrupt
        ##slave.ptrace_lock.can_run.clear()  
        #if slave.running:    
        #    log.info(f"ptrace will interrupt the slave [{slave.pid}]")
        #    slave.interrupt()
        # It won't be hable to continue, right ? [21/06/23 13:30]
        ##slave.ptrace_lock.can_run.set()
        # Is the if needed ? Shouldn't we send the signal everytime even in manual ? [23/07/23]
        if slave.running:
            os.kill(slave.pid, signal.SIGSTOP)
        self.return_value = 0x0

    ########################## REV UTILS ##########################

    # TODO if address set, return backup of area overwriten instead of address
    # TODO parameter "overwritable = False", if set to True save the memory region so that you can send other shellcodes without calling memprotect (Maybe set a larger area that simple len(shellcode) then)
    def inject_shellcode(self, shellcode, *, address = None, skip_mprotect = False, inferior = None):
        """
        Inject a shellcode in the binary.
        By default will allocate an area in the heap and make it executable

        Arguments:
            shellcode: bytes to inject
            address: address where to write. If not set will be allocated with malloc
            skip_mprotect: turn on this flag if the section is already executable
        """

        if inferior == None:
            inferior = self.current_inferior
        
        old_inferior = self.switch_inferior(inferior.num)

        if address is None:
            self._logger.debug("allocating memory for shellcode")
            address = self.alloc(len(shellcode))

        self.restore_arch()
        
        self.write(address, shellcode)
        if skip_mprotect:
            return address
        # How many pages does your shellcode takes
        size = 0x1000 * ((1 + (address + len(shellcode)) // 0x1000) - address // 0x1000)
        #if not self.elf.statically_linked:
        #    ans = self.execute(f"call (long) mprotect({hex(address)}, {hex(size)}, 7)")
        #else:
        if "mprotect" in self.symbols:
            # I can use gdb call, but there are problems if the symbols are "fake" so put a check elf.staticaly_linked if you want to do it [04/03/23]
            ans = self.call(self.symbols["mprotect"], [address & 0xfffffffffffff000, size, constants.PROT_EXEC | constants.PROT_READ | constants.PROT_WRITE])
        ans = self.syscall(constants.SYS_mprotect.real, [address & 0xfffffffffffff000, size, constants.PROT_EXEC | constants.PROT_READ | constants.PROT_WRITE])
        
        self.switch_inferior(old_inferior.num)

        return address

    def inject_sleep(self, address, inferior=None):
        """
        Inject a shellcode that stoppes the execution at a specific address

        Is meant to be used in the binary code, so it expects an address and returns the bytes that have been overwriten
        """
        #test:
        #jmp test
        # I put a nop to let step(force=True) work in case [29/04/23]
        shellcode = shellcode_sleep[context.arch]
        backup = self.read(address, len(shellcode), inferior=inferior)
        self.write(address, shellcode, inferior=inferior)
        return backup

    ##########################  GEF shortcuts   #########################
    def context(self):
        """
        print memory infos as in gdb
        """
        print(self.execute("context"))

    #Works only with GEF. I use them to avoid writing down print(self.execute("heap bins")) every time
    def bins(self):
        print(self.execute("heap bins"))

    def chunks(self):
        print(self.execute("heap chunks"))

    def telescope(self, address=None, length = 10, reference=None):
        """
        reference: int -> print the offset of each pointer from the reference pointer 
        """
        print(self.execute(f"telescope {hex(address) if address is not None else ''} -l {length} {'-r ' + hex(reference) if reference is not None else ''}"))

    ########################### Heresies ##########################
    
    def __getattr__(self, name):
    #    #getattr is only called when an attribute is NOT found in the instance's dictionary
        if name in ["p", "elf"]: #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self.registers in __setattr__
            return False
        if name in self.special_registers + self.registers + self.minor_registers:
            if self.gdb is not None:
                try:
                    res = int(self.gdb.parse_and_eval(f"${name}")) % 2**context.bits
                except:
                    log.warn("error reading register. Retrying...")
                    res = int(self.gdb.parse_and_eval(f"${name}")) % 2**context.bits
            elif self.libdebug is not None:
                res = getattr(self.libdebug, name)
            return res
        elif self.p and hasattr(self.p, name):
            return getattr(self.p, name)
        # May want to also expose in case you want to access something like inferiors() 
        elif self.gdb is not None and hasattr(self.gdb, name):
            return getattr(self.gdb, name)
        elif self.libdebug is not None and hasattr(self.libdebug, name):
            return getattr(self.libdebug, name)
        else:
            # Get better errors when can't resolve properties
            self.__getattribute__(name)

    def __setattr__(self, name, value):
        if self.elf and name in self.special_registers + self.registers + self.minor_registers:
            self.restore_arch()
            if self.gdb is not None:
                if name.lower in ["eip, rip"] and value != self.instruction_pointer:
                    # GDB has a bug when setting rip ! [09/06/23]
                    jump(value)
                else:
                    self.execute(f"set ${name.lower()} = {value % 2**context.bits}")
            elif self.libdebug is not None:
                setattr(self.libdebug, name, value % 2**context.bits)
            else:
                ...
        else:
            super().__setattr__(name, value)

    def __repr__(self) -> str:
        # I'm afraid it may crash if used with remote [17/11/23]
        if self.pid is None:
            return super().__repr__()

        if self.closed.is_set():
            msg = "<exited>"
        elif self.running:
            msg = "<running>"
        else:
            msg = f"<not running> {hex(self.instruction_pointer)}:{self.next_inst.toString()} [{self._stop_reason}]"
        return "Debugger [{:d}] {:s}".format(self.pid, msg)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        # We should also close all children I think [17/11/23]
        for child in self.children.values():
            child.close()