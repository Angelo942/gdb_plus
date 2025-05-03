import pwn
import os
from time import sleep
from functools import partial
from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_RISCV, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN
# Migrate to capstone v6, but keep support for v5
try:
    from capstone import CS_ARCH_AARCH64
except ImportError:
    from capstone import CS_ARCH_ARM64
    CS_ARCH_AARCH64 = CS_ARCH_ARM64
from threading import Event
from queue import Queue
from gdb_plus.utils import *
from collections import defaultdict
from queue import Queue
from math import ceil
from multiprocessing import Process, Event as p_Event, Queue as p_Queue, cpu_count
import re
from functools import cache, cached_property
from elftools.elf.sections import SymbolTableSection


# Logs to debug the library can be enabled by setting DEBUG = True in gdb_plus.utils
_logger = logging.getLogger("gdb_plus")
ch = logging.StreamHandler()
formatter = logging.Formatter("%(name)s:%(funcName)s:%(message)s")
ch.setFormatter(formatter)
_logger.addHandler(ch)
if DEBUG: _logger.level = 10

DEBUG_OFF = "Debug is off, commands won't be executed"

SHOULD_STOP = 0b1
SKIP_SYSCALL = 0b10
# Constants for interrupt
INTERRUPT_SENT = 0b1 # We sent the signal
INTERRUPT_HIT_BREAKPOINT = 0b10 # The process stopped for a breakpoint instead of our signal.


def lock_decorator(func):
    def parse(self, *args, **kwargs):
        with self._ptrace_lock.log(func.__name__):
            result = func(self, *args, **kwargs)
            return result
    return parse

class Debugger:
    # NOTE: If possible patch the rpath (spwn and pwninit do it automatically) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target: [int, process, str, ELF, EXE, list, tuple], *, binary:[str, ELF, EXE]=None, env:dict=None, aslr:bool=True, script:str="", from_start:bool=True, debug_from:int=None, timeout:float=0.5, from_entry:bool=True, silent=True):
        """
        Args:
            target (int, process, str, ELF, EXE, list, tuple):
                - **int**: The pid of a process to debug.
                - **process**: Process to debug
                - **str**: A path to the file to debug.
                - **ELF**: File to debug.
                - **list**: A list of arguments as in process(list)

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

        # To decompile assembly for next_inst
        self._capstone = None 
        
        # Only used to locate the canary
        self._saved_auxiliary_vector = None 

        # Control access to the libraries
        self._exe = None
        self._ld = None
        self._symbols = None
        self._libraries = {}

        self._canary = None
        self._args = None
        self._sys_args = None
        self._closed = Event()
        self._parent = None
        self.children = {} # Maybe put {self.pid: self} as first one
        self._slaves = {} # I keep it to be sure I am tracing them 
        self._ptrace_breakpoints = []
        self._ptrace_backups = {}
        self._ftrace_breakpoints = []
        self._ltrace_breakpoints = []

        self.pid = None
        self._context_params = context.copy() # NOTE: Be careful to check that you are using the right context arch for the binary before calling gdb
        self.silent = silent

        self.p = None
        self.gdb = None
        self.libdebug = None

        # Additional informations on the debugging context.
        self._gef = False
        self._pwndbg = False
        self.local_debugging = True # By default I let it to True, then switch it back if it's not the case

        self._backup_p = None
        self.r = None
        self._host = None
        self._port = 0
        self._kill_threads = Event()

        # Ptrace_cont
        self._out_of_breakpoint = Event()
        self._ptrace_emulated = False
        self._ptrace_syscall = False
        self._ptrace_lock = MyLock(self._out_of_breakpoint, owner=self)
        self._ptrace_can_continue = Event()
        self._ptrace_has_stopped = Event()  
        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        # NOTE: Do we want to save temporary breakpoints too ? [17/04/23]
        self.breakpoints = defaultdict(list)
        # Let's try to reduce race conditions [19/06/23]
        self._stops_to_enforce = 0
        self._breakpoint_handled = Event()

        self._handled_signals = {}
        self.gdbscript = script if script is not None else "" # For non blocking debug_from
        self.debug_from_done = Event()

        # MyEvent allows calls to wait in parallel
        self._myStopped = MyEvent() # Include original event
        self._myStopped.set() # we call __setup_gdb after an attach so the process isn't running. Make just sure this doesn't cause troubles [17/04/23]

        self._cached_registers = {}
        # To know that I'm responsible for the interruption even if there is no callback
        self._stepped = False
        self._interrupted = False
        self._detached = False
        # Maybe not needed (see set_split_on_fork)
        self._last_breakpoint_deleted = 0 # Keep track of the last temporary breakpoint deleted if we really have to know if we hit something

        self._event_table = {}
        self._event_breakpoints = {}
        self._syscall_return = False

        if args.REMOTE or context.noptrace:
            self.debugging = False
            self.local_debugging = False
            self.children = defaultdict(lambda: self) # Is this necessary ? If it's just for split we could change that function to return self
        else:
            self.debugging = True
        
        if args.ASLR:
            aslr = True

        # NOTE: If we know the binary we are sure that binary is defined and of type EXE. [23/01/25]
        # NOTE: Maybe it's good not to rely too much on ELF in case someone wants to use it for different kinds of executables. [08/07/24]
        # NOTE: Should context be the fail-safe or do we want to make it the default ? [23/01/25]
        # Ensure that we have a  binary defined with the exception of when the target is a list, pid or remote gdbserver.
        if type(binary) in [str, ELF]:
            binary = EXE(binary, checksec=False)
        elif binary is None:
            if type(target) is EXE:
                binary = target
            if type(target) in [str, ELF]:
                binary = EXE(target, checksec=False)
            elif type(target) is process:
                binary = EXE(target.elf, checksec=False)
            elif type(context.binary) is ELF:
                binary = EXE(context.binary, checksec=False)
        self._exe = binary

        # TODO test with programs using dlopen
        if self._exe is not None and not self._exe.statically_linked:
            libraries = enum_libs(self._exe)
            for library_name in libraries:
                name = library_name.split(".")[0]
                self._libraries[name] = None

        # NOTE: What happens when the user want's to debug different processes in the same script ? This may break when using a mix of architectures. [05/02/25]
        # Ensure that a context is defined. Must be set before running gdb to make sure to use the emulator if needed.
        if not context.copy().get("arch", False): # Empty context
            if self.exe is not None:
                context.binary = self.exe
                log.info(f"context not set... Using {context}")
                self._context_params = context.copy()
            else:
                log.warn("No context set and no binary given. We recommend setting context.binary at the beginning of your script.")

        # The idea was to let gdb interrupt only one inferior while letting the other one run, but this doesn't work [29/04/23]
        #script = "set target-async on\nset pagination off\nset non-stop on" + script

        # Connect to the process.
        # We assume that connecting to a specific pid, gdbserver or process is only done only outside a pwn challenge so we don't have to handle REMOTE and NOPTRACE 
        # NOTE: This may not be accurate for a remote gdbserver. Someone may have a docker container to debug the challenge. [05/02/25]
        # TODO: Handle tuple and NOPTRACE
        # The cases handled are in order:
        # 1: tuple -> remote gdb server. We assume that we can not communicate or directly access the files we see in memory.
        # 2: int -> pid of the local process. Here too we can not communicate with the process
        # 3: process
        # Those where the cases where we assume the user to be debugging a specific process. Now instead we do consider whether or not the user still wants to launch a process and debug it.
        # 4: any other target
        if type(target) is tuple:
            if len(target) != 2:
                raise Exception("What are you trying to do ? tuples (host, port) are only for connections to a gdbserver")
            self.p = None
            self.gdb = self.__attach_gdb(target, exe=self.exe.path, gdbscript=script)
            self.pid = self.current_inferior.pid
            self.local_debugging = False
        # We should check if we crash when elf.native == False to warn the user to install qemu-user, but elf doesn't exist yet... [06/01/25]
        # Do we try only for context.native == False and context.copy == {} ? [06/01/25]
        elif type(target) is int:
            self.p = None
            self.pid = target
            assert self.exe is not None, "I need a file to work from a pid" # Not really... Let's keep it like this for now, but continue assuming we don't have a real file
            # We may want to run the script only at the end in case the user really insists on putting a continue in it. [17/11/23]
            self.gdb = self.__attach_gdb(target, gdbscript=script)
        elif type(target) is process:
            self.p = target
            self.gdb = self.__attach_gdb(target, gdbscript=script)
        elif args.REMOTE:
            self.p = None
        elif context.noptrace:
            self.p = self.__silence(process, target if isinstance(target, list) else self.exe.path, env=env, aslr=aslr)
        elif from_start:
            try:
                self.p = self.__silence(gdb.debug, target if isinstance(target, list) else self.exe.path, env=env, aslr=aslr, gdbscript=script, api=True)
            except pwn.exception.PwnlibException:
                if not context.native:
                    log.error(f"Could not debug program for {context.arch}. Did you install qemu-user ?")
            self.gdb = self.p.gdb
            # If pwntools doesn't find gdb-multiarch it will still start a normal gdb process but the process wouldn't run.
            if not context.native:
                try: 
                    self.execute("info tasks")
                except Exception:
                    log.error("You need to install gdb-multiarch to debug binaries under qemu!")
        else:
            self.p = self.__silence(process, target if isinstance(target, list) else self.exe.path, env=env, aslr=aslr)
            self.gdb = self.__attach_gdb(self.p, gdbscript=script)

        if type(self.p) is process:
            self.pid = self.p.pid

        if self.pid is not None:
            self.logger = logging.getLogger(f"Debugger-{self.pid}")
        else:
            self.logger = logging.getLogger(f"Remote Debugger")
        self.logger.addHandler(ch)
        self.logger.setLevel(_logger.level)

        # Prevent confusion between exe.symbols pointing to the plt and libc.symbols pointing to the function itself.
        if self.exe is not None and not self.exe.statically_linked:
            for symbol_name in self.exe.plt:
                if (symbol := self.exe.symbols.get(symbol_name, None)) is not None:
                    del symbol
        
        self._initialized = True
        if self.debugging:

            self.__setup_gdb()

            # NOTE: Start debugging from a specific address. Wait timeout seconds for the program to reach that address. Is blocking so you may need to use context.Thread() in some cases
            # NOTE: WARNING don't use 'continue' in your gdbscript when using debug_from ! [17/04/23]
            # NOTE: I don't like that this is blocking, so you can't interact while waiting... Can we do it differently ? [17/04/23]
            if debug_from is not None:
                # NOTE: I can't attach again to the process if we are under an emulator
                assert context.native, "debug_from isn't supported in qemu"
                address_debug_from = self._parse_address(debug_from)
                backup = self.inject_sleep(address_debug_from)
                while True:  
                    self.detach()
                    sleep(timeout)
                    # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
                    self.gdb = self.__attach_gdb(self.pid, gdbscript=script) # P is gdbserver...
                    self.__setup_gdb()
                    if self.instruction_pointer - address_debug_from in range(0, len(backup)): # I'm in the sleep shellcode
                        self.write(address_debug_from, backup)
                        self.jump(address_debug_from)
                        break
                    else:
                        log.warn(f"{timeout}s timeout isn't enough to reach the code... Retrying...")
            # This is here to have the libc always available [06/01/25]
            # self.instruction_pointer != self.exe.entry: May not have a loader and libc, but still be considered dynamically linked
            if from_entry and self.exe is not None and not self.exe.statically_linked and self.ld is None:
                log.warn(f"{self.exe.name} is not marked as statically linked, but I can not find a loader!")
            elif from_entry and self.exe is not None and self.ld is not None and self.instruction_pointer in self.ld:
                if not context.native:
                    log.warn_once("Debugging from entry may fail with qemu. In case set Debugger(..., from_entry = False)")
                self.until(self.exe.entry)
                # If the library is loaded by the program with dlopen access_library will fail.
                for library in self._libraries:
                    try:
                        self.access_library(library)
                    except Exception:
                        pass

    def __handle_breakpoints(self, breakpoints):
        """
        Execute callbacks and determine if the execution should resume.
        """
        should_continue = self._stop_reason != "SINGLE STEP" # Simple version. If the user is stepping the breakpoint should never make the program continue [05/06/23]
        # I don't set stop after each breakpoint to avoid letting a script continue while another callback is running [06/06/23]
        set_stop = []
        address = self.instruction_pointer
        if DEBUG: self.logger.debug("0x%x: %d %s", address, len(breakpoints), breakpoints)
        # Invert list of breakpoints to make callback resolution in LIFO order
        for breakpoint in breakpoints[::-1]:
            if breakpoint.temporary:
                self.delete_breakpoint(breakpoint)

            if breakpoint.callback is None:
                should_continue = False
                # Must be set for each breakpoint for the library functions to work [05/06/23]
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
                    if DEBUG: self.logger.debug("[%d] callback returned False", self.pid)

        # Be sure to be in the last stop
        if address == self.instruction_pointer:
            if DEBUG: self.logger.debug("saving remaining stops: %d", len(set_stop))
            self._stops_to_enforce = len(set_stop)

        # Come funziona ancora questo ? Deve controllare i breakpoint multipli ed evitare che mandiamo un segnale sbagliato, però se nessuno aspetta dopo devo andare avanti...
        for i, stop_reason in enumerate(set_stop):
            self._breakpoint_handled.clear()
            self.__set_stop(stop_reason)
            # Se stai gestendo l'ultimo vai avanti e basta
            if i + 1 < len(set_stop):
                self._breakpoint_handled.wait()
            #self.__enforce_stop(stop_reason)

        # TODO IMPROVE THIS [06/06/23]
        # We have a problem. If I do a next() and hit a breakpoint with a finish(); return False, How should I know not to continue after the finish ?
        # If this is the only breakpoint that stop we can continue [19/06/23]
        if should_continue and self._stops_to_enforce <= 1:#not self._myStopped.enforce_stop: 
            self.__hidden_continue()
        if DEBUG: self.logger.debug("setting breakpoint handled")
        self._breakpoint_handled.set()

    # We stopped using gdb's implementation of temporary breakpoints so that we can differentiate an interruption caused by my debugger and cause by the manual use of gdb 
    # Event could tell me which breakpoint has been hit or which signal cause the interruption
    # For ptrace emulation if the interruption is caused by a breakpoint, a step or an interrupt we stop the process. Otherwise we let the master decide in waitpid depending on the settings if we should return the control to the user [23/07/23]. This may cause problems though if waitpid is never called
    # Stop handlers run in a normal thread, so they don't have access to the correct context. We could copy it as an object variable, but do we really need it here ? [29/12/23]
    # Yes, to access self.ip! [29/12/23]
    @lock_decorator
    def __stop_handler_gdb(self):
        """
        Actions that the debugger performs every time the process is interrupted except when exiting
        Handle temporary breakpoints and callbacks
        """
        # Current inferior will change to the inferior who stopped last
        ip = self.instruction_pointer
        breakpoints = self.breakpoints[ip]

        if DEBUG: _logger.debug("[%d] stopped at address: %s for %s", self.current_inferior.pid, self.reverse_lookup(ip), self._stop_reason)
            
        # Warn that if a parent has to listen for a signal you must tell your handler to stop the execution [22/07/23]
        if self._stop_reason in SIGNALS and SIGNALS[self._stop_reason] in self._handled_signals:
            should_stop = self._handled_signals[SIGNALS[self._stop_reason]](self)
            if should_stop == False:
                self.__hidden_continue()
            else:
                if self._ptrace_emulated:
                    if DEBUG: self.logger.debug("stop will be handle by waitpid")
                    self._ptrace_has_stopped.set()
                else:
                    self.__set_stop(f"signal {self._stop_reason} handled")
            return  

        # We could also pass the stop event and read the breakpoint from there... But it would only be useful to know that it is a catchpoint and which one, so who cares [25/07/23]
        # We have a problem with multiple catchpoints for the same syscall... [26/07/23]
        # Can we get the reason from the StopEvent ?
        if self._stop_reason == "BREAKPOINT" and (callback := self._event_breakpoints.get(self._details_breakpoint_stopped, None)) is not None:
            if DEBUG: self.logger.debug("stopped for catchpoint")
            name = list(self._event_table.keys())[list(self._event_table.values()).index(self._details_breakpoint_stopped)]
            # Syscalls have to be handled differently because we break both when calling it and when returning
            if name.startswith("syscall "):
                if self._syscall_return == False: 
                    # Make sure we don't miss the return
                    # Put above to avoid race condition after the jump
                    self._raise_priority("handling syscall")
                    should_skip = callback(self, entry=True)
                    if should_skip is not None and should_skip & SKIP_SYSCALL:
                        self.jump(self.instruction_pointer)
                        if not should_skip & SHOULD_STOP:
                            self.__hidden_continue()
                        else:
                            # Wait I must stop for the user, not the emulator...
                            # I should tell any wait() that I stopped, but not waitpid...
                            # if self._ptrace_emulated:
                            #     self._ptrace_has_stopped.set()
                            #else:
                            #    # TODO TEST IT [26/07/23]
                            self.__set_stop("stopped after skipping syscall")
                        self._lower_priority("syscall skipped")    
                        return
                    # hit the return
                    self._syscall_return = True
                    self.c()
                    should_stop = callback(self, entry=False)
                    self._lower_priority("syscall handled")
                    self._syscall_return = False
                    if should_stop == False:
                        self.__hidden_continue()
                    else:
                        self.__set_stop("returned from syscall")
                else:
                    self.__set_stop("returned from syscall")
                return
            else:
                self._raise_priority("handling event")
                should_stop = callback(self)
                should_stop = True if should_stop is None else should_stop
                self._lower_priority("event handled")
                if should_stop:
                    should_continue = False
                    self.__set_stop("event callback returned True or None")
                else:
                    if DEBUG: self.logger.debug("[%d] callback returned False", self.pid)
                    self.__hidden_continue()
                return

        if len(breakpoints) == 0:
            # Is it right to catch SIGSTOP and SIGTRAP ? [04/06/23]
            #if self._stop_reason == "SIGSEGV":
            #    self.__exit_handler(...)
            # I put the signal first because I may have PTRACE_CONT be called on a SIGILL and I must tell the master that we stopped. I hope it won't cause problems with the different SIGSTOP that gdb puts in the way. [23/06/23]
            if self._interrupted and self._stop_reason == "SIGINT":
                self._interrupted = False
                self.__set_stop(f"interrupted")
            
            elif self._stop_reason in SIGNALS:
                # I hope that the case where we step and still end up on a breakpoint won't cause problems because we would not reset stepped... [29/04/23]
                if self._ptrace_emulated:
                    if DEBUG: self.logger.debug("stop will be handle by waitpid")
                    self._ptrace_has_stopped.set()
                else:
                    self.__set_stop(f"signal: {self._stop_reason}")
            # self._stepped must only set by step() and can't be set by PTRACE_SINGLESTEP [23/07/23]
            elif self._stepped:
                self._stepped = False
                self.__set_stop("stepped")
            else:
                if DEBUG: self.logger.debug("stopped for a manual interaction")
                self.__enforce_stop("manual interaction")
            return            
            
        # Doesn't handle the case where we use ni and hit the breakpoint though... [17/04/23] TODO!
        # Doesn't even handle the case where I step, but I'm waiting in continue until
        # Damn, gdb detects the breakpoint even if we don't run over the INT3... so this doesn't work. We never have reason SINGLE STEP with a breakpoint. We need another indication [10/05/23]
        with context.local(**self._context_params): # Not needed because we are already in a thread with context.local, but just to not miss any context.Thread I put the context.local in all of them [08/07/24]
            context.Thread(target=self.__handle_breakpoints, args = (breakpoints,), name=f"[{self.pid}] handle breakpoint {hex(ip)}").start()

    # INT3 while enumerating ptrace doesn't set ptrace_has_stopped [24/12/23]
    # The handler is not called at all! Is it because libdebug thinks it's an internal interruption ?
    # No, without emulate_ptrace() we get to the "why did I stop"...
    # But if I only set ptrace_emulated = True then everything works...
    @lock_decorator
    def __stop_handler_libdebug(self):
        """
        Actions that the debugger performs every time the process is interrupted
        Handle temporary breakpoints and callbacks
        """
        with context.local(**self._context_params):

            # If we detach there will be a step to shutdown waitpid, but libdebug will have detached before we can execute the handler, so let's just skip it.
            if self._detached:
                if DEBUG: self.logger.debug("libdebug stopped waitpid")
                return

            # Current inferior will change to the inferior who stopped last
            ip = self.instruction_pointer
            breakpoints = self.breakpoints[ip]

            if DEBUG: self.logger.debug("[%d] stopped at address: 0x%x with status: 0x%x", self.libdebug.cur_tid, ip, self.libdebug.stop_status)
            
            if self._stop_reason in SIGNALS and SIGNALS[self._stop_reason] in self._handled_signals:
                should_stop = self._handled_signals[SIGNALS[self._stop_reason]](self)
                if should_stop == False:
                    self.__hidden_continue()
                else:
                    if self._ptrace_emulated:
                        if DEBUG: self.logger.debug("stop will be handle by waitpid")
                        self._ptrace_has_stopped.set()
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
                if self._stepped or self._interrupted:
                    self._stepped = False
                    self._interrupted = False
                    if self.stop_signal not in [0x5, 0x2, 0x13]:
                        log.warn(f"I wanted to step or interrupt, but stopped due to signal: {self._stop_reason}")
                        if self._ptrace_emulated:
                            if DEBUG: self.logger.debug("stop will be handle by waitpid")
                            self._ptrace_has_stopped.set()
                            return
                # This should now be handled by libdebug [08/06/23]
                # AND SIGTRAP COULD ALSO BE DUE TO A INT3 EMULATING PTRACE [24/12/23]
                #elif self.libdebug.stop_status == 0x57f:
                #    # Look into how to handle steps in libdebug [21/05/23]
                #
                #    log.warn("I suppose libdebug just stepped so let's pretend nothing happened")
                #    return
                else:
                    # Once to let know there may be a problem, but not spamming when it is part of the challenge.
                    if self._ptrace_emulated:
                        if DEBUG: self.logger.debug("stop will be handle by waitpid")
                        self._ptrace_has_stopped.set()
                        return
                    else:
                        log.warn_once(f"why did I stop ??? [{hex(self.libdebug.stop_status)}]")
                self.__set_stop("no breakpoint")
                return            
            
            self.__handle_breakpoints(breakpoints)
            #context.Thread(target=self.__handle_breakpoints, args=(breakpoints,)).start()

    # 02/05/25
    # By default this callback is executed every time a process exits, but that includes both our program finishing, and inferior finishing and us detaching from a process
    # We want all of them to set gdb.stopped both to let know the debugger the process stopped, or to kill the loop thread when we detach
    # You may not want to do it when you detach from a child process that is already at a stop though so we should disable the callback before splitting 
    # If the main process exits then we should close the debugger
    def __exit_handler(self, event):
        # Should I kill all children ? []
        # Waiiiiit, this is called even if we detach from the child in split()! [25/07/23] 
        # Yes, fuck [14/08/23]
        # Okay, we disable this handler before splitting processes, but we could also check that the pid of the event.inferior is not the one of the main debugger (would require to warn user that he can't detach main process) [08/07/24]
        if event.inferior.pid == self.pid:
            if DEBUG: self.logger.debug("setting stop because process exited")
            self.__set_stop(f"process exited", exit=True)
            self._closed.set()
            self._ptrace_has_stopped.set()
        else:
            if DEBUG: self.logger.debug("%s has been disconnected", event.inferior.pid)
            self.__set_stop(f"inferior exited", exit=True)

    # TODO look into peda someday
    def __test_debugger(self):
        """
        Determine which extension of gdb is being used between GEF and pwndbg
        """
        try:
            self.execute("gef")
            self._gef = True
            if DEBUG: _logger.debug("user is using gef")
            return
        except:
            if DEBUG: _logger.debug("user isn't using gef")
        try:
            self.execute("pwndbg")
            self._pwndbg = True
            if DEBUG: _logger.debug("user is using pwndbg")
            return
        except:
            if DEBUG: _logger.debug("user isn't using pwndbg")
        
    def __setup_gdb(self):
        """
        setup of gdb's events
        """
        def loop_handler():
            while True:
                self.gdb.wait() # Move the wait here to se look only when needed [09/07/24]
                if DEBUG: self.logger.debug("GDB stopped somewhere.")
                # I ended up setting the stopped event when I close the debugger to stop the wait.
                # The idea was that close() would cause a stop event, but this is not true if we stopped already, so we need to timeout the wait instead
                if self._kill_threads.is_set() or self._closed.is_set():
                    if DEBUG: self.logger.debug("exiting loop handler")
                    break
                with context.local(**self._context_params):
                    context.Thread(target=self.__stop_handler_gdb, name=f"[{self.pid}] stop_handler_gdb").start()
        with context.local(**self._context_params):
            context.Thread(target=loop_handler, name=f"[{self.pid}] loop_stop_handler_gdb").start()
        
        self.gdb.events.exited.connect(self.__exit_handler)
        def clear_cache(event):
            if DEBUG: self.logger.debug("GDB clearing register cache")
            self._cached_registers = {}
        self.gdb.events.cont.connect(clear_cache)
        # Could be improved clearing only event.regnum, but you need a map to which register corresponds to which number for each architecture [08/07/24]
        self.gdb.events.register_changed.connect(clear_cache)
        #self.execute("set write on")

        # I still don't know how to disable it to let ptrace_emulate work in peace [26/07/23]
        def callback_ptrace(self, entry):
            if entry:
                log.warn_once(f"THE PROCESS [{self.pid}] USES PTRACE!")
            # Do we also want to delete the breakpoint once we know we are using ptrace ? [13/08/23]
            else:
                self.delete_catch_syscall("ptrace")        
            return False
        self.catch_syscall("ptrace", callback_ptrace)

        # Manually set by split_child
        self.split = Queue()

        self._closed.clear()
        self._kill_threads.clear()

        self._myStopped.pid = self.pid
        self.__test_debugger()

        if not context.native and self._gef:
            log.warn_once("Using GEF with qemu. In case of bugs try pwndbg")

        if self._pwndbg:
            # because for some reason they set the child...
            # But this breaks any gdbscript with set follow-fork-mode to child... [17/11/23]
            if "set follow-fork-mode" not in self.gdbscript:
                self.execute("set follow-fork-mode parent")      

    def __setup_libdebug(self):
        self.libdebug.handle_stop = self.__stop_handler_libdebug

        self.libdebug.handle_exit = self.__exit_handler
        
        self._closed.clear()
        self._kill_threads.clear()

    # È già successo che wait ritorni -1 e crashi libdebug [08/05/23]
    # Legacy callbacks won't be transferred over... It's really time to get rid of them [21/05/23]
    # BUG migrating back to gdb while emulating ptrace hangs because the program thinks the interrupt should be handled by waitpid [19/11/23]
    def migrate(self, *, gdb=False, libdebug=False, script=""):
        """
        Switch the debugger being used on the backend. Current options are gdb and libdebug.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        assert context.native, "migrate isn't supported in qemu"

        # Maybe put a try except to restore the backup in case of accident [06/06/23]
        if gdb:
            assert self.gdb is None
            self.detach(block=True)
            if DEBUG: self.logger.debug("migrating to gdb")
            self.libdebug = None
            self._detached  = False
            self.gdb = self.__attach_gdb(self.pid, gdbscript=script)
            self.__setup_gdb()
            # Catch SIGSTOP
            address = self.instruction_pointer
            
            # The stop handle will never tell gdb we stopped if ptrace_emulated is set. The simplest way to bypass the problem is to set it to False for a second
            backup = self._ptrace_emulated
            self._ptrace_emulated = False
            with context.silent:
                self.step(repeat=4)
            self._ptrace_emulated = backup

            if address != self.instruction_pointer:
                log.warn("I made a mistake trying to catch the SIGSTOP after attaching with gdb")
            # I must get back before setting the breakpoints otherwise I may overwrite them
            for address in self.breakpoints:
                for breakpoint in self.breakpoints[address]:
                    bp = self.__breakpoint_gdb(address)
                    breakpoint.native_breakpoint = bp
        elif libdebug:
            assert not self._ptrace_syscall, "libdebug can't catch ptrace syscall. Emulate with syscall = False"
            if self._event_breakpoints:
                log.warn_once("you will lose all your syscall catchpoints!")
            try:
                from libdebug_legacy import Debugger as lib_Debugger
            except ImportError as e:
                print("libdebug_legacy is not installed")
                print("you can install it with: pip3 install git+https://github.com/Angelo942/libdebug.git")
                raise e
            # Disable hook stop
            assert self.libdebug is None
            assert self.gdb is not None
            self.gdb.events.exited.disconnect(self.__exit_handler)
            self.detach(block=True)
            if DEBUG: self.logger.debug("migrating to libdebug")
            self.gdb = None
            self._gef = False
            self._pwndbg = False
            self._detached  = False
            self.libdebug = lib_Debugger(multithread=False)
            while not self.libdebug.attach(self.pid, options=False):
                log.warn("error attaching with libdebug... Retrying...")
                continue
            assert not self.libdebug.running
            self.__setup_libdebug()
            # Catch SIGSTOP
            address = self.instruction_pointer

            backup = self._ptrace_emulated
            self._ptrace_emulated = False
            with context.silent:
                self.step()
            self._ptrace_emulated = backup

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

    # Here to have only one check that we can indeed attach to the process
    def __attach_gdb(self, target, gdbscript=None, exe=None):
        if not context.native:
            log.error("We can not attach to a process under QEMU")
        _, debugger = self.__silence(gdb.attach, target, gdbscript=gdbscript, exe=exe, api=True)
        try: 
            debugger.execute("info tasks", to_string=True)
        except Exception:
            log.error("Can not attach to process! Did you set ptrace scope to 0 ? (/etc/sysctl.d/10-ptrace.conf)")
        return debugger

    def debug_from(self, location: [int, str], *, event=None, timeout=0.5):
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

        def action():
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
                    self.gdb = self.__attach_gdb(self.p.pid, gdbscript=self.gdbscript) # P is gdbserver...
                except Exception as e:
                    if DEBUG: self.logger.debug("can't attach in debug_from because of %s... Retrying...", e)
                    continue
                self.__setup_gdb()
                if self.instruction_pointer - address in range(0, len(backup)): # I'm in the sleep shellcode
                    self.write(address, backup)
                    self.jump(address)
                    self.debug_from_done.set()
                    break
                else:
                    log.warn(f"{timeout}s timeout isn't enough to reach the code... Retrying...")
        context.Thread(target=action, name=f"[{self.pid}] debug_from").start()
        return self

    # Still useful for cases where we don't have the binary to locate the entry point.
    # Especially when you are using a specific loader!
    def load_libc(self):
        """
        Continue until the program has loaded the libc. Needed before setting breakpoints on libc functions.
        """
        self.catch("load")
        while self.libc is None:
            self.c()
        self.delete_catch("load")

        return self

    # Use as : dbg = Debugger("file").remote(IP, PORT)
    def remote(self, host: str, port: int):
        """
        Define the connection to use when the script is called with argument REMOTE.
        """
        self._host = host
        self._port = port
        if args.REMOTE:
            self.p = self.__silence(remote, host, port)
        return self

    setup_remote = remote

    def connect(*, overwrite=True):
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

    def detach(self, quit = True, block = False):
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

        if self.gdb is not None:
            # They will be lost
            self._event_breakpoints = {}
            self._event_table = {}
            self._kill_threads.set()
            self.gdb.stopped.set()

            try:
                if block:
                    os.kill(self.pid, signal.SIGSTOP)
                self.execute("detach")
            except:
                if DEBUG: self.logger.debug("process already stopped")
            try:
                self.execute("quit") # Doesn't always work if after interacting manually
            except EOFError:
                if DEBUG: self.logger.debug("GDB successfully closed")
            self._cached_registers = {}

        elif self.libdebug is not None:
            self.libdebug.detach()
            if not block:
                os.kill(self.pid, signal.SIGCONT)

        else:
            ...

    # TODO set option to kill child processes ? [05/08/24]
    # TODO make sure it works when inside a read [16/04/25]
    def close(self):
        """
        Close process and debugger.
        Doesn't kill child processes.
        """

        self.detach()
        # Yah, I should do it here, but I close the terminal in detach, so let's handle it there.
        #except:
        #    if DEBUG: self.logger.debug("can't detach because process has already exited")
        # Can't close the process if I just attached to the pid
        if self.p:
            self.__silence(self.p.close)
        if self.r is not None:
            self.__silence(self.r.close)
        if self._backup_p is not None:
            self.__silence(self._backup_p.close)
        
        if self.gdb is not None:
            # Is this really needed ? Currently seems to break the interrupt inside detach by not detecting the interruption [05/01/25]
            # Yes it is needed to make sure that the loop_stop_handler exits [01/05/25] We can try to move it after detach though
            self.gdb.stopped.set() 

    def __silence(self, fun, *args, **kwargs):
        if self.silent:
            with context.silent:
                return fun(*args, **kwargs)
        else:
            return fun(*args, **kwargs)

    # Now we may have problems if the user try calling it...
    # should warn to use execute_action and wait if they are doing something that will let the process run
    def execute(self, code: str):
        """ 
        Execute a gdb command that does NOT require a wait later.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return ""
        
        return self.gdb.execute(code, to_string=True)
        
    # I want a function to restart the process without closing and opening a new one
    # Not working properly
    # Can use elf.entry to find entry point
    def reset(self, argv=None, reload_elf=False):
        ...

    # Since reset doesn't work
    # Could be expanded with memory regions
    def backup(self) -> list:
        """
        return the state of all registers.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        values = []
        for register in self._special_registers + self._registers: # include ip, setattr will cut it out if not needed
            values.append(getattr(self, register))
        return values
        
    def restore_backup(self, backup: list):
        """
        Reset the state of all registers from a given backup
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for name, value in zip(self._special_registers + self._registers, backup):
                setattr(self, name, value)

    # Return old_inferior to know where to go back
    def switch_inferior(self, n: int) -> int:
        """
        For multi-process applications change the process you are working with in gdb. 
        Try to avoid it and instead split each process in a different Debugger.
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self._cached_registers = {}
        # May not be accurate if you switched manually before
        old_inferior = self.current_inferior
        while self.current_inferior.num != n:
            if DEBUG: self.logger.debug("switching to inferior %d", n)
            self.execute(f"inferior {n}")
            inferior = self.current_inferior
            if DEBUG: self.logger.debug("I'm inferior %d, [pid: %d]", inferior.num, inferior.pid)
            sleep(0.1)
        self.pid = self.current_inferior.pid
        return old_inferior

    @property
    def inferiors(self):
        return {inferior.num: inferior for inferior in self.gdb.inferiors()}
        #return (None,) + self.gdb.inferiors()

    # TODO if possible allow for an optimisation "single inferior" or something similar where we never waste time calling the inferior [08/10/24]
    @property
    def current_inferior(self):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
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
            log.warn_once(DEBUG_OFF)
            return Fake_arguments()

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
            log.warn_once(DEBUG_OFF)
            return Fake_arguments()

        if self._sys_args is None:
            self._sys_args = Arguments_syscall(self)
        return self._sys_args 

    sys_args = syscall_args

    # Taken from GEF to handle slave interruption
    @property
    def _stop_reason(self) -> str:
        # We need a loop because we noticed if you continue manually from gdb and then call interrupt, the interrupt will continue before the process really stopped. 
        # If it's a general problem with gdb is better to keep it here, if it comes out only in interrupt let's move it to there
        # Right now I don't like that if the program is running, info program fails and we get NOT RUNNING instead. It's confusing.
        counter = 0
        while counter < 5:
            if self.running:
                sleep(0.1)
            counter += 1
        if self.gdb is not None:
            try:
                res = self.execute("info program").splitlines()
            except:
                return "RUNNING"
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
            if self._stepped:
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

        # For some reason `catch load` has """It stopped at breakpoint -2.\nIt stopped at breakpoint 2.""" [21/07/24]
        for line in res[::-1]:
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

        priority = self._raise_priority(sender)
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
        if DEBUG: self.logger.debug("hidden continue")
        sleep(0.02)
        if self.gdb is not None:
            self.gdb.execute("continue")
        elif self.libdebug is not None:
            self.libdebug.cont(blocking=False)
        else:
            ...

    def __continue_gdb(self, force, wait, done):
        # Do I check the address instead ? Like hidden_continue [09/06/23]
        with self._ptrace_lock.log("__continue_gdb"):
            priority = self._raise_priority("avoid race condition in continue")
            self.step(force=True)
            if self._stop_reason != "SINGLE STEP":
                if "BREAKPOINT" in self._stop_reason:
                    if DEBUG: self.logger.debug("step in continue already reached the breakpoint")
                elif self._stop_reason == "SIGINT":
                    if DEBUG: self.logger.debug("syscall interrupted by user") # step doesn't return if we are on a read, so calling interrupt() would leave us here with a SIGINT
                else:
                    log.warn(f"unknown interruption! {self._stop_reason}")
                self._lower_priority("avoid race condition in continue")
                done.set()
                return
            self.execute_action("continue", sender="continue")
        # Damn, I may not want to wait at all... [22/05/23]
        # Keep priority intact, so I have to wait
        #if wait:
        self._priority_wait(comment="continue", priority = priority + 1)
        done.set()
        # The problem is that this has to be set after wait() [29/07/23 21:45]
        self._lower_priority("avoid race condition in continue")

    def __continue_libdebug(self, force, wait, done, signal):
        # Continue in libdebug is already stepping [21/05/23]
        # Maybe keep the step if force = True [22/O5/23]
        #self.step(force=force)
        ## I hit a breakpoint
        #if self.instruction_pointer in self.breakpoints or self.instruction_pointer == self._last_breakpoint_deleted:
        #    return
        # I don't need the thread, right ? And this way I can lock the step [12/06/23]
        with self._ptrace_lock.log("__continue_libdebug"):
            self.execute_action(lambda: self.libdebug.cont(blocking=False, signal=signal), sender="continue")
        #if wait:
        self._priority_wait(comment="continue")
        done.set()
        
    # TODO make the option to have "until" be non blocking with an event when we reach the address [28/04/23] In other words migrate wait=False to wait=Event()
    def c(self, *, wait=True, force = False, signal=0x0):
        """
        Continue execution of the process

        Arguments:
            wait: Should block your script until the next interruption ?
            until: Continue until a specified location. Your script will wait if you have to play with gdb manually.

            force: gdb may bug and keep you at the same address after a jump or if the stack frame as been edited. If you notice this problem use force to bypass it. If you don't worry about a callback being called twice don't bother
        """
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
        priority = self._raise_priority("avoid race condition in continue until")
        self.cont(wait=True, force=force)
        # Should we take into consideration the inferior too ? [29/04/23]
        
        def has_callback():
            for bp in self.breakpoints[self.instruction_pointer]:
                if bp.callback is not None:
                    return True
            return False

        while self.instruction_pointer != address:
            log.warn(f"[{self.pid}] stopped at {self.reverse_lookup (self.instruction_pointer)} for '{self._stop_reason}' instead of {self.reverse_lookup(address)}")
            if self._stop_reason == "BREAKPOINT" and has_callback(): # It would maybe be best to ban return None and force the user to set True or False. [23/01/25]
                log.warn_once("The process stopped on a breakpoint with callback. If you wanted it to continue remember to make your callback return False")
            else:
                log.warn_once("I assume this happened because you are using gdb manually. Finish what you are doing and let the process run. I will handle the rest")
            wont_use_this_priority = self.execute_action("", sender="continue just to reset the wait")
            # I don't trust the previous priority, while the first one should be safe
            self._priority_wait(comment="continue_until", priority = priority + 1)
            # TODO check that the process didn't exit. [21/10/23]
        self._lower_priority("avoid race condition in continue until")
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
        
        Arguments:
            location: Where to stop the execution. Can be a relative address, absolute address or symbol name.
            wait: Wait for the program to reach the destination or return a event set when done.
            until: Continue until a specified location. Your script will wait if you have to play with gdb manually.

            force: gdb may bug and keep you at the same address after a jump or if the stack frame as been edited. If you notice this problem use force to bypass it. If you don't worry about a callback being called twice don't bother
        """
        with self._ptrace_lock.log("continue_until"):
            done = Event()

            if not self.debugging:
                done.set()
                log.warn_once(DEBUG_OFF)
                return done

            address = self._parse_address(location)
            if not loop and address == self.instruction_pointer:
                log.warn(f"I'm already at {self.reverse_lookup(address)}")
                log.warn_once("Be careful that the default behaviour changed. Use loop=True if you want to continue anyway")
                return done
                
            self.b(address, temporary=True, user_defined=False, hw=hw)
            if DEBUG: self.logger.debug("continuing until %s", self.reverse_lookup(address))

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
            self._myStopped.wait(timeout)
        else:
            self._priority_wait("standard wait")

    # This should only be used under the hood, but how do we let the other one to the user without generating problems ? [14/04/23]
    def _priority_wait(self, comment="?", priority=None):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        self._myStopped.priority_wait(comment, priority)
            
    # problems when I haven't executed anything
    # Inside a callback checking running doesn't make sense since in that instant the program is interrupted, but we define it as running for interrupt() to still stop the program when we finish the callback. 
    @property
    def running(self):
        with context.silent:
            if self.gdb is not None:
                try:
                    # We need a command that succeeds when the process exits, but fails when inside a callback [02/05/25]
                    # accessing a register fails after we exit
                    # info ... succeeds even inside a callback
                    self.execute("info program")
                    return False
                except:
                    return True
            elif self.libdebug is not None:
                return not self.libdebug._test_execution()
            else:
                ...

    @property
    def priority(self):
        return self._myStopped.priority

    @priority.setter
    def priority(self, value):
        self._myStopped.priority = value

    def _raise_priority(self, comment):
        self._myStopped.raise_priority(comment)
        return self.priority

    def _lower_priority(self, comment):
        self._myStopped.lower_priority(comment)
        return self.priority

    def __clear_stop(self, name="someone", /):
        if self.gdb is not None:
            pid = self.current_inferior.pid
        elif self.libdebug is not None:
            pid = self.pid # Handle thread
        else:
            ...

        if self._myStopped.is_set():
            #if DEBUG: self.logger.debug("[%d] stopped has been cleared by %s", pid, name)
            self._myStopped.clear(name)

    #def __hidden_stop(self, name="someone", /):
    #    if self.gdb is not None:
    #        pid = self.current_inferior.pid
    #    elif self.libdebug is not None:
    #        pid = self.pid # Handle thread
    #    else:
    #        ...
    #    if self._myStopped.is_set():
    #        log.debug(f"[{pid}] stopped has been hidden_cleared by {name}")
    #        self._myStopped.hidden_clear()

    def __set_stop(self, comment = "", exit=False):
        if self.gdb is not None:
            pid = self.current_inferior.pid
        elif self.libdebug is not None:
            pid = self.pid # Handle thread
        else:
            ...     
        # We need a special case because when exiting self.instruction_pointer is not available  
        if not exit:
            if comment:
                if DEBUG: self.logger.debug("[%d] setting stopped in 0x%x for %s", pid, self.instruction_pointer, comment) # no reverse lookup ? [13/08/23]
            else:
                if DEBUG: self.logger.debug("[%d] setting stopped in 0x%x", pid, self.instruction_pointer)
        # handle case where no action are performed after the end of a callback with high priority 
        self._myStopped.pid = pid
        self.__clear_stop(comment)
        self._myStopped.set()

    def __enforce_stop(self, comment):
        self._myStopped.flag_enforce_stop = self._myStopped.priority
        if DEBUG: self.logger.debug("enforcing stop from level %d for reason: %s", self._myStopped.flag_enforce_stop, comment)

    #def wait_fork(self):
    #    self.gdb.forked.wait()
    #    self.gdb.forked.clear()

    def wait_split(self):
        """
        Wait for the process to fork
        set_split_on_fork() must be set before the call to fork

        Return:
            pid: pid of the child process

        Example:
            dbg.set_split_on_fork()
            dbg.c(wait=False)
            pid_child = dbg.wait_split()
            child = dbg.children[pid_child]
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        pid = self.split.get()
        if pid == 0:
            raise Exception("What the fuck happened with split ???")
        return pid

    # For now is handled by simple wait [06/03/23]
    def _wait_exit(self):
        self._closed.wait()

    # Can we remove these ? [25/08/24]
    def _wait_master(self):
        self._ptrace_can_continue.wait()
        self._ptrace_can_continue.clear()

    # TODO make sure the slave didn't stop for a user breakpoint !
    # Handle all options: https://stackoverflow.com/questions/21248840/example-of-waitpid-in-use
    def _wait_slave(self, options=0x40000000):
        if options == 0x1: # WNOHANG
            log.info("waitpid WNOHANG! Won't stop")
            # Check first that the slave isn't running in case ptrace_has_stopped hasn't been cleared correctly ? Clear it in hidden_continue instead of PTRACE_CONT ? [27/06/23]
            stopped = self._ptrace_has_stopped.is_set()
        else: 
            if DEBUG: self.logger.debug("waiting for slave to stop.")
            self._ptrace_has_stopped.wait()
            if DEBUG: self.logger.debug("slave has stop.")
            stopped = True

        # I can't clear it only here ! A wrong SIGSTOP in the step before a continue would set it again [22/07/23] 
        if stopped:
            self._ptrace_has_stopped.clear()

        return stopped

    def __interrupt_gdb(self):
        pass

    def __interrupt_libdebug(self):
        pass

    # Maybe should be the one returning if the process did stop due to the interrupt or not [13/06/23]
    # Breakpoint callbacks should be handled before the interruption to simplify the logic and I guess that if we reach a breakpoint and still send a SIGINT the signal will arrive later 
    # how do I interrupt in case of remote debugging ?
    @lock_decorator
    def interrupt(self, *, strict=False):
        """
        In a callback it makes no sense to check if the process is running since for that instant it will be on halt. We therefore use strict to force the interrupt call.
        """
        # claim priority asap
        priority = self._raise_priority("interrupt")
        
        if not self.debugging:
            # Who cares, right ?
            #self._lower_priority("no process to interrupt")
            log.warn_once(DEBUG_OFF)
            return

        if not strict and not self.running:
            self._lower_priority("release interrupt")
            # Must go after the lower_priority() to let other threads see it [19/06/23]
            # Do I really need a set stop ?? [26/07/23]
            self.__set_stop("Release interrupt. I didn't have to stop")
            return False

        self._interrupted = True
        if DEBUG: self.logger.debug("interrupting [pid:%d]", self.pid)
        # SIGSTOP is too common in gdb
        if DEBUG: self.logger.debug("sending SIGINT")
        if self.local_debugging:
            os.kill(self.pid, signal.SIGINT)
        else:
            self.execute("interrupt")
        self._priority_wait(comment="interrupt", priority = priority)
        # For now it will be someone else problem the fact that we sent the SIGINT when we arrived on a breakpoint or something similar. [21/07/23] Think about how to catch it without breaking the other threads that are waiting
        # TODO check that we did indeed took over the control [17/10/23] (BUG interrupt while reading doesn't work)
        
        res = INTERRUPT_SENT
        if self._stop_reason != "SIGINT":
            # Catch del SIGINT
            if DEBUG: self.logger.debug("We hit a breakpoint before the SIGINT... I will continue stepping to catch them.")
            
            # I must make sure the callbacks aren't called each time!
            address = self.instruction_pointer
            saved_callbacks = []
            for bp in self.breakpoints[address]:
                saved_callbacks.append(bp.callback)
                bp.callback = None
            
            # After this we finally reached the signal, so we are good to continue
            with context.silent:
                res = self.step_until_condition(lambda dbg: dbg._stop_reason == "SIGINT", limit=5)
            if address != self.instruction_pointer:
                log.warn("Oups, I made a mistake trying to catch the SIGINT...")
            elif res == -1:
                log.warn("What the fuck happened with the SIGINT ? I never found it...")
            for bp, callback in zip(self.breakpoints[address], saved_callbacks):
                bp.callback = callback
            res |= INTERRUPT_HIT_BREAKPOINT
        # Inform eventual continue that we interrupted the program
        self.__set_stop("interrupted")
        return res

    manual = interrupt


    def _step(self, signal=0x0):
            address = self.instruction_pointer

            if DEBUG: self.logger.debug("stepping from 0x%x", self.instruction_pointer)
            if self.gdb is not None:
                if signal:
                    self.signal(signal, step=True)
                else:
                    priority = self.execute_action("si", sender="step")
            elif self.libdebug is not None:
                priority = self.execute_action(lambda: self.libdebug.step(signal=signal), sender="step")
            else:
                ...
            
            self._priority_wait(comment="step", priority = priority)
            
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
            force : if the stack frame has been tampered with gdb may stay stuck on the current instruction. Use force to handle this bug in gdb
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        # Should only be the first step, right ? [08/05/23]
        if force:
            self.__broken_step()
            repeat -= 1

        for _ in range(repeat):
        
            self._stepped = True

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
            if DEBUG: self.logger.debug("Bug still present. Had to force %d time(s)", n)

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

        address = self._parse_address(location)
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
        # Should be possible to take immediately the corresponding stack frame instead of using a loop [28/04/23]
        for _ in range(repeat):
            ip = self.__saved_ip
            if DEBUG: self.logger.debug("finish found next ip : 0x%x", ip)
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
        self._priority_wait(comment="jump", priority = priority)

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

        #log.warn_once("jump is deprecated. Overwrite directly the instruction pointer instead")
        address = self._parse_address(location)

        # I end up allowing it because to skip a syscall I have to jump, but gdb thinks I'm already at the next instruction [26/07/23]
        #if address == self.instruction_pointer:
        #    if DEBUG: self.logger.debug("not jumping because I'm already at %s", self.reverse_lookup(address))
        #    return
        
        if DEBUG: self.logger.debug("jumping to %s", self.reverse_lookup(address))
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
        if not self.exe.statically_linked:
            try:
                ans = self.execute(f"call ({cast}) {function} ({', '.join([hex(arg) for arg in args])})")
                if cast == "void":
                    ret = None
                else:
                    ans = ans.split()[-1]
                    # GEF prints logs as base 16, but pwndbg as base 10
                    ret = int(ans, 16) if "0x" in ans else int(ans)
            except Exception: #gdb.error: The program being debugged was signalled while in a function called from GDB.
                if DEBUG: self.logger.debug("gdb got int3 executing %s. Retrying...", function)
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

    def __continue_call(self, backup, to_free, heap, end_pointer, return_value, alignment):
        #if end_pointer == self.instruction_pointer: # We called the function while on the first instruction, let's just step and continue normally [21/05/23] Wait, why bother ?
        # But this only works for intel processors. Use loop=True instead and you won't care if you started on the first instruction
        self.continue_until(end_pointer, loop=True)
        #while unpack(self.read(self.stack_pointer - context.bytes, context.bytes)) != end_pointer:
        #    assert self.instruction_pointer == end_pointer, "Something strange happened in a call"
        #    log.warn_once("Are you sure you called the function from outside ?")
        #    self.continue_until(end_pointer)

        if DEBUG: self.logger.debug("call finished")
                
        res = self.return_value
        for _ in range(alignment):
            self.pop()
        self.restore_backup(backup)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        return_value.put(res) # will be the event that tells me I finished

    # I still need end_pointer even if I would like to put the breakpoint on the address from which we call the function because I can't be sure that someone won't want to call a function from inside 
    # Wait, finish is doing it anyway... So let's require that call isn't used while you are inside the function, but still handle it just in case. Like a check that *(rsp - bytes) -> rip. It's not perfect, but it should at least always be true if we used the function properly [21/05/23]
    def call(self, function: [int, str], args: list = [], *, heap=True, wait = True, calling_convention = None):
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
        if wait = True the functions return the content of rax, otherwise the queue where it will be put once the function finishes
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        address = self._parse_address(function)
        if calling_convention is None: calling_convention = function_calling_convention[context.arch]
        if DEBUG: self.logger.debug("calling %s", self.reverse_lookup(address))

        args, to_free  = self.__convert_args(args, heap)

        #save registers 
        backup = self.backup()    
        
        for register in calling_convention:
            if len(args) == 0:
                break
            setattr(self, register, args.pop(0))
            
        #Should I offset the stack pointer to preserve the stack frame ? No, right ?
        for arg in args[::-1]:
            self.push(arg)
        
        return_address = self.instruction_pointer
        
        # Libc functions may die otherwise
        alignment = 0
        while self.stack_pointer % 0x10 != 0x0:
            self.push(0)
            alignment += 1
        if context.arch in ["i386", "amd64"]:
            self.push(return_address)
        elif context.arch == "aarch64":
            self.x30 = return_address
        elif context.arch in ["riscv32", "riscv64"]:
            self.ra = return_address
        elif context.arch == "mips":
            self.ra = return_address

        self.jump(address)
        
        return_value = Queue()
        context.Thread(target=self.__continue_call, args=(backup, to_free, heap, return_address, return_value, alignment), name=f"[{self.pid}] call").start()
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
        self._handled_signals[SIGNALS[signal]] = callback

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
                self._priority_wait(comment=f"signal {n}", priority = priority)
        elif self.libdebug is not None:
            if type(n) is str:
                n = n.upper()
                n = SIGNALS[n]
            if DEBUG: self.logger.debug("sending signal 0x%x -> %s", n, SIGNALS_from_num[n])
            if step:
                self.step(signal=n)
            else:
                self.c(signal=n)
        else:
            ...

        return self

    # Can not be cached because qemu somehow changes it back at every step! [16/01/25]
    def make_page_rwx(self, address: int, size : int = 1, *, syscall_address : [int, None] = None):
        """
        Sets the memory protections of a page to be readable, writable, and executable (RWX). 

        Args:
            address : int
                Any address within the page to update.
            size : OPTIONAL INT 
                Number of bytes that have to be executable. Set if the data may overlap multiple pages.
            syscall_address : OPTIONAL INT
                If running under QEMU without a symbol for mprotect we require the address of an executable syscall instruction.


        """
        page_address = address - address % 0x1000
        page_size = (size // 0x1000 + 1) * 0x1000

        if "mprotect" in self.symbols:
            if self._gdb is not None:
                self.execute(f"call (void)mprotect({page_address}, {page_size}, 0x7)")
            else:
                self.call("mprotect", [page_address, page_size, 7])
        elif context.arch not in ["riscv32", "riscv64"]: 
            self.syscall(constants.SYS_mprotect.real, [page_address, page_size, constants.PROT_EXEC | constants.PROT_READ | constants.PROT_WRITE], syscall_address = syscall_address)
        else: # pwntools doesn't have constants yet for RISCV yet [18/01/25]
            self.syscall(226, [page_address, page_size, 7], syscall_address = syscall_address)
        
    def syscall(self, code: int, args: list, *, heap = True, syscall_address = None):
        """
        Make the program call a given syscall
        Under qemu restrictions apply. You must have the symbols for mprotect to make the code section writable or pass as an argument the address of a syscall instruction.

        Parameters
        ----------
        code : INT or pwnlib constant. 
            The syscall to call
        args : LIST of INT, pwnlib constants or STRING. 
            Arguments to the syscall. By default strings will be allocated to the heap

        syscall_address : INT, optional. 
            Address of a syscall. Used only if the program runs under qemu and you don't have the symbols for mprotect.
        """
        if DEBUG: self.logger.debug("syscall %d: %s", code, args)
        
        args = [code] + args

        shellcode = shellcode_syscall[context.arch]
        calling_convention = syscall_calling_convention[context.arch]

        assert len(args) <= len(calling_convention), "too many arguments for syscall"

        backup_registers = self.backup()
        return_address = self.instruction_pointer
        args, to_free = self.__convert_args(args, heap)
        if syscall_address is not None:
            self.jump(syscall_address)

        else:
            # QEMU requires to call mprotect to write in executable memory [16/01/25]
            if not context.native:
                if "mprotect" not in self.symbols:
                    raise Exception("calling syscalls under qemu requires mprotect! Add the symbol or give me the address of a syscall instruction.")
                else: 
                    self.make_page_rwx(return_address, len(shellcode))
                    #pass # I will let write() call mprotect if needed [16/01/25]
        
            backup_memory = self.read(return_address, len(shellcode))
            self.write(return_address, shellcode)
        
        for register, arg in zip(calling_convention, args):
            if DEBUG: self.logger.debug("%s setted to %s", register, arg)
            setattr(self, register, arg)
        # Execute the syscall instruction
        self.step()
        res = self.return_value
        self.restore_backup(backup_registers)
        if syscall_address is None:
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
        if context.arch in ["riscv32", "riscv64"]:
            log.warn_once("catch syscall not supported for RISCV")
            return None

        return self.catch_event("syscall " + name, callback)

    handle_syscall = catch_syscall

    def delete_catch_syscall(self, name: str):
        return self.delete_catch("syscall " + name)

    # If you allow multiple callbacks on the same event you have to figure out a way to delete a specific catchpoint from the callback itself (ex ptrace detection) [18/01/25] 
    def catch_event(self, name: str, callback = lambda *args, **kwargs: True):
        if self.gdb is None:
            raise Exception("not implemented in libdebug")

        # To avoid multiple breakpoints for the same syscall which may break my way of handling them [27/07/23]
        if name in self._event_table:
            log.warn("there is already a catchpoint for %s... Overwriting...", name)
            self._event_breakpoints[self._event_table[name]] = callback
        else:
            if DEBUG: self.logger.debug("setting catchpoint %s", name)
            self.execute(f"catch {name}")
            # In old versions of gdb (bug found in ubuntu 20.4) breakpoints() only return the breakpoints, not the catchpoints. 27/04/24
            #num = self.gdb.breakpoints()[-1].number
            num = int(self.execute(f"info breakpoints").split("\n")[-2].split()[0])
            self._event_table[name] = num
            self._event_breakpoints[num] = callback

        return self

    catch = catch_event

    def delete_catch(self, name: str):

        if DEBUG: self.logger.debug("deleting catchpoint %s", name)
        try:
            bp = self._event_table.pop(name)
        except KeyError:
            log.warn("%s is not being caught", name)
            return
        self._event_breakpoints.pop(bp)
        self.execute(f"delete {bp}")
        return self
        
    # Be careful about the interactions between finish and other user breakpoints
    # TODO print ascii strings instead of pointer
    def set_ftrace(self, *, calling_convention = None, n_args = 3, no_return = False, custom_callback = None, exclude = []):
        """
        Can not always read the return value because some "functions" may not return but jump to another function. Use no_return in case of problem 
        """
        if calling_convention is None:
            calling_convention = function_calling_convention[context.arch]
        symtab = self.exe.get_section_by_name(".symtab")
        if not isinstance(symtab, SymbolTableSection):
            log.warn("Can not find symbols. If you added them yourself to the binary please raise an issue.")
            return self
        with log.progress("looking for functions in elf.symbols") as prog:
            for idx, symbol in enumerate(symtab.iter_symbols()):
                if symbol in exclude:
                    continue
                prog.status(f"{idx+1}/{symtab.num_symbols()}")
                if symbol.entry["st_info"]["type"] != "STT_FUNC":
                    continue
                address = self.exe.symbols.get(symbol.name, None)
                # is in the plt
                if address is None:
                    continue
                if custom_callback is None:
                    def callback(dbg, name = symbol.name):
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

    def disable_ftrace(self):
        for bp in self._ftrace_breakpoints:
            self.delete_breakpoint(bp)

    # Be careful about the interactions between finish and other user breakpoints [31/07/24]
    # In particular consider skipping ptrace and wait functions if ptrace is emulated and we decide to move the breakpoints from the libc to the plt. [01/08/24]
    def set_ltrace(self, *, calling_convention = None, n_args = 3, no_return = False, exclude = []):
        if self.exe.statically_linked:
            log.warn("The binary does not use libraries!")
            return self

        if calling_convention is None:
            calling_convention = function_calling_convention[context.arch]
        for name, address in self.exe.plt.items():
            if name in exclude:
                continue
            def callback(dbg, name = name): # Needed to save the correct name
                # TODO consider using a kind of context.calling_convention and use dbg.args here [32/07/24]
                print(f"{name}{[hex(getattr(dbg, calling_convention[i])) for i in range(n_args)]}", end=" ")
                if not no_return:
                    dbg.finish()
                    print(f"-> {hex(dbg.return_value)}")
                return False
            bp = self.b(address, callback=callback, user_defined=False)
            self._ltrace_breakpoints.append(bp)
        return self

    def disable_ltrace(self):
        for bp in self._ltrace_breakpoints:
            self.delete_breakpoint(bp)

    # TODO take a library for relative addresses like libdebug
    # May want to increase the limit
    # Is there a reason to make it public ? [06/01/25]
    def _parse_address(self, location: [int, str]) -> str:
        """
        parse symbols and relative addresses to return the absolute address

        If the binary is not PIE all addresses are assumed to be absolute.
        If the binary is PIE we assume all addresses that could belong to the binary to be absolute.
        The only addresses that are considered relative are the one who are not a valid address of the binary, but are small enough to fit in the binary. 
        """
        if type(location) is int:
            address = location

            if not self.exe.pie:
                return address

            if not address in self.exe and address < self.exe.range: # NOTE: I'm not sure yet if we should only use only allow relative breakpoints in len(exe.data) or the whole range of pages allocated to the program [05/02/25]
                address += self.exe.address

        elif type(location) is str:
            function = location
            offset = 0
            if "+" in location:
                # die if more than 1 +, but that's your fault
                function, offset = [x.strip() for x in location.split("+")]
                offset = int(offset, 16) if "0x" in offset.lower() else int(offset)

            try:
                address = self.symbols[function] + offset
            except KeyError as e:
                if not self.exe.statically_linked and self.libc is None:
                    log.error("symbol %s not found in ELF", location)
                    log.error("The libc is not loaded yet. If you want to put a breakpoint there call load_libc() first!")
                elif not self.exe.statically_linked:
                    log.error("symbol %s not found in ELF or libc", location)
                else:
                    log.error("symbol %s not found in ELF", location)
                raise e


        else:
            raise Exception(f"parse_breakpoint is asking what is the type of {location}")
        
        return address

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

        address = self._parse_address(location)


        if hw:
            if DEBUG: self.logger.debug("putting hardware breakpoint in %s", self.reverse_lookup(address))
        else:
            if DEBUG: self.logger.debug("putting breakpoint in %s", self.reverse_lookup(address))
        
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

    def tb(self, *args, **kwargs):
        return self.b(*args, **kwargs, temporary=True)

    temporary_breakpoint = tb

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
            address = self._parse_address(location)
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

        #if DEBUG: self.logger.debug("reading from inferior %d, [pid: %d]", inferior.num, inferior.pid)
        return self.inferiors[inferior.num].read_memory(address, size).tobytes()

    def read(self, address: int, size: int, *, inferior = None, pid = None) -> bytes:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return b"\x00" * size

        if inferior is not None:
            pid = inferior.pid
        if pid is None:
            pid = self.pid

        if self.gdb is not None and context.arch:
            return self.__read_gdb(address, size, inferior=inferior)

        # Data inside qemu is not updated
        # We can not access memory inside remote gdbserver
        with open(f"/proc/{pid}/mem", "r+b") as fd:
            fd.seek(address)
            return fd.read(size)

    # qemu doesn't allow writing in non writable pages [23/08/24]
    def __write_gdb(self, address: int, byte_array: bytes, *, inferior = None):

        if inferior == None:
            inferior = self.current_inferior
        
        try:
            inferior.write_memory(address, byte_array)
        except Exception as e: #gdb.MemoryError
            if not context.native:
                log.warn_once("QEMU is preventing to write on the page. Changing permissions...") # Warn only once because QEMU will reset the protection at each step and it would spam the user of errors [16/01/25]
                self.make_page_rwx(address, len(byte_array))
                inferior.write_memory(address, byte_array)
                log.warn_once("Successfully changed permissions.")
            else:
                raise e

    # How to handle multiple processes ?
    def __write_libdebug(self, address: int, byte_array: bytes, *, pid = None):
        if pid is not None:
            ...

    # Do we want to handle here that if address is none we allocate ourself a pointer ? [17/11/23]
    def write(self, address: int, byte_array: bytes, *, inferior = None, pid = None):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 
            
        if inferior is not None:
            pid = inferior.pid
        if pid is None:
            pid = self.pid

        if DEBUG: self.logger.debug("writing %s at 0x%x", byte_array.hex(), address)
        
        # BUG: GDB may write in the wrong inferior...
        # BUG: GDB with QEMU can not write in non writable pages
        if self.gdb is not None:
            return self.__write_gdb(address, byte_array)

        # Doesn't exist if the process is not running locally (ex remote gdbserver)
        # Doesn't matter if running under qemu because /proc/pid/mem is just a copy created at launch and nothing more 
        with open(f"/proc/{pid}/mem", "r+b") as fd:
            fd.seek(address)
            fd.write(byte_array)

    # Names should be singular or plurals ? I wanted singular for read and plural for write but it should be consistent [02/06/23]
    # I assume little endianness [02/06/23]
    def _read_numbers(self, address: int, n: int, byte_size: int) -> list:
        address = self._parse_address(address)
        data = self.read(address, n*byte_size)
        return [unpack(data[i*byte_size:(i+1)*byte_size], byte_size * 8) for i in range(n)]

    def read_bytes(self, address: int, n: int) -> list:
        return self._read_numbers(address, n, 1)

    def read_byte(self, address: int) -> int:
        return self.read_bytes(address, 1)[0]

    def read_shorts(self, address: int, n: int) -> list:
        return self._read_numbers(address, n, 2)
    
    def read_short(self, address: int) -> int:
        return self.read_shorts(address, 1)[0]

    def read_ints(self, address: int, n: int) -> list:
        return self._read_numbers(address, n, 4)
    
    def read_int(self, address: int) -> int:
        return self.read_ints(address, 1)[0]

    def read_longs(self, address: int, n: int) -> list:
        return self._read_numbers(address, n, 8)

    def read_long(self, address: int) -> int:
        return self.read_longs(address, 1)[0]

    def read_long_longs(self, address: int, n: int) -> list:
        return self._read_numbers(address, n, 16)

    def read_long_long(self, address: int) -> int:
        return self.read_long_longs(address, 1)[0]

    def read_pointers(self, address: int, n: int) -> list:
        return self.read_longs(address, n) if context.bits == 64 else self.read_ints(address, n)
    
    def read_pointer(self, address: int) -> int:
        return self.read_pointers(address, 1)[0]

    # Should we return the null bytes ? No, consistent with write_strings [02/06/23]
    def read_strings(self, address: int, n: int) -> list:
        address = self._parse_address(address)
        chunk = 0x100
        data = b""
        i = 0
        while data.count(b"\x00") <= n:
            data += self.read(address + chunk*i, chunk)
            i += 1
        return data.split(b"\x00")[:n]
        
    def read_string(self, address: int) -> bytes:
        return self.read_strings(address, 1)[0]

    #def write_bit(self, address: int, )

    def _write_numbers(self, address: int, values: list, byte_size: int, *, heap = True) -> int:
        data = b"".join([pack(x, byte_size * 8) for x in values])
        if address is None:
            address = self.alloc(len(data), heap=heap)
        else:
            address = self._parse_address(address)
        self.write(address, data)
        return address     

    def write_bytes(self, address: int, values: list, *, heap = True) -> int:
        return self._write_numbers(address, values, 1, heap = heap)

    def write_byte(self, address: int, value: list, *, heap = True) -> int:
        return self.write_bytes(address, [value])
        
    def write_shorts(self, address: int, values: list, *, heap = True) -> int:
        return self._write_numbers(address, values, 2, heap = heap)

    def write_shorts(self, address: int, value: list, *, heap = True) -> int:
        return self.write_shorts(address, [value])

    def write_ints(self, address: int, values: list, *, heap = True) -> int:
        return self._write_numbers(address, values, 4, heap = heap)

    def write_int(self, address: int, value: int, *, heap = True) -> int:
        return self.write_ints(address, [value], heap = heap)

    def write_longs(self, address: int, values: list, *, heap = True) -> int:
        return self._write_numbers(address, values, 8, heap = heap)

    def write_long(self, address: int, value: int, *, heap = True) -> int:
        return self.write_longs(address, [value], heap = heap)

    def write_long_longs(self, address: int, values: list, *, heap = True) -> int:
        return self._write_numbers(address, values, 16, heap = heap)

    def write_long_long(self, address: int, value: int, *, heap = True) -> int:
        return self.write_long_longs(address, [value], heap = heap)

    def write_pointers(self, address: int, values: list, *, heap = True) -> list:
        return self.write_longs(address, values, heap = heap) if context.bits == 64 else self.write_ints(address, values, heap = heap)
    
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
            address = self._parse_address(address)
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

        if DEBUG: self.logger.debug("pushing 0x%x", value)
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
    #gdb.error: The program being debugged was signalled while in a function called from GDB.
    #GDB remains in the frame where the signal was received.
    #To change this behaviour use "set unwindonsignal on".
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
                self._free_bss = self.exe.bss() # I have to think about how to preserve eventual data already present
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
            #I know it's not perfect, but damn I don't want to implement a heap logic for the bss
            #Just use the heap if you can

    # We could make size round up to the start of next instruction, but should we ? [23/01/25]
    def nop(self, address, instructions = 1, *, size = None):
        address = self._parse_address(address)
        if size is None:
            code = self.disassemble(address, instructions*10)
            size = 0
            for i in range(instructions):
                size += next(code).size
        if size % len(nop[context.arch]) != 0:
            log.warn(f"I have to nop {size} bytes, but this is not divisible by the length of our nop instruction ({len(nop[context.arch])}).")
        backup = self.read(address, size)
        self.write(address, nop[context.arch] * (size // len(nop[context.arch])))
        return backup

    # taken from GEF to locate the canary
    @property
    def _auxiliary_vector(self):
        if not self._saved_auxiliary_vector:
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
            self._saved_auxiliary_vector = auxiliary_vector
        return self._saved_auxiliary_vector

    # The canary is constant right ? This way you can also set it after a leak and access it from anywhere
    @property
    def canary(self):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return 0

        elif self._canary is None:
            auxval = self._auxiliary_vector
            canary_location = auxval["AT_RANDOM"]
            canary = self.read(canary_location, context.bytes)
            self._canary = b"\x00"+canary[1:]
        
        return self._canary

    # We can not search for the canary while gdb is running, so for now I only check if the canary is known. [24/04/24]
    @canary.setter
    def canary(self, value):
        if self.debugging and self._canary is not None and value != self._canary:
            # Do we want to backup the original value to make sure we don't warn for conflict between the values set by the user ? [24/04/24]
            log.warn(f"setting canary to: {value}, but debugger thinks canary is {self.canary}")
        self._canary = value
     
    @property
    def _special_registers(self):
        if context.arch in ["i386", "amd64"]:
            return ["eflags", "cs", "ss", "ds", "es", "fs", "gs"]
        elif context.arch == "aarch64":
            return ["cpsr", "fpsr", "fpcr", "vg"]
        elif context.arch == "arm":
            return ["cpsr"]
        elif context.arch in ["riscv32", "riscv64"]:
            return []
        elif context.arch == "mips":
            return ["hi", "lo", "at"]
        else:
            raise Exception(f"what arch is {context.arch}")

    # WARNING reset expects the last two registers to be sp and ip. backup expects the last register to be ip
    @property
    def _registers(self):
        if context.arch == "aarch64":
            return [f"x{i}" for i in range(31)] + ["lr"] + ["sp", "pc"]
        elif context.arch == "arm":
            return [f"r{i}" for i in range(16)] + ["fp", "ip", "lr"] + ["sp", "pc"] # fp, etc... are in the 15 registers, but to allow both names to be used I have to duplicate them
        elif context.arch == "i386":
            return ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]
        elif context.arch == "amd64":
            return ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp", "rip"]
        elif context.arch in ["riscv32", "riscv64"]:
            return [f"t{i}" for i in range(7)] + [f"s{i}" for i in range(12)] + [f"a{i}" for i in range(8)] + ["ra", "gp", "tp", "sp"] + ["pc"]
        elif context.arch == "mips":
            return [f"v{i}" for i in range(2)] + [f"a{i}" for i in range(4)] + [f"t{i}" for i in range(10)] + [f"s{i}" for i in range(8)] + [f"k{i}" for i in range(2)] + ["ra", "gp", "fp", "sp"] + ["pc"]
        else:
            raise Exception(f"what arch is {context.arch}")

    # Making ax accessible will probably be faster that having to write 
    @property
    def _minor_registers(self):
        if context.arch == "aarch64":
            return [f"w{x}" for x in range(31)]
        elif context.arch == "arm":
            return [] # Arm can not access 16bits or less in a register
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
        elif context.arch in ["riscv32", "riscv64"]:
            return []
        elif context.arch == "mips":
            return []
        else:
            raise Exception(f"what arch is {context.arch}")

    # We should add a new type of registers for aliases so that the user can access them, but we don't duplicate them when doing backups. 
    # Would also be useful to access floating points [21/01/25]
    @property
    def _long_registers(self):
        if context.arch == "amd64":
            return [f"xmm{i}" for i in range(32)]
        else:
            return []

    @property
    def next_inst(self):
        inst = next(self.disassemble(self.instruction_pointer, 16)) #15 bytes is the maximum size for an instruction in x64
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        if context.arch in ["amd64", "i386"]:
            inst.is_call = inst.mnemonic == "call"
        elif context.arch == "aarch64":
            inst.is_call = inst.mnemonic == "bl"
        elif context.arch in ["riscv32", "riscv64"]:
            inst.is_call = inst.mnemonic == "jal" # jal is the standard function call, but it could also use jalr, c.jalr to call dynamic code from a register or just extend the range... The problem is that jalr can also be a ret instruction...
            #if "jalr" # Check that it's not using zero register (return)
        elif context.arch == "mips":
            inst.is_call = inst.mnemonic in ["jal", "jalr", "bal"]
        else:
            ...
        return inst

    # May be useful for Inner_Debugger
    # BUG capstone v5, Risky Business start function. disassemble(ip, 1000) will stop after 4 instructions
    def disassemble(self, address, size):
        if self._capstone is None:
            if context.arch == "amd64":
                self._capstone = Cs(CS_ARCH_X86, CS_MODE_64)
            elif context.arch == "i386":
                self._capstone = Cs(CS_ARCH_X86, CS_MODE_32)
            elif context.arch == "aarch64":
                self._capstone = Cs(CS_ARCH_AARCH64, CS_MODE_ARM)
            elif context.arch == "arm":
                self._capstone = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif context.arch in ["riscv32", "riscv64"]:
                self._capstone = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC) #CS_MODE_RISCV32 if context.bits == 32 else CS_MODE_RISCV64)
            elif context.arch == "mips":
                self._capstone = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
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
        elif context.arch == "arm":
            return self.r0 # Not always true
        elif context.arch in ["riscv32", "riscv64"]:
            return self.a0
        elif context.arch == "mips":
            return self.v0
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
        elif context.arch == "arm":
            self.r0 = value # Not always true
        elif context.arch in ["riscv32", "riscv64"]:
            self.a0 = value # Sometimes a1 is also used
        elif context.arch == "mips":
            self.v0 = value
        else:
            ...


    @property
    def stack_pointer(self):
        if context.arch == "amd64":
            return self.rsp
        elif context.arch == "i386":
            return self.esp
        elif context.arch in ["arm", "aarch64"]:
            return self.sp
        elif context.arch in ["riscv32", "riscv64"]:
            return self.sp
        elif context.arch == "mips":
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
        elif context.arch in ["arm", "aarch64"]:
            self.sp = value
        elif context.arch in ["riscv32", "riscv64"]:
            self.sp = value
        elif context.arch == "mips":
            self.sp = value
        else:
            ...
        while self.stack_pointer != value:
            if self.gdb is None:
                raise Exception("Error setting stack pointer!")

            if DEBUG: self.logger.debug("forcing last frame")
            self.execute("select-frame 0") # I don't know what frames are for, but if you need to push or pop you just want to work on the current frame i guess ? [04/03/23]

            if context.arch == "amd64":
                self.rsp = value
            elif context.arch == "i386":
                self.esp = value
            elif context.arch in ["arm", "aarch64"]:
                self.sp = value
            elif context.arch in ["riscv32", "riscv64"]:
                self.sp = value
            elif context.arch == "mips":
                self.sp = value
            else:
                ...

    @property
    def base_pointer(self):
        if context.arch == "amd64":
            return self.rbp
        elif context.arch == "i386":
            return self.ebp
        elif context.arch in ["arm", "aarch64"]:
            return self.fp # TODO check
        elif context.arch in ["riscv32", "riscv64"]:
            ...
        elif context.arch == "mips":
            return self.fp
        else:
            ...
    
    @base_pointer.setter
    def base_pointer(self, value):
        if context.arch == "amd64":
            self.rbp = value
        elif context.arch == "i386":
            self.ebp = value
        elif context.arch in ["arm", "aarch64"]:
            self.fp = value
        elif context.arch in ["riscv32", "riscv64"]:
            ...
        elif context.arch == "mips":
            self.fp = value
        else:
            ...

    # Prevent null pointers
    @property
    def instruction_pointer(self):
        ans = None
        for attempts in range(2):
            # what about self.gdb.newest_frame().pc() ? [28/04/23]
            if context.arch == "amd64":
                ans = self.rip
            elif context.arch == "i386":
                try:
                    ans = self.eip
                except Exception as e:
                    print(e)
                    log.error("I failed retrieving eip! make sure you set context.arch")
                    continue
            elif context.arch in ["arm", "aarch64"]:
                ans = self.pc
            elif context.arch in ["riscv32", "riscv64"]:
                ans = self.pc
            elif context.arch == "mips":
                ans = self.pc
            else:
                ...
            
            if ans == 0:
                log.warn("null pointer in ip ! retrying...")
            else:
                break        
        return ans

    @instruction_pointer.setter
    def instruction_pointer(self, value):
        if context.arch == "amd64":
            self.rip = value
        elif context.arch == "i386":
            self.eip = value
        elif context.arch in ["arm", "aarch64"]:
            self.pc = value
        elif context.arch in ["riscv32", "riscv64"]:
            self.pc = value
        elif context.arch == "mips":
            self.pc = value
        else:
            ...

    def _find_rip(self):
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
        elif context.arch in ["riscv32", "riscv64"]:
            return self.ra
        elif context.arch == "mips":
            return self.ra

        # Doesn't work with qemu [05/07/23]
        elif self.gdb is not None:
            stack_frame = self.gdb.newest_frame().older()
            # Fail if call return on __start symbol
            if stack_frame is None:
                return 0
            return stack_frame.pc()

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

   ########################## FILES ##########################

    # Quick attempt to find maps
    # TODO handle remote debugging [20/01/25]
    @property
    def maps(self):
        maps = {}
        try:
            with open(f"/proc/{self.pid}/maps") as fd:
                maps_raw = fd.read()
            for line in maps_raw.splitlines():
                if not context.native and "/qemu-" in line:
                    break
                line = line.split()
                start, end = line[0].split("-")
                maps[int(start, 16)] = int(end, 16) - int(start, 16)
        except Exception: # In remote debugging we don't have the /proc file
            pass
        return maps

    # I copied it from pwntools to have access to it even if I attach directly to a pid 
    # We still need pwntools when we are not debugging the process. It is needed for example to access the libc while pwning a remote challenge. 
    # I assume that you don't care about the address when you are not debugging the program
    # The main advantage now though is just the speed of not having to run a new process every time we call the function if we are already debugging it.
    @property
    def libs(self):
        """libs() -> dict
        Return a dictionary mapping the path of each shared library loaded
        by the process to the address it is loaded at in the process' address
        space.

        The function still works when the program is not being debugged, but only for internal reasons. Please don't rely on it's output in those cases.
        """
        if not self.debugging:
            maps = self.exe.libs
            for key in maps:
                maps[key] = [maps[key], maps[key]]
            return maps

        if self.local_debugging:
            # I don't think the try is needed anymore.
            try:
                with open(f"/proc/{self.pid}/maps") as fd:
                    maps_raw = fd.read()
            except IOError:
                maps_raw = self.execute("info proc map")
        else:
            maps_raw = self.execute("info proc map")

        # Enumerate all of the libraries actually loaded right now.
        maps = {}
        for line in maps_raw.splitlines():
            if '/' not in line: continue
            path = line[line.index('/'):]
            if not context.native and "/qemu-" in path: # Everything after the QEMU binary is only libs for QEMU that we don't want. Be careful though if this breaks something [04/02/25]
                break
            path = os.path.realpath(path)
            if path not in maps:
                maps[path]= []

        for lib in maps:
            path = os.path.realpath(lib)
            for line in maps_raw.splitlines():
                if line.endswith(path):
                    if len(maps[lib]) == 0:
                        # /proc/pid/maps uses "start-end", while info proc map uses "start    end"
                        for part in line.replace("-", " ").split(" "):
                            if part:
                                address = part
                                break
                        maps[lib].append(int(address, 16))
                    address = line.split()[0].split('-')[-1]
                    maps[lib].append(int(address, 16))
            maps[lib] = [maps[lib][0], maps[lib][-1]] # Keep only start and end of the file in memory

        return maps

    def _set_range(self, file: EXE):
        if not self.debugging:
            file.address = 0
            file.end_address = 0
            return

        for path, addresses in self.libs.items():
            if file.name == path.split("/")[-1]:
                address = addresses[0]
                file.end_address = addresses[-1]
                break
        else:
            log.warn(f"can not find {file.name} in the binaries loaded in gdb")
            return

        # NOTE: Can not trust libs to find the correct page [06/01/25]
        # BUG Sometimes with arm we have the same binary at both 0x10000 and 0x20000, vmmap detects the second one, while we should use the first for the offsets... [20/01/25]
        if context.arch in ["riscv32", "riscv64", "arm", "mips"]:
            offset = file.size // 100 - (file.size // 100 % 8) # Random place to avoid the ELF part that could be common between multiple libraries
            while file.data[offset:offset+8] == b"\x00" * 8:
                offset += 8
            if file.data[offset:offset+0x8] != self.read(address+offset, 8):
                log.warn_once(f"QEMU messed up the {file.name} base. Trying to find correct address...")
                for address in list(self.maps) + list(map(lambda x: x - 0x10000, self.maps)): # I test both address and address - 0x1000 which is the typical error in QEMU
                    try:
                        if file.data[offset:offset+0x8] == self.read(address+offset, 8):
                            log.success(f"Found address {hex(address)}!")
                            break
                    except: # Some pages are not readable in QEMU...
                        continue
                else:
                    log.failure(f"can't find {file.name} address. Consider disabling ASLR.")
                    file.address = 0
                    return
        
            try:
                if file.data[offset:offset+0x8] == self.read(address+offset-0x10000, 8):
                    log.warn(f"[{file.name}] We are not sure between {hex(address)} and {hex(address - 0x10000)}. We are assuming the second one")
                    address -= 0x10000
            except:
                pass

        file.address = address

    # How does this interact with remote debugging ? [26/03/25]
    # Let's introduce local_path hoping it's enough and call it a day for now. [26/03/25]
    # We can not expect the user to load manually the libc, but must make it accessible when using REMOTE, so we have to find it by debugging the program anyway. [13/04/25]
    # It would be nice to find the path to the library without having to debug the program. [13/04/25]
    def access_library(self, name, local_path=None):
        """
        Create the EXE object for a particular library
        """
        if self._libraries.get(name, None) is not None:
            log.warn(f"{name} is already accessible as dbg.{name}")
            return self._libraries[name]
        
        # # If we are working under QEMU and not debugging the process pwntools implementations of elf.libs may fail. If you see this problem we will need to run a debugger ourselves.
        # # The idea of using fake_terminal.py is terrible. Somehow it is 3 times slower, so it's not worth it just to prevent having a terminal popping up.
        # if local_path is None and not self.debugging and not context.local: # May want to find specific architectures that cause trouble 
        #     with Debugger(self.exe, from_entry=True) as dbg: # Reach entry to load all libraries
        #         return dbg.access_library(name)    

        found_path = None
        if local_path is None:
            for path in self.libs:
                library_name = path.split("/")[-1]
                if name in library_name:
                    assert found_path is None, f"Name is not specific enough! Could mean both {found_path} and {path}"
                    found_path = path
            if found_path is None:
                msg = "\n".join([
                    f"{name} cannot be found between:",
                    *[f" - {path}" for path in self.libs],
                    "The library may not have been loaded yet"
                ])
                log.warn(msg)
                return None
        else:
            found_path = local_path
        
        library = EXE(found_path, checksec=False)
        self._set_range(library)
        self._libraries[name] = library
        return library

    @property
    def libraries(self):
        for name, file in self._libraries.items():
            if file is None:
                with context.silent:
                    self.access_library(name)
        return self._libraries

    @property
    def ld(self):
        if self._ld == -1:
            return None
        elif not self.debugging or (self.exe is not None and self.exe.statically_linked):
            self._ld = -1
            return None
        elif self._ld is None:
            for path, addresses in self.libs.items():
                if path.split("/")[-1].startswith("ld"): # handle mips ld.so.1
                    try:
                        self._ld = EXE(path, address=addresses[0], end_address=addresses[-1], checksec=False)
                    except Exception:
                        if not self.local_debugging:
                            log.warn(f"can not access {path} from remote server.")
                    break
            else:
                log.warn_once("Can not find loader...")
                self._ld = -1
                return None
        return self._ld

    @ld.setter
    def ld(self, elf_ld: ELF):
        self._ld = elf_ld

    # NOTE: Here for backward compatibility with 7.0 
    @property
    def base_libc(self):
        if self.libc is None:
            log.error("I don't see a libc ! Set dbg.libc = ELF(<path_to_libc>)")
        return self.libc.address
    @base_libc.setter
    def base_libc(self, address):
        if self.libc is None:
            log.error("I don't see a libc ! Set dbg.libc = ELF(<path_to_libc>)")
        self.libc.address = address
    libc_address = base_libc

    # If we don't have the binary we may consider iterating over the libraries to find a name that doesn't start with lib or ld- [05/02/25]
    @property
    def exe(self):
        if self.gdb is not None and self._exe is not None and self._exe.address == 0:
            self._set_range(self._exe)

        return self._exe 

    elf = exe

    # NOTE: Here for backward compatibility with 7.0 
    @property
    def base_elf(self):
        return self.exe.address
    @base_elf.setter
    def base_elf(self, address):
        self.exe.address = address
    elf_address = base_elf
    exe_address = base_elf

    # pwntools is a bit loose on what is included in the symbols. In particular all library functions used by the executable are also included with the address of the plt. We have to remove those.
    # When merging all symbols we can not guarantee which plt and got we are referring to, so I prefer to simply discard those symbols.
    # Previously I would delete those symbols from the ELF itself, but just to be clean let's make our own copy until we see that the performances are too bad.
    # Once every library has been loaded we can just cache all symbols. I don't cache intermediate steps because I assume they are all loaded around the same time. Assumption not valid when using dlopen. 
    # What do we do about global variables such as stdin and stdout that may overshadow each other ? So far I'm taking them of to be sure.
    @property
    def symbols(self):
        symbols = {}
        if self._symbols is None:
            for name, address in self.exe.symbols.items():
                if name not in self.exe.plt and name not in self.exe.got and name[:4] not in ["got.", "plt."]:
                    symbols[name] = address
            all_libraries_present = True
            for _, library in self.libraries.items():
                if library is not None:
                    for name, address in library.symbols.items():
                        if name[:4] in ["got.", "plt."]:
                            continue
                        # The libc also has a got and plt, so we can't blindly remove all the symbols in those tables.
                        # The criteria I use is that pwntools adds the symbols from the plt if they are not in the binary so they can be detected because the address of the symbol is the same as the plt.
                        if name in library.plt and address == library.plt[name]:
                            continue
                        # We still remove the global variables to prevent name collisions between different files.
                        if name in library.got and name not in library.plt:
                            continue
                        else:
                            symbols[name] = address
                else:
                    all_libraries_present = False
            if all_libraries_present:
                self._symbols = symbols
            else:
                return symbols
        return self._symbols

   ########################## FORKS ##########################
    # TODO find a better name [28/02/23]
    # TODO make inferior and n the same parameter ? [04/03/23]

    # Call shellcode has problems: https://sourceware.org/gdb/onlinedocs/gdb/Registers.html. Can't push rip
    # Warn that the child will still be in the middle of the fork [26/04/23]
    # TODO support split for libdebug [02/06/23] (Will require a new patch to libdebug)
    # I thought about setting emulate_ptrace for the child if it is set in the parent, but I want to let the user free of choosing the parameters they wants [23/07/23]
    def _split_child(self, *, pid = None, inferior=None, n=None, script=""):
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
                    raise Exception(f"How am I expected to find which child you want ??")

        if DEBUG: self.logger.debug("splitting inferior %d, [pid: %d]", inferior.num, inferior.pid)
        n = inferior.num
        pid = inferior.pid
        old_inferior = self.switch_inferior(n)
        ip = self.instruction_pointer
        backup = self.inject_sleep(ip)
        self.switch_inferior(old_inferior.num)
        if DEBUG: self.logger.debug("detaching from child [%d]", pid)
        self.execute(f"detach inferiors {n}")
        child = Debugger(pid, binary=self.exe, script=script, from_start=False, silent=self.silent)
        # needed even though by default they both inherit the module's priority since the user may change the priority of a specific debugger. [17/11/23]
        child.logger.setLevel(self.logger.level)
        # TODO copy all syscall handlers in the parent ? [31/07/23]
        # Copy libc since child can't take it from process [04/06/23]
        # Maybe not needed anymore, but better do it with all libraries anyway [01/05/25]
        child._libraries = self._libraries
        # Set parent for ptrace [08/06/23]
        child._parent = self
        if DEBUG: _logger.debug("new debugger opened")
        child.write(ip, backup)
        child.logger.debug("shellcode patched")
        child.jump(ip)

        # GEF puts a breakpoint after the fork...
        if self.gdb is not None and self._gef:
            bps = child.gdb.breakpoints()
            if len(bps) > 0:
                bp = bps[-1]
                if bp.location == "*" + hex(child.instruction_pointer + 1):
                    bp.delete()
        
        return child  
    
    # entrambi dovrebbero essere interrotti, il parent alla fine di fork, il child a metà
    # Ho deciso di lasciare correre il parent. Te la gestisci te se vuoi mettere un breakpoint mettilo dopo
    # I just discovered "gdb.events.new_inferior"... I can take the pid from event.inferior.pid, but can I do more ?
    # interrupt is not working as well as we would like. With a callback on the event we have to call interrupt when we notice the fork, but the program will have continued for a while [22/12/23] 
    # We should move to catch fork and catch clone if we want to allow interrupt [22/12/23]
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

        if self.libdebug is not None:
            log.error("Libdebug can not split on fork. You have to use gdb.")
            return self

        if self._pwndbg:
            log.warn_once("pwndbg may not handle correctly multi process applications. We recommend using GEF")

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
                    self._raise_priority("split")
                    stopped = self.interrupt(strict=True)
                    log.info(f"splitting child: {inferior.pid}")
                    # Am I the reason why the process stopped ?
                    self.children[pid] = self._split_child(inferior=inferior, script=script)
                    # Should not continue if I reached the breakpoint before the split
                    self._lower_priority("release split")
                    self.split.put(pid)
                    if not interrupt and stopped & INTERRUPT_SENT and not stopped & INTERRUPT_HIT_BREAKPOINT:
                        self.__hidden_continue()
                    elif interrupt:
                        self.__set_stop("forked")
                    else:
                        self.__set_stop("We hit a breakpoint while interrupting the process. Handle it!")
                            
                ## Non puoi eseguire azioni dentro ad un handler degli eventi quindi lancio in un thread a parte
                with context.local(**self._context_params):
                    context.Thread(target=split, args = (inferior,), name=f"[{self.pid}] split_fork").start()

            self.fork_handler = fork_handler
            self.gdb.events.new_inferior.connect(self.fork_handler)
            
        return self

    split_on_fork = set_split_on_fork

    # Take all processes related
    @property
    def _ptrace_group(self):
        if self._parent is not None:
            return self._parent._ptrace_group

        return {p.pid: p for p in self._recursive_children}

    # Take all grand-children
    @property
    def _recursive_children(self):
        group = {self}
        for child in self.children.values():
            group |= child._recursive_children
        return group

    # I want a single function so that each process can be both master and slave [08/06/23]
    # I use real callback as long as we are breaking on the function it should work. The problem is if we start catch the syscall instead [08/06/23] Why ? [28/07/23]
    # Should we split the "manual" between ptrace and waitpid ? So that I can only wait for the later ? For now I will put the breakpoint a bit later so that you can do continue_until("waitpid") [28/07/23]
    # TODO teach how to add symbols in a binary for the functions if the code is statically linked and stripped
    # TODO use plt if binary is not statically linked so that you don't need to load the libc ? [31/07/24] -> This may interfere with ltrace.
    def emulate_ptrace(self, *, off=False, wait_fun="waitpid", wait_syscall="wait4", manual=False, silent=False, signals = ["SIGSTOP"], syscall=False):
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
            if self._ptrace_syscall:
                log.warn("I still don't know how to disable the emulation with syscall")
                return

            for bp in self._ptrace_breakpoints:
                self.delete_breakpoint(bp)

            for address, backup in self._ptrace_backups.items():
                self.write(address, backup)
            self._ptrace_emulated = False
            return

        self._ptrace_emulated = True
        if syscall:
            assert self.gdb is not None, "libdebug can't catch ptrace syscall. Emulate with syscall = False"
            self._ptrace_syscall = True
        
        # TODO HANDLE CATCHPOINTS AS BREAKPOINTS TO DELETE THEM
        if len(self._ptrace_breakpoints):
            log.warn(f"[{self.pid}] is already emulating ptrace")
            return

        if DEBUG: self.logger.debug("emulating ptrace")

        if self.gdb is not None:
            # When emulating ptrace SIGSTOP is supposed to be used between the processes and caught by waitpid, so I don't pass it to the process to avoid problems [22/07/23]
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

        ptrace_dict = {constants.PTRACE_TRACEME: self._PTRACE_TRACEME,
            constants.PTRACE_POKEDATA: self._PTRACE_POKETEXT,
            constants.PTRACE_POKETEXT: self._PTRACE_POKETEXT, 
            constants.PTRACE_PEEKTEXT: self._PTRACE_PEEKTEXT, 
            constants.PTRACE_PEEKDATA: self._PTRACE_PEEKTEXT, 
            constants.PTRACE_GETREGS: self._PTRACE_GETREGS, 
            constants.PTRACE_SETREGS: self._PTRACE_SETREGS,
            constants.PTRACE_ATTACH: self._PTRACE_ATTACH,
            constants.PTRACE_SEIZE: self._PTRACE_SEIZE,
            constants.PTRACE_CONT: self._PTRACE_CONT,
            constants.PTRACE_DETACH: self._PTRACE_DETACH,
            constants.PTRACE_SETOPTIONS: self._PTRACE_SETOPTIONS,
            constants.PTRACE_SINGLESTEP: self._PTRACE_SINGLESTEP,}
        
        if not syscall:
            # Disable functions (Is it needed compared to a simple return in the callback ? I'm worried about the user manually going over the breakpoint) 
            shellcode = nop[context.arch] + return_instruction[context.arch]
            
            address = self._parse_address(wait_fun)
            backup = self.read(address, len(shellcode))
            self.write(address, shellcode)
            self._ptrace_backups[address] = backup

            address = self._parse_address("ptrace")
            backup = self.read(address, len(shellcode))
            self.write(address, shellcode)
            self._ptrace_backups[address] = backup

        def callback_wait(dbg, entry=None):
            def callback(dbg): 
                if syscall:
                    args = dbg.syscall_args
                else:
                    args = dbg.args

                pid = args[0]
                status_pointer = args[1]
                options = args[2]

                if pid == 2**32 - 1:
                    assert len(dbg._slaves) <= 1, "For now I can only handle waitpid(-1) if there is only one slave"
                    if len(self._slaves) == 0:
                        log.warn("The other process hasn't called TRACEME yet. I will wait... (just make sure you didn't setup ptrace_emulation too late)")
                    while len(self._slaves) == 0:
                        sleep(0.2)
                    pid = list(dbg._slaves.keys())[0]
                    if DEBUG: self.logger.debug("waiting for -1...")
                
                log.info(f'waitpid for process [{pid}]')
                if pid not in self._ptrace_group:
                    raise Exception(f"We reached waitpid but we didn't have time to split the new process! Please stop the process earlier")
                if pid not in self._slaves:
                    log.warn(f"The process {pid} hasn't called TRACEME yet. I will wait... (just make sure you didn't setup ptrace_emulation too late)")
                while pid not in self._slaves:
                    sleep(0.2)
                tracee = dbg._slaves[pid]
                stopped = tracee._wait_slave(options)

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
                # Don't stop for a WNOHANG [09/06/23]


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
            
            if syscall:
                return_code = SKIP_SYSCALL | should_stop
            else:
                return_code = should_stop

            return return_code

        if syscall:
            self.catch_syscall(wait_syscall, callback_wait)
        else:
            self._ptrace_breakpoints.append(self.b(wait_fun + "+1", callback=callback_wait, user_defined=False))

        # I still lose control if I hit the breakpoint on ptrace with a dbg.si()... [18/01/25]
        def ptrace_callback(dbg, entry=None):
            def callback(dbg):
                if syscall:
                    args = dbg.syscall_args
                else:
                    args = dbg.args

                ptrace_command = args[0]
                pid = args[1]
                arg1 = args[2]
                arg2 = args[3]
                
                log.info(f"[{dbg.pid}] ptrace {pid} -> {ptrace_command}: ({hex(arg1)}, {hex(arg2)})")
                action = ptrace_dict[ptrace_command]

                if ptrace_command == constants.PTRACE_TRACEME:
                    tracer = dbg if dbg._parent is None else dbg._parent
                    
                    if dbg.pid not in tracer._slaves:
                        log.info(f"TRACEME: [{dbg.pid}] will be trace by [{tracer.pid}]")
                        should_stop = action(tracer, manual=manual)

                    else:
                        log.warn(f"[{dbg.pid}] is already traced !")
                        dbg.return_value = -1
                        return manual

                elif ptrace_command in [constants.PTRACE_ATTACH, constants.PTRACE_SEIZE]:
                    
                    if pid in dbg._slaves:
                        log.warn(f"[{pid}] is already traced !")
                        dbg.return_value = -1
                        return manual

                    else:
                        tracee = dbg._ptrace_group[pid]
                        should_stop = action(pid, arg2, slave=tracee, manual=manual)

                else:
                    tracee = dbg._slaves[pid]
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

        if syscall:
            self.catch_syscall("ptrace", ptrace_callback)
        else:
            self._ptrace_breakpoints.append(self.b("ptrace+1", callback=ptrace_callback, user_defined=False))

        return self

    # We have problems with ptrace_group, but that was also a stupid idea so we should think about removing it... Just wait for the pid to be in the slaves... [22/12/23]
    # No, ptrace_group is still useful to get a process from his pid when emulating attach! [22/12/23]
    def trace(self, slave, parent=False):
        """
        Setup the debugger with the provided slave, simulating the state as if a fork and call to ptrace_traceme or ptrace_attach had been made.
        You still have to call self.emulate_ptrace() with the settings you want.

        Args:
            parent (bool): Optional. Set to True if the slave is the tracer's parent process. By default we will pretend the slave is a child.
        """
        self._slaves[slave.pid] = slave
        slave._ptrace_emulated = True
        if parent:
            self._parent = slave
            slave.children[self.pid] = self
        else:
            self.children[slave.pid] = slave
            slave._parent = self

   ########################## PTRACE EMULATION ##########################
    # If attach and interrupt stop the process I want continue and detach to let it run again, otherwise just set ptrace_can_continue [08/06/23]
    # Should we handle the interruptions in a special way ? Like adding a priority when attaching ? [08/06/23] (But how to handle stop due to a SIGNAL ?)

    # We could do a return False or True depending on if we interrupted the process or not. A small indication if we are debugging manually or not [08/06/23]
    def _PTRACE_ATTACH(self, pid, _, *, slave, **kwargs):
        log.info(f"pretending to attach to process {pid}")
        self._slaves[pid] = slave
        #if slave.running:
        #    log.info(f"attach will interrupt the slave")
        #    slave.interrupt()
        #    # It makes no sense because any signal interruption would not be able to distinguish if we were manually debugging or not [08/06/23] (Not really, but it would require a lot of work)
        #    #slave.ptrace_interrupted = True
        self._PTRACE_INTERRUPT(..., ..., slave=slave)
        slave._ptrace_has_stopped.set()
        self.return_value = 0
        return False

    def _PTRACE_SEIZE(self, pid, options, *, slave, **kwargs):
        log.info(f"pretending to seize process {slave.pid}")
        self._PTRACE_SETOPTIONS(pid, options, slave=slave)
        self._slaves[pid] = slave
        self.return_value = 0x0
        return False

    # Only function called by the slave
    def _PTRACE_TRACEME(self, tracer, *, manual=False, **kwargs):
        log.info("slave wants to be traced")
        tracer._slaves[self.pid] = self
        log.info(f"setting {self.pid} as slave for {tracer.pid}")
        self.return_value = 0
        # dirt left by ptrace that could be checked
        # Only do it if we don't handle the syscall... [26/07/23]
        #if context.arch == "amd64":
        #    self.r8 = -1
        # Wait, why ? haha. This was stupid... [24/12/23]
        #tracer._ptrace_has_stopped.set()
        return manual

    def _PTRACE_CONT(self, _, __, *, slave, manual=False, **kwargs):
        if not manual:
            log.info(f"[{self.pid}] PTRACE_CONT will let the slave [{slave.pid}] continue")
            slave._ptrace_has_stopped.clear()
            slave.__hidden_continue(force=True)
        else:
            slave._ptrace_can_continue.set()
            log.info("slave can continue !")
        self.return_value = 0x0
        return manual

    def _PTRACE_DETACH(self, _, __, *, slave, manual=False, **kwargs):
        log.ingo(f"ptrace detached from {slave.pid}")
        self._slaves.pop(pid)
        slave._ptrace_can_continue.set()
        if not manual:
            log.info(f"detach will let the slave continue")
            self.__hidden_continue(force=True)
        self.return_value = 0x0
        return manual

    def _PTRACE_POKETEXT(self, address, data, *, slave, manual=False, **kwargs):
        log.info(f"poking {hex(data)} into process {slave.pid} at address {hex(address)}")
        slave.write(address, pack(data))
        self.return_value = 0 # right ?
        return manual

    def _PTRACE_PEEKTEXT(self, address, _, *, slave, manual=False, **kwargs):
        try:
            data = unpack(slave.read(address, context.bytes))
            log.info(f"peeking {hex(data)} from process {slave.pid} at address {hex(address)}")
        except Exception:
            data = -1
            log.info(f"invalid address {hex(address)} to peek from process {slave.pid}. Returning -1")

        self.return_value = data
        return manual

    def _PTRACE_GETREGS(self, _, pointer_registers, *, slave, manual=False, **kwargs):
        registers = user_regs_struct()
        for register in slave._registers:
            value = getattr(slave, register)
            if DEBUG: self.logger.debug("reading [%d]'s register %s: 0x%x", slave.pid, register, value)
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            setattr(registers, register, value)
        self.write(pointer_registers, registers.get())
        self.return_value = 0 # right ?
        return manual

    # ATTENTO CHE setattr ritorna prima che venga fatto correttamente la jump per mettere rip. Quindi potresti avere una race condition [09/06/23]
    def _PTRACE_SETREGS(self, _, pointer_registers, *, slave, manual=False, **kwargs):
        registers = user_regs_struct()
        registers.set(self.read(pointer_registers, registers.size))
        for register in slave._registers:
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            value = getattr(registers, register)
            if DEBUG: self.logger.debug("setting [%d]'s register %s: 0x%x", slave.pid, register, value)
            setattr(slave, register, value)
        self.return_value = 0 
        return manual

    def _PTRACE_SETOPTIONS(self, _, options, *, slave, manual=False, **kwargs):
        if DEBUG: self.logger.debug("0x%x", options)
        if options & constants.PTRACE_O_EXITKILL:
            options -= constants.PTRACE_O_EXITKILL
            log.info("Option EXITKILL set")
            #if DEBUG: self.logger.debug("They want to kill the slave if you remove the master")
            if DEBUG: self.logger.debug("0x%x", options)
        
        if options & constants.PTRACE_O_TRACESYSGOOD:
            options -= constants.PTRACE_O_TRACESYSGOOD
            log.info("Option TRACESYSGOOD set")
            #log.debug("")
            if DEBUG: self.logger.debug("0x%x", options)
            
        if options != 0:
            raise Exception(f"{hex(options)}: Not implemented yet")

        self.return_value = 0x0
        return manual

    def _PTRACE_SINGLESTEP(self, _, __, *, slave, manual=False, **kwargs):
        log.info(f"ptrace single step from {slave.reverse_lookup(slave.instruction_pointer)}")
        slave.step()
        if DEBUG: self.logger.debug("Telling the slave that it has stopped")
        slave._ptrace_has_stopped.set()
        self.return_value = 0x0
        return manual
        
    # NOT TESTED YET
    def _PTRACE_INTERRUPT(self, _, __, *, slave, **kwargs):
        # Should I just send a SIGSTOP ? Using interrupt won't make it accessible to waitpid! [23/07/23]
        if DEBUG: self.logger.debug("waiting out of breakpoint")
        slave._out_of_breakpoint.wait()
        if DEBUG: self.logger.debug("out of breakpoint waited")
        ## 1) does it make sense ? If someone will try running while I interrupt it will try again just after. But this would break any action the master is trying to perform [21/06/23 14:00]
        ## 2) We can't have both this and the lock_wrapper for interrupt
        ##slave._ptrace_lock.can_run.clear()  
        #if slave.running:    
        #    log.info(f"ptrace will interrupt the slave [{slave.pid}]")
        #    slave.interrupt()
        # It won't be able to continue, right ? [21/06/23 13:30]
        ##slave._ptrace_lock.can_run.set()
        # Is the if needed ? Shouldn't we send the signal every time even in manual ? [23/07/23]
        if slave.running:
            os.kill(slave.pid, signal.SIGSTOP)
        self.return_value = 0x0

   ########################## REV UTILS ##########################

    # TODO if address set, return backup of area overwritten instead of address
    # TODO parameter "overwritable = False", if set to True save the memory region so that you can send other shellcodes without calling mprotect (Maybe set a larger area that simple len(shellcode) then)
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
            if DEBUG: self.logger.debug("allocating memory for shellcode")
            address = self.alloc(len(shellcode))

        if not skip_mprotect:
            self.make_page_rwx(address, len(shellcode))

        self.write(address, shellcode) # After make_page_rwx because in QEMU write may have to make the page writable anyway
        self.switch_inferior(old_inferior.num)

        return address

    def inject_sleep(self, address, inferior=None):
        """
        Inject a shellcode that stops the execution at a specific address

        Is meant to be used in the binary code, so it expects an address and returns the bytes that have been overwritten
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
        stopped = self.interrupt()
        if self._gef:
            print(self.execute("heap bins"))
        elif self._pwndbg:
            print(self.execute("bins"))
        else:
            print("GEF or pwndbg not detected")
        if stopped:
            self.c(wait=False)

    def chunks(self):
        stopped = self.interrupt()
        if self._gef:
            print(self.execute("heap chunks"))
        elif self._pwndbg:
            print(self.execute("heap"))
        else:
            print("GEF or pwndbg not detected")
        if stopped:
            self.c(wait=False)

    def telescope(self, address=None, length = 10, reference=None):
        """
        reference: int -> print the offset of each pointer from the reference pointer 
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        if self._gef:
            print(self.execute(f"telescope {hex(address) if address is not None else ''} -l {length} {'-r ' + hex(reference) if reference is not None else ''}"))
        elif self._pwndbg:
            print(self.execute(f"telescope {hex(address) if address is not None else ''} {length}"))
        else:
            print("telescope requires GEF or pwndbg")

   ########################### Heresies ##########################
    
    def __getattr__(self, name):
        # getattr is only called when an attribute is NOT found in the instance's dictionary
        # In the case of ./script.py REMOTE, if .remote() is not called we also return False because p hasn't been defined yet. Maybe that can be confusing ? [16/04/25]
        if name == "_initialized": #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self._registers in __setattr__
            return False

        if name in self._special_registers + self._registers + self._minor_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                res = 0
            elif self.gdb is not None:
                res = self._cached_registers.get(name, None)
                if res is not None:
                    return res
                try:
                    reg = self.gdb.parse_and_eval(f"${name}")
                except:
                    log.warn("error reading register. Retrying...")
                    reg = self.gdb.parse_and_eval(f"${name}")
                # .bytes is not supported yet in ubuntu 22
                #res = unpack(reg.bytes, "all")
                res = int(reg) & ((1 << reg.type.sizeof * 8) - 1)
                self._cached_registers[name] = res
            elif self.libdebug is not None:
                # BUG libdebug can not parse lower registers [19/11/23]
                res = getattr(self.libdebug, name)
            return res
        elif name in self._long_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                return 0
            elif self.gdb is not None:
                return int(self.execute(f"p ${name}.uint128").split(" = ")[-1])
            else:
                raise Exception("not supported")
        elif name in self._libraries:
            with context.silent:
                return self.libraries[name]
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

    # Consider checking if the value is an instance of ELF and in case look for the base address. This is useful when we need other libraries than libc. [11:45] 
    def __setattr__(self, name, value):
        if not self._initialized:
            super().__setattr__(name, value)
        elif name in self._special_registers + self._registers + self._minor_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                return
            elif self.gdb is not None:
                if name.lower() in ["eip", "rip", "pc"]:
                    # GDB has a bug when setting rip ! [09/06/23]
                    self.jump(value)
                else:  
                    if DEBUG: self.logger.debug(" setting %s to %d", name, value)
                    # NOTE: a single reference to a gdb.Value of a register can be used to assign the value (no need for modulo). `self.gdb.parse_and_eval(f"${name}").assign(value)`. It would be nice to have only a list of references to all registers and use them, but while they can be used to assign values, you can not read values updated during the execution. [13/08/24]
                    # We keep the % to convert types such as pwn.Constant to ints 
                    # We did test that it doesn't create problems with negative values on 32 bit registers in 64 bit programs
                    self.execute(f"set ${name.lower()} = {value % 2**context.bits}")
                # NOTE: Currently setting a register will cause a clear_cache [06/02/25]
                # TODO: Change clear_cache to leave it when we are the one setting a register
                # self._cached_registers[name] = value % 2**context.bits # I can not guarantee that this will be correct
            elif self.libdebug is not None:
                setattr(self.libdebug, name, value % 2**context.bits) # I don't remember if libdebug accepts negative values
            else:
                ...
        elif name in self._long_registers:
            if not self.debugging:
                log.warn_once(DEBUG_OFF)
                return
            elif self.gdb is not None:
                if DEBUG: self.logger.debug(" setting %s to %d", name, value)
                self.execute(f"set {name}.uint128={value}")
            else:
                raise Exception("Not supported")
        elif name in self._libraries:
            self._libraries[name] = value # Allow to overwrite libraries (In case of remote path)
        else:
            super().__setattr__(name, value)

    def __repr__(self) -> str:
        # I'm afraid it may crash if used with remote [17/11/23]
        if self.pid is None:
            return super().__repr__()

        if self._closed.is_set():
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
