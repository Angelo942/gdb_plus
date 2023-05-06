from pwn import *
import os
from time import sleep
from functools import partial
from capstone import Cs, CS_ARCH_X86
from threading import Event
from queue import Queue
from gdb_plus.utils import Arguments, user_regs_struct, context, MyEvent, Breakpoint

RET = b"\xc3"

class Debugger:
    # If possible patch the rpath (spwn and pwninit do it automatically) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target: [int, process, str, list], env={}, aslr:bool=True, script:str="", from_start:bool=True, binary:str=None, debug_from: int=None, timeout: int=0.5):
        log.debug(f"debugging {target if binary is None else binary} using arch: {context.arch} [{context.bits}bits]")

        self._capstone = None #To decompile assembly for next_inst
        self._auxiliary_vector = None #only used to locate the canary
        self._base_libc = None
        self._base_elf = None
        self._canary = None
        self._args = None
        self.closed = Event()
        self._inferior = 1 # Used to switch between inferiors [03/03/23]
        self.children = {} # Maybe put {self.pid: self} as first one
        self.slaves = {} # to emulate ptrace
        self.master = None
        # Maybe use a queue. Maybe even share the same one between slave and master so you don't need the pid. [26/03/23]
        self._wait_signal = None
        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        # Do we want to save temporary breakpoints too ? [17/04/23]
        self.breakpoints = {} #Save all non temporary breakpoints for easy access # The fact that they can't be temporary is used by the callback [21/03/23]
        self.gdbscript = script # For non blocking debug_from
        self.debug_from_done = Event()

        # To know that I'm responsible for the interruption even if there is no callback
        self.stepped = False
        self.interrupted = False
        # Maybe not needed (see set_split_on_fork)
        self.last_breakpoint_deleted = 0 # Keep track of the last temporary breakpoint deleted if we realy have to know if we hit something

        if args.REMOTE or context.noptrace:
            self.debugging = False
        else:
            self.debugging = True

        # The idea was to let gdb interrupt only one inferior while letting the other one run, but this doesn't work [29/04/23]
        #script = "set target-async on\nset pagination off\nset non-stop on" + script

        if type(target) is int:
            self.p = None
            self.pid = target
            assert binary is not None, "I need a file to work from a pid" # Not really... Let's keep it like this for now, but continue assuming we don't have a real file
            self.elf = ELF(binary, checksec=False)
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

        # pwntools symbols duplicate every entry in the plt and the got. This breaks my version of symbols because they have the same name as the libc [25/03/23]
        # This may break not stripped statically linked binaries, just wait for the libc to be loaded and those symbols will be overshadowed [25/03/23]
        # Let's still do it for dynamically linked binaries [04/04/23]
        if self.elf and not self.elf.statically_linked:
            for symbol_name in list(self.elf.symbols.keys()):
                if (symbol_name.startswith("plt.") or symbol_name.startswith("got.")) and (name := symbol_name[4:]) in self.elf.symbols:
                    del self.elf.symbols[name]

        # Because pwntools context isn't perfect
        self.restore_arch()

        if self.debugging:
            self.elf.address = self.get_base_elf()

            # Start debugging from a specific address. Wait timeout seconds for the program to reach that address. Is blocking so you may need to use context.Thread() in some cases
            # WARNING don't use 'continue' in your gdbscript when using debug_from ! [17/04/23]
            # I don't like that this is blocking, so you can't interact while waiting... Can we do it differently ? [17/04/23]
            if debug_from is not None:
                address_debug_from = self.parse_address(debug_from)
                backup = self.inject_sleep(address_debug_from)
                while True:  
                    self.detach()
                    sleep(timeout)
                    # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
                    _, self.gdb = gdb.attach(self.pid, gdbscript=script, api=True) # P is gdbserver...
                    if self.instruction_pointer - address_debug_from in range(0, len(backup)): # I'm in the sleep shellcode
                        self.write(address_debug_from, backup)
                        # To allow call to wait inside the jump
                        self.myStopped = self.gdb.stopped
                        self.myStopped.priority = 0
                        # should maybe rename priority_wait into wait and avoid this line [17/04/23]
                        self.myStopped.priority_wait = lambda: self.myStopped.wait()
                        self.jump(address_debug_from)
                        break
                    else:
                        log.warn(f"{timeout}s timeout isn't enought to reach the code... Retrying...")

            self.__setup_gdb()

    # We stopped using gdb's implementation of temporary breakpoints so that we can differentiate an interruption caused by my debugger and cause by the manual use of gdb 
    # Event could tell me which breakpoint has been hit or which signal cause the interruption
    def __stop_handler(self):
        """
        Actions that the debugger performs every time the process is interrupted
        Handle temporary breakpoints and callbacks
        """
        self.restore_arch()

        ## I don't want to use interrupt in split_on_fork
        #if not self.to_split.empty():
        #    pid = self.to_split.get()
        #    log.debug(f"found child {pid} to split out")
        #    self.children[pid] = self.split_child(pid=pid)

        # Current inferior will change to the inferior who stopped last
        ip = self.instruction_pointer
        bp = self.breakpoints.get(ip)
        log.debug(f"{self.current_inferior.pid} stopped at address: {hex(ip)} for {self._stop_reason}")
        
        if bp is None:
            if self.stepped or self.interrupted or self._stop_reason in ["SIGSTOP", "SIGTRAP"]: # SIGTRAP to handle known int3 in the code
                # I hope that the case where we step and still end up on a breakpoint won't cause problems because we would not reset stepped... [29/04/23]
                self.stepped = False
                self.interrupted = False
                self.__set_stop()
            return            
        
        if bp.temporary:
            self.delete_breakpoint(ip)

        # TODO, it may be interesting to have the option to put an array of breakpoints for recursive functions [21/03/23]
        # something like
        #if type(self.real_callbacks[self.instruction_pointer]) is list:
        #   callback =  self.real_callbacks[ip].pop()
        #   if len(self.real_callbacks[ip]) == 0:
        #       del self.real_callbacks[ip]
        #else:
                        
        # This should let us keep control of the debugger even if we use gdb manually while emulating ptrace
        # Doesn't handle the case where we use ni and hit the breakpoint though... [17/04/23] TODO!
        # Doesn't even handle the case where I step, but I'm waiting in continue until
        if bp.callback is not None and bp.callback(self) == False and self._stop_reason != "SINGLE STEP":
            self.execute("c")
        else:
            self.__set_stop()  
        
    def __setup_gdb(self):
        """
        setup of gdb's events
        """
        # MyEvent allows calls to wait in parallel
        self.myStopped = MyEvent() # Include original event
        self.myStopped.set() # we call __setup_gdb after an attach so the process isn't running. Make just sure this doesn't cause troubles [17/04/23]

        self.gdb.events.stop.connect(lambda event: context.Thread(target=self.__stop_handler).start())
        
        def exit_handler(event):
            log.debug("setting stop because process exited")
            self.myStopped.pid = self.current_inferior.pid
            self.myStopped.set()
            self.closed.set()

        self.gdb.events.exited.connect(exit_handler)

        # Manually set by split_child
        self.split = Queue()

        # Ptrace_cont
        self.master_wants_you_to_continue = Event()
        self.slave_has_stopped = Event()    

    # Because pwntools isn't perfect
    def restore_arch(self):
        """
        check that the context used by pwntools is correct
        """
        if self.elf is not None and context.arch != self.elf.arch:
            log.debug("wrong context ! Updating...")
        context.arch = self.elf.arch
        context.bits = self.elf.bits

    def debug_from(self, location: [int, str], *, event=None, timeout=0.5):
        """
        Alternative debug_from which isn't blocking
        wait dbg.debug_from_done to know when to continue

        event: optional event to signal that you have finished the actions you needed to perform. Otherwise a timeout of 0.5s will be used
        """
        address = self.parse_address(location)

        if self.debugging:
            def action():
                backup = self.inject_sleep(address)
                while True:  
                    self.detach()
                    if event is not None:
                        event.wait()
                        log.debug("user finished interaction. Proceeding with debug_from")
                    log.warn("you haven't set an event to let me know when you finished interactiong with the process. I will give you half a second.")
                    sleep(timeout)
                    # Maybe the process is being traced and I can't attach to it yet
                    try:
                        # what happens if there is a continue in script ? It should break the script, but usually it's the last instruction so who cares ? Just warn them in the docs [06/04/23]
                        _, self.gdb = gdb.attach(self.p.pid, gdbscript=self.gdbscript, api=True) # P is gdbserver...
                    except Exception as e:
                        log.debug(f"can't attach in debug_from because of {e}... Retrying...")
                        continue
                    self.__setup_gdb()
                    if self.instruction_pointer - address in range(0, len(backup)): # I'm in the sleep shellcode
                        self.write(address, backup)
                        self.jump(address)
                        self.debug_from_done.set()
                        break
                    else:
                        log.warn(f"{timeout}s timeout isn't enought to reach the code... Retrying...")

            context.Thread(target=action).start()
        else:
            #log.warn_once(FEATURE_SKIPPED)
            self.debug_from_done.set()
        return self

    # Use as : dbg = Debugger("file").remote(IP, PORT)
    def remote(self, host: str, port: int):
        """
        Define the connection to use when the script is called with argument REMOTE
        """
        if args.REMOTE:
            self.p = remote(host, port)
        return self

    def detach(self, quit = True):
        try:
            self.execute("detach")
        except:
            log.debug("process already stopped")
        try:
            self.execute("quit") # Doesn't always work if after interacting manually
        except EOFError:
            log.debug("GDB successfully closed")

    def close(self):
        self.detach()
        # Can't close the process if I just attached to the pid
        if self.p:
            self.p.close()

    # Now we may have problems if the user try calling it...
    # should warn to use execute_action and wait if they are doing something that will let the process run
    def execute(self, code: str):
        """ 
        Execute a command that does NOT require a wait later
        """
        if self.debugging:
            return self.gdb.execute(code, to_string=True)
        else:
            log.warn_once("Debug is off, commands won't be executed")

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
        values = []
        for register in self.special_registers + self.registers[:-1]: # exclude ip
            values.append(getattr(self, register))
        return values
        
    def restore_backup(self, backup: list):
        """
        Reset the state of all registers from a backup
        """
        for name, value in zip(self.special_registers + self.registers[:-1], backup):
                setattr(self, name, value)

    # Return old_inferior to know where to go back
    def switch_inferior(self, n: int) -> int:
        """
        For multi-process applications change the process you are working with in gdb
        """
        # May not be accurate if you switched manually before
        old_inferior = self._inferior
        while self.gdb.selected_inferior().num != n:
            log.debug(f"switching to inferior {n}")
            self.execute(f"inferior {n}")
            log.debug(f"I'm inferior {self.gdb.selected_inferior()}")
            self._inferior = n
        return old_inferior

    @property
    def inferiors(self):
        return {inferior.num: inferior for inferior in self.gdb.inferiors()}
        #return (None,) + self.gdb.inferiors()

    # Useless ? I wanted it for the interrupt, but info inferior requires to be at a halt [07/03/23]
    @property
    def current_inferior(self):
        # trova ultimo id
        # prendi ultima riga non nulla
        #data = self.execute("info inferior").split("\n") # shouldn't it be "info inferiorS" ?
        #for line in data:
        #    line = line.split()
        #    if line[0] == "*":
        #        n = int(line[1])
        #        return self.inferiors[n]
        return self.gdb.selected_inferior()

    @property
    def args(self):
        """
        Access arguments of the current function
        Can be use to read and write
        Can only access a single argument at a time
        dbg.args[5] = 1 # Valid
        a, b = dbg.args[:2] # Not valid!
        """
        if self._args is None:
            self._args = Arguments(self)
        return self._args 

    # Taken from GEF to handle slave interruption
    @property
    def _stop_reason(self) -> str:
        res = self.gdb.execute("info program", to_string=True).splitlines()
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

    @property
    def _details_breakpoint_stopped(self) -> str:
        """
        If the program stopped at a breakpoint, return the id of that breakpoint
        This can be used to identify caught syscall
        """
        for line in res:
            line = line.strip()
            #It stopped at breakpoint 2.
            if line.startswith("It stopped at breakpoint "):
                return line.split(".")[0][len("It stopped at breakpoint "):]
        else:
            log.warn("process didn't stop for a breakpoint")


   ########################## CONTROL FLOW ##########################

    # For commands that will make the process run and should handle priority
    def execute_action(self, command, sender=None):
        """
        Wrapper around execute to handle commands that will require a wait
        """
        self.priority += 1
        self.__clear_stop(sender if sender is not None else command)
        self.execute(command)

    def __c(self, wait, done):
        if wait:
            self.priority_wait()
        if done is not None:
            done.set()

    # TODO make the option to have "until" be non blocking with an event when we reach the address [28/04/23] In other words migrate wait=False to wait=Event()
    def c(self, *, wait=True, force = False, until = None):
        """
        Continue execution of the process

        Arguments:
            wait: Should block your script until the next interruption ?
            until: Continue until a specified location. Your script will wait if you have to play with gdb manually.

            force: gdb may bug and keep you at the same address after a jump or if the stackframe as been edited. If you notice this problem use force to bypass it 
        """
        self.restore_arch()

        # I always step so if we catch a broken instruction we can inform the user [05/05/23]
        # In case of force=False the program should continue anywhay since we are already stepping, but the program will still raise a warning. [05/05/23]
        self.step(force=force)

        if until is not None:
            log.warn_once("dbg.cont(until=ADDRESS) is deprecated, use dbg.continue_until(ADDRESS) instead!")
            return self.continue_until(until, wait=True)
        
        self.execute_action("continue", sender="continue")
        
        if wait:
            self.priority_wait()
        elif until is not None:
            return done
        else:
            pass
            # I would like to return done too, but I'm sure the average user will try dbg.wait instead of done.wait

    cont = c

    def __continue_until(self, address, done):
        self.execute_action("continue", sender="continue_until")
        self.priority_wait()
        # Should we take into consideration the inferior too ? [29/04/23]
        while self.instruction_pointer != address:
            log.info(f"debugger {self.pid} stopped at {hex(self.instruction_pointer)} for '{self._stop_reason}' instead of {hex(address)}")
            log.warn_once("I assume this happened because you are using gdb manually. Finish what you are doing and let the process run. I will handle the rest")
            self.execute_action("", sender="continue just to reset the wait")
            self.priority_wait()
        done.set()

    def continue_until(self, location, /, *, wait=True):
        """
        Continue until a specific address
        can be blocking or non blocking thanks to wait
        It the function is called from the address you want to reach the intended behaviour is to supose you are in a loop and continue anyway
        """ 
        self.restore_arch()
        
        self.step(force=True) # force=True just to be sure 
        address = self.parse_address(location)
        if address == self.instruction_pointer:
            return
            
        self.b(address, temporary=True)
        log.debug(f"{self.pid} continuing until {hex(address)}")

        done = Event()
        context.Thread(target=self.__continue_until, args=(address, done)).start()
        if wait:
            done.wait()
        else:
            return done

    until = continue_until


    def wait(self, timeout=None, legacy=False):
        """
        Wait for the process to stop after an action.
        Won't return until all future actions have been handled so that you can use it at the same time in your script and in a breakpoint
        """
        if legacy:
            self.myStopped.wait(timeout)
        else:
            self.priority_wait()

    # This should only be used under the hood, but how do we let the other one to the user without generating problems ? [14/04/23]
    def priority_wait(self):
        self.myStopped.priority_wait()

    # problems when I haven't executed anything
    @property
    def running(self):
        return not self.myStopped.is_set()

    @property
    def priority(self):
        return self.myStopped.priority

    @priority.setter
    def priority(self, value):
        self.myStopped.priority = value

    def __clear_stop(self, name="someone", /):
        log.debug(f"{self.current_inferior.pid} stopped has been cleared by {name}")
        self.myStopped.clear()

    def __set_stop(self):
        log.debug(f"{self.current_inferior.pid} setting stopped in {hex(self.instruction_pointer)}")
        # handle case where no action are performed after the end of a callback with high priority 
        self.__clear_stop("__set_stop")
        self.myStopped.pid = self.current_inferior.pid
        self.myStopped.set()

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
        pid = self.split.get()
        if pid == 0:
            raise Exception("What the fuck happened with split ???")
        return pid

    def advanced_continue_and_wait_split(self):
        log.warn("advanced_continue_and_wait_split is deprecated. Use cont(until=\"fork\"); finish(); wait_split() instead")
        self.c(until="fork")
        self.finish()
        return self.wait_split()

    # For now is handled by simple wait [06/03/23]
    def wait_exit(self):
        self.closed.wait()

    def wait_master(self):
        self.master_wants_you_to_continue.wait()
        self.master_wants_you_to_continue.clear()

    # Should handle multiple slaves ?
    def wait_slave(self):
        self.slave_has_stopped.wait()
        self.slave_has_stopped.clear()

    # temporarily interrupt the execution of our process to get back control of gdb (equivalent of a manual ctrl+C)
    # don't worry about the "kill"
    # May cause problem with the priority [26/04/23]
    # Why does it allways interrupt the first inferior even when I switch to another one ?? [29/04/23]
    def interrupt(self):
        """
        Stop the process as you would with ctrl+C in gdb

        Warning: can not YET be put inside a callback
        """
        if not self.debugging:
            #log.warn_once(FEATURE_SKIPPED)
            return
        
        # TODO check that self.running is valid and then use execute_action and priority_wait
        # Can not work correctly with multiple inferiors. End up always interrupting the first one... [29/04/23]
        if self.running == self.running:
            self.interrupted = True
            #self.myStopped.clear()
            #os.kill(self.inferiors[self._inferior].pid, signal.SIGINT)
            #self.wait(legacy=True, timeout=0.1)
            # Need priority if calling interrupt in callback for split while waiting for finish in another thread
            log.debug(f"interrupting inferior: {self.current_inferior} [pid:{self.current_inferior.pid}]")
            self.execute_action("interrupt", sender="interrupt")
            #os.kill(self.inferiors[self._inferior].pid, signal.SIGSTOP)
            self.priority_wait()

    manual = interrupt


    # Next may break again on the same address, but not step
    # Why isn't force = True the default behaviour ? [29/04/23]
    # I don't use force=True by default because there are instructions that keep the instruction pointer at the same address even if executed [05/05/23]
    def step(self, repeat:int=1, *, force=False):
        """
        execute a single instruction

        Argument:
            repeat: step n times
            force : if the stackframe has been tampered with gdb may stay stuck on the current instruction. Use force to handle this bug in gdb
        """
        for _ in range(repeat):
            address = self.instruction_pointer
            self.stepped = True
            self.execute_action("si", sender="step")
            self.priority_wait() 
            if address == self.instruction_pointer:
                # If I want to handle here the case where gdb updates the stack_frame, but stays on the same address. Currently handled by "exit_broken_function" [23/03/23]
                if force:
                    self.step(force=True)
                else:
                    log.warn("You stepped, but the address didn't change. This may be due to a bug in gdb. If this wasn't the intended behaviour use force=True in the function step or continue you just called")

    si = step

    def __broken_step(self):
        old_ip = self.instruction_pointer
        callback = None

        # Remove callback to avoid calling it twice (Nice, this wasn't possible with legacy_callbacks) (I'm not sure if we could simply disable a breakpoint for a turn)
        if (bp := self.breakpoints.get(old_ip)) is not None:
            callback = bp.callback
            bp.callback = None

        self.step()

        while self.instruction_pointer == old_ip:
                log.debug("Bug ret still present")
                self.step()

        if callback is not None:
            bp.callback = callback

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

    def step_until_ret(self, callback=None, limit:int=10_000) -> int:
        """
        step until the end of the function

        Arguments:
            callback: optional function to call at each step
            limit: number of step before giving up. Set at 10.000 by default
        """
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
        """
        for i in range(limit):
            if condition(self):
                return i
            self.step()

        log.warn_once(f"I made {limit} steps and haven't found what you are looking for...")
        return -1

    def __next(self, repeat, done=None):
        for _ in range(repeat):
            next_inst = self.next_inst
            if next_inst.mnemonic == "call":
                self.c(until=self.instruction_pointer+next_inst.size)
            else:
                self.step()
        if done is not None:
            done.set()

    # May not want to wait if you are going over a functions that need user interaction
    def next(self, wait:bool=True, repeat:int=1):
        if wait:
            self.__next(repeat)
        else:
            done = Event()
            context.Thread(target=self.__next, args=(repeat, done)).start()
            return done

    ni = next

    def __finish(self, repeat, done):
        # Should be possible to take immediatly the corresponding stack frame instead of using a loop [28/04/23]
        for _ in range(repeat):
            ip = self.__saved_ip
            log.debug(f"finish found next ip : {hex(ip)}")
            if ip == 0:
                raise Exception("stack frame is broken or we are not in a function")
            self.c(until=ip)
        if done is not None:
            done.set()

    # May be dependent on the stack frame and cause problems after a jump [27/04/23]
    def finish(self, *, wait:bool=True, repeat = 1):
        done = Event()    
        context.Thread(target=self.__finish, args=(repeat, done)).start()
        if wait:
            done.wait()
        else:
            return done

    # How to handle a jump no wait without destroying the priority queue ? [17/04/23]
    # Don't let it as an option... [17/04/23]
    def jump(self, location: [int, str], stop = True):
        """
        Jump to specified location
        """
        #log.warn_once("jump is deprecated. Overwrite directly the instruction pointer instead")
        address = self.parse_address(location)
        # BUG setting rip this way may cause problems with si [30/04/23] 
        #self.instruction_pointer = address
        self.b(address, temporary=True)
        self.execute_action(f"jump *{hex(address)}", sender="jump")
        self.priority_wait()

    # Now can return from anywhere in the function
    # Works only for standard functions (push rbp; mov rbp, rsp; ...; leave; ret;). May crash if used in the libc
    # Can't I use __saved_ip now ? [28/04/23]
    def ret(self, value: int = None):
        """
        Exit from current function without executing it. 

        Warning: Experimental and depends on the stack frame
        """
        #log.warn_once(f"ret is still at an experimental stage and may not work properly")
        #if self.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
        #    pass
        #elif self.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
        #    self.pop() # Remove the base pointer # No need to place it back in rbp
        #else:
        #    self.stack_pointer = self.base_pointer
        #    self.base_pointer = self.pop()
        #ret_address = self.pop()
        #self.instruction_pointer = ret_address
        self.instruction_pointer = self.__saved_ip
        if value is not None:
            self.return_value = value

    # For some reasons we get int3 some times
    def gdb_call(self, function: str, args: list, *, cast = "long"):
        if not self.elf.statically_linked:
            try:
                ans = self.execute(f"call ({cast}) {function} ({', '.join([hex(arg) for arg in args])})")
                if cast == "void":
                    return None
                ans = ans.split()[-1]
                # GEF prints logs as base 16, but pwndbg as base 10
                return int(ans, 16) if "0x" in ans else int(ans)
            except Exception: #gdb.error: The program being debugged was signalled while in a function called from GDB.
                log.debug(f"gdb got int3 executing {function}. Retrying...")
                self.finish()
                # For some reason I just get 0x0
                #return self.return_value()
                return self.gdb_call(function, args) # Should work this time
        
        elif function in self.symbols:
            return self.call(self.symbols[function], args)
            
        else:
            raise Exception(f"I don't know how to handle this function! {function} not in symbols")

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
                self.write(pointer, arg + b"\x00")
                arg = pointer

            parsed_args.append(arg)

        return parsed_args, to_free

    def __continue_call(self, backup, to_free, heap, end_pointer, return_value):
        if end_pointer is None:
            self.finish() # Finish can only work if the stack-frame isn't broken
            log.debug("call finished")
                
        else:
            self.c(until=end_pointer)
            # Exit the function
            self.step()
        
        res = self.return_value
        self.restore_backup(backup)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        return_value.put(res) # will be the event that tells me I finished

    # I still need end_pointer even if I would like to put the breakpoint on the address from which we call the function because I can't be sure that someone won't want to call a function from inside 
    def call(self, function: [int, str], args: list = [], *, end_pointer=None, heap=True, wait = True):
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
            The function will run with a 'finish' command. If for some reason you know that it won't work this way you can set an instruction to stop at. (I currently expect it to be a ret and will step on it to leave)
        heap : bool, optional
            Byte arrays and strings passed to the functions are by default saved on the heap with a malloc(). If you can't set this to False to save them on the bss (WARNING I can't guaranty I won't overwrite data this way)
        """
        self.restore_arch()
        
        address = self.parse_address(function)
        
        args, to_free  = self.__convert_args(args, heap)

        #save registers 
        backup = self.backup()    
        
        if context.bits == 64:
            calling_convention = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            for register in calling_convention:
                if len(args) == 0:
                    break
                log.debug("%s setted to %s", register, args[0])
                setattr(self, register, args.pop(0))
            
        #Should I offset the stack pointer to preserve the stack frame ? No, right ?
        for arg in args:
            self.push(arg)
        
        # May be useful later
        return_address = self.instruction_pointer
        self.push(return_address)
        self.jump(address)

        return_value = Queue()
        context.Thread(target=self.__continue_call, args=(backup, to_free, heap, end_pointer, return_value)).start()
        if wait:
            return return_value.get()
        else:
            log.warn_once("you decided not to wait for the call to finish. I return a queue to the return value of the function. When you need it use .get() to wait for the call to finish")
            return return_value

    # Can be used with signal code or name. Case insensitive.
    # TODO handle priority_wait
    def signal(self, n: [int, str], /, *, handler : [int, str] = None):
        """
        Send a signal to the process and put and break returning from the handler
        Once sent the program will jump to the handler and continue running therefore We set a breakpoint on the next instruction before sending the signal.
        (If no handler is defined by the program remember that the process will die)
        You can put breakpoints in the handler and debug it as you please, but remember that there will always be a breakpoint when you return from the handler

        Parameters
        ----------
        n : INT or STRING
            Name or id of the signal. Name isn't case sensitive
        handler : POINTER, optional
            USE IF SIGNAL WILL MODIFY THE NEXT INSTRUCTION
            Pointer to the last instruction of the signal handler. Will be used to set a breakpoint after the code has been modified
        """

        log.warn_once("the method signal() is still evolving. Use it if you don't want the program to continue after receiving the signal. If the signal will modify your code you HAVE to add the argument 'handler' with an address after the code has changed")
        # Sending signal will cause the process to resume his execution so we put a breakpoint and wait for the handler to finish executing
        # I may put a flag to precise if the code is self modifying or not and if it is handle breakpoints
        # If the code is self modifying you must use handler otherwise the breakpoint will be overwritten with bad code [26/02/23]
        if handler is None:
            self.b(self.instruction_pointer, temporary=True)
        else:
            from queue import Queue
            my_address = Queue()
            my_address.put(self.instruction_pointer)
            def callback(dbg):
                address = my_address.get()
                my_address.put(dbg.instruction_pointer)
                dbg.b(address, temporary=True)
                return False  
            self.b(handler, callback=callback, temporary=True)
        
        if type(n) is str:
            n = n.upper()
        self.execute_action(f"signal {n}", sender="signal")
        self.priority_wait()

    def syscall(self, code: int, args: list, *, heap = True):
        log.debug(f"syscall {code}: {args}")
        
        if context.bits == 64:
            calling_convention = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            shellcode = b"\x0f\x05"
        else:
            calling_convention = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
            shellcode = b"\xcd\x80"
        
        assert len(args) <= len(calling_convention), "too many arguments for syscall"

        backup_registers = self.backup()
        return_address = self.instruction_pointer
        backup_memory = self.read(return_address, len(shellcode))
        self.write(return_address, shellcode)
        self.return_value = code

        args, to_free = self.__convert_args(args, heap)

        for register, arg in zip(calling_convention, args):
            log.debug("%s setted to %s", register, arg)
            setattr(self, register, arg)
    
        self.step()
        res = self.return_value
        self.restore_backup(backup_registers)
        self.write(return_address, backup_memory)
        self.jump(return_address)
        for pointer, n in to_free[::-1]: #I do it backward to have a coherent behaviour with heap=False, but I still don't really know if I should implement a free in that case
            self.dealloc(pointer, len=n, heap=heap)
        
        return res

    # TODO take a library for relative addresses like libdebug
    def parse_address(self, location: [int, str]) -> str:
        """
        parse symbols and relative addresses to return the absolute address
        """
        if type(location) is int:
            address = location
            if location < 0x010000:
                address += self.base_elf
            elif location < 0x020000:
                log.warn("are you sure you haven't copied the address from ghidra without correctly rebasing the binary ?")

        elif type(location) is str:
            function = location
            offset = 0
            if "+" in location:
                # die if more than 1 +, but that's your fault
                function, offset = [x.strip() for x in location.split("+")]
            address = self.symbols[function] + offset

        else:
            raise f"parse_breakpoint is asking what is the type of {location}"
        
        return address

    # Legacy
    parse_for_breakpoint = parse_address

    # May want to put breakpoints relative to the libc too?
    # I want to keep legacy breakpoints for the ones I set with the library because we must be able to work manually when emulating ptrace [23/03/23]
    # legacy_callback will be deprecated once I can overwrite gdb's nexti to keep his breakpoint even if the process gets interrupted [27/04/23]
    def b(self, location: [int, str], callback=None, legacy_callback=None, temporary=False):
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

        Returns
        -------
        Breakpoint
            Return a pointer to the breakpoint set
            I don't see when you would need it, but here it is
        """

        # Move from callback to real_callback
        # real_callbacks have problems, but with features not even available with simple callbacks. Furthermore now you can use return False with temporary breakpoints
        if not self.debugging:
            return

        address = self.parse_address(location)

        log.debug(f"putting breakpoint in {hex(address)}")
        
        # Still needed for hidden breakpoint with return False when you want to also use gdb manually [17/04/23]
        if legacy_callback is not None:
            log.warn_once("if your callbacks crash you may not notice it and you have to scroll a bit to find the error messages hidden in the gdb terminal")
            # I don't know yet how to handle the conn if I don't go through self.gdb.Breakpoint so I create the class here :(
            class MyBreakpoint(self.gdb.Breakpoint):
                def __init__(_self, address, callback):
                    super().__init__(address)
                    _self.callback = legacy_callback
                # WARNING IF A TEMPORARY BREAKPOINT DOESN'T STOP IT WON'T COUNT AS HIT AND STAY ACTIVE. May cause problems with the callback if you pass multiple times [26/02/23]
                def stop(_self, *args):
                    _break = _self.callback(self) 
                    if _break is None:
                        return True
                    return _break
            res = MyBreakpoint(f"*{hex(address)}", callback)

        else:
            res = self.gdb.Breakpoint(f"*{hex(address)}")
        
        self.breakpoints[address] = Breakpoint(res.server_breakpoint, callback, temporary)
        return res
        
    breakpoint = b

    def delete_breakpoint(self, location: [int, str]) -> bool:
        address = self.parse_address(location)
        # Is there a case where it isn't ?? [17/04/23]
        if address in self.breakpoints:
            self.breakpoints.pop(address).gdb_breakpoint.delete() # Remove from dict and delete from gdb

    ########################## MEMORY ACCESS ##########################

    def read(self, address: int, size: int, *, inferior = None) -> bytes:

        if inferior == None:
            inferior = self._inferior

        log.debug(f"reading from inferior {inferior}")
        return self.inferiors[inferior].read_memory(address, size).tobytes()

    def write(self, address: int, byte_array: bytes, *, inferior = None):

        if inferior == None:
            inferior = self._inferior
        
        inferior = self.inferiors[inferior]
        log.debug(f"writing {byte_array} in {inferior} at address {hex(address)}")
        # BUG: GDB writes in the wrong inferior...
        #inferior.write_memory(address, byte_array)
        fd = os.open(f"/proc/{inferior.pid}/mem", os.O_RDWR)
        os.lseek(fd, address, os.SEEK_SET)
        os.write(fd, byte_array)
        os.close(fd)

    def push(self, value: int):
        """
        push value (must be uint) on the stack
        """
        log.debug(f"pushing {pack(value)}")
        self.stack_pointer -= context.bytes
        self.write(self.stack_pointer, pack(value))

    def pop(self) -> int:
        """
        pop value (uint) from the stack
        """
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
    
    def alloc(self, n: int, /, *, heap=True, inferior = None) -> int:
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

        if inferior == None:
            inferior = self._inferior
        
        if heap:
            old_inferior = self.switch_inferior(inferior)
            
            res = self.gdb_call("malloc", [n])

            self.switch_inferior(old_inferior)

            return res

        else:
            if self._free_bss is None:
                self._free_bss = self.elf.bss() # I have to think about how to preserve eventual data already present
            self._free_bss += n
            return self._free_bss
        
    def dealloc(self, pointer: int, len=0, heap=True, inferior = None):
        
        if inferior == None:
            inferior = self._inferior
        
        if heap:
            
            old_inferior = self.switch_inferior(inferior)

            self.gdb_call("free", [pointer], cast="void")

            self.switch_inferior(old_inferior)

        else:
            # MMMMMMM, not perfect for different inferiors
            self._free_bss -= len
            #I know it's not perfect, but damn I don't want to implement a heap logic for the bss ahahah
            #Just use the heap if you can

    # I copied it from pwntools to have access to it even if I attach directly to a pid
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
    def get_base_elf(self):
        maps = self.libs()
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
            #        print(f"Entry point = {hex(address)}")
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
        if hasattr(self, "libc") and self.libc is not None: # If I attack to a pid I self.p doesn't have libc = None
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
        return ["eflags", "cs", "ss", "ds", "es", "fs", "gs"]

    # WARNING reset expects the last two registers to be sp and ip. backup expects the last register to be ip
    @property
    def registers(self):
        if context.bits == 32:
            return ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]
        elif context.bits == 64:
            return ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp", "rip"]
        else:
            log.critical("Bits not known")

    # Making ax accessible will probably be faster that having to write 
    @property
    def minor_registers(self):
        _minor_registers = ["ax", "al", "ah",
        "bx", " bh", "bl",
        "cx", " ch", "cl",
        "dx", " dh", "dl",
        "si", "sil",
        "di", "dil",
        "sp", "spl",
        "bp", "bpl"]
        if context.bits == 64:
            _minor_registers += ["eax", "ebx", "ecx", "edx", "esi", "edi",
            "r8d", "r8w", "r8l",
            "r9d", "r9w", "r9l",
            "r10d", "r10w", "r10l",
            "r11d", "r11w", "r11l",            
            "r12d", "r12w", "r12l",
            "r13d", "r13w", "r13l",
            "r14d", "r14w", "r14l",
            "r15d", "r15w", "r15l"]
        return _minor_registers

    @property
    def next_inst(self):
        inst = next(self.disassemble(self.instruction_pointer, 16)) #15 bytes is the maximum size for an instruction in x64
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        return inst

    # May be usefull for Inner_Debugger
    def disassemble(self, address, size):
        if self._capstone is None:
            self._capstone = Cs(CS_ARCH_X86, context.bytes)
        return self._capstone.disasm(self.read(address, size), address)

    ########################## Generic references ##########################

    @property
    def return_value(self):
        if context.bits == 32:
            return self.eax
        else:
            return self.rax

    @return_value.setter
    def return_value(self, value):
        if context.bits == 32:
            self.eax = value
        else:
            self.rax = value

    @property
    def stack_pointer(self):
        if context.bits == 32:
            return self.esp
        else:
            return self.rsp

    # issue: setting $sp is not allowed when other stack frames are selected... https://sourceware.org/gdb/onlinedocs/gdb/Registers.html [04/03/23]
    @stack_pointer.setter
    def stack_pointer(self, value):
        # May move this line to push and pop if someone can argue a good reason to.
        while self.stack_pointer != value:
            log.debug("forcing last frame")
            self.execute("select-frame 0") # I don't know what frames are for, but if you need to push or pop you just want to work on the current frame i guess ? [04/03/23]
            
            if context.bits == 32:
                self.esp = value
            else:
                self.rsp = value

    @property
    def base_pointer(self):
        if context.bits == 32:
            return self.ebp
        else:
            return self.rbp
    
    @base_pointer.setter
    def base_pointer(self, value):
        if context.bits == 32:
            self.ebp = value
        else:
            self.rbp = value

    # Prevent null pointers
    @property
    def instruction_pointer(self):
        ans = 0
        while ans == 0:
            # what about self.gdb.newest_frame().pc() ? [28/04/23]
            if context.bits == 32:
                ans = self.eip
            else:
                ans = self.rip
            # log
            if ans == 0:
                log.debug("null pointer in ip ! retrying...")
        return ans

    @instruction_pointer.setter
    def instruction_pointer(self, value):
        if context.bits == 32:
            self.eip = value
        else:
            self.rip = value

    @property
    def __saved_ip(self):
        return self.gdb.newest_frame().older().pc()

        ## rip = 0x7ffff7fe45b8 in _dl_start_final (./elf/rtld.c:507); saved rip = 0x7ffff7fe32b8
        #data = self.execute("info frame 0").split("\n")
        #print(data)
        #for line in data:
        #    if " saved " in line and "ip = " in line:
        #        ip = line.split("saved ")[-1].split("= ")[-1]
        #        if "<" in ip:
        #            return 0
        #        return int(ip, 16)

    ########################## FORKS ##########################
    # TODO find a better name [28/02/23]
    # TODO make inferior and n the same parameter ? [04/03/23]

    # Call shellcode has problems: https://sourceware.org/gdb/onlinedocs/gdb/Registers.html. Can't push rip
    # Warn that the child will still be in the middle of the fork [26/04/23]
    def split_child(self, *, pid = None, inferior=None, n=None):
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

        log.debug(f"splitting inferior {inferior}")
        n = inferior.num
        pid = inferior.pid
        old_n = self.switch_inferior(n)
        ip = self.instruction_pointer
        backup = self.inject_sleep(ip, inferior.num)

        # For some reason it may happend that we receive a SIGINT on the first step. This would kill the process if I detached now [29/04/23] (Always that same bug)
        self.step() 
        
        self.switch_inferior(old_n)
        log.debug("detaching from child")
        self.execute(f"detach inferiors {n}")
        child = Debugger(pid, binary=self.elf.path)
        log.debug("new debugger opened")
        child.write(ip, backup)
        log.debug("shellcode patched")
        child.jump(ip)
        return child  
    
    # entrambi dovrebbero essere interrotti, il parent alla fine di fork, il child a metà
    # Ho deciso di lasciare correre il parent. Te la gestisci te se vuoi mettere un breakpoint mettilo dopo
    # I just discovered "gdb.events.new_inferior"... I can take the pid from event.inferior.pid, but can I do more ?
    def set_split_on_fork(self, off=False, c=False, keep_breakpoints=False, interrupt=False):
        """
        split out a new debugging session for the child process every time you hit a fork

        Arguments:
            off: disable feature
            interrupt: stop parent when forking

        """
        if off:
            self.execute("set detach-on-fork on")
            #if self.symbols["fork"] in self.breakpoints:
            #    self.breakpoints["fork"].enabled = False
            #    del self.breakpoints["fork"]

            # Will break if not set on before
            self.gdb.events.new_inferior.disconnect(self.inferior_handler)
                
        else:
            self.execute("set detach-on-fork off")

            # The interrupt may give me problems with continue_until
            def fork_handler(event):
                inferior = event.inferior
                pid = inferior.pid        
                #self.to_split.put(pid)
                def split(inferior):
                    log.info(f"splitting child: {inferior.pid}")
                    stopped = False
                    if self.running:
                        self.interrupt()
                        # How to handle the case where we interrupt at the address of a temporary breakpoint ? [05/05/23]
                        #if self.instruction_pointer not in self.breakpoints and self.instruction_pointer != self.last_breakpoint_deleted:
                        if self._stop_reason != "BREAKPOINT":
                            stopped = True
                    self.children[pid] = self.split_child(inferior=inferior)
                    # Should not continue if I reached the breakpoint before the split
                    if not interrupt and stopped:
                        self.execute("c")
                        # What is the difference ? [05/O5/23 20:30]
                        #self.priority -= 1 # Can i do it this way to keep the priority correct ? [05/05/23 20:00]
                        #self.cont(wait=False)
                    # Put it at the end to avoid any race condition [05/05/23 2O:30]
                    self.split.put(pid)
                ## Non puoi eseguire azioni dentro ad un handler degli eventi quindi lancio in un thread a parte
                context.Thread(target=split, args = (inferior,)).start()

            self.gdb.events.new_inferior.connect(fork_handler)
            
            return self

    # Taken from GEF to handle slave interuption
    @property
    def _stop_reason(self) -> str:
        res = self.gdb.execute("info program", to_string=True).splitlines()
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

    @property
    def _details_breakpoint_stopped(self) -> str:
        """
        If the program stopped at a breakpoint, return the id of that breakpoint
        This can be used to identify caught syscall
        """
        for line in res:
            line = line.strip()
            #It stopped at breakpoint 2.
            if line.startswith("It stopped at breakpoint "):
                return line.split(".")[0][len("It stopped at breakpoint "):]
        else:
            log.warn("process didn't stop for a breakpoint")

    # Non dovrebbe gestire gli int3 piuttosto ? Un set event if not in breakpoints execute code ? [06/03/23]
    # Boh, tanto si ferma e basta... 
    # Però si, dovrebbe dirlo al master
    # Il problema è che spesso si ferma prima di sapere chi sia il master
    # Maybe add a callback for SIGSTOP... [25/03/23]
    # TODO set in __stop_handler an action to sent to the master why we stopped [27/04/23]
    def emulate_ptrace_slave(self, master = None, *, off = False, wait_fun="waitpid"):
        """
        Emulate calls to ptrace as a slave process [and one day send back informations to the master]

        Arguments:
            off: Stop emulating ptrace
            master: pointer to the master if you need to send back informations on the interruptions. Can be set later writing self.master
            wait_fun: symbol or address of the function used to wait for the master. Default: "waitpid"
        """
        if master is not None:
            self.master = master

        if not off:
            log.debug(f"emulating slave proc {self.pid}")
            # patch waitpid
            # Attento che funziona solo su 64 bit, ma è un test per capire da dove appare il sigabort [08/03/23]
            self.write(self.symbols[wait_fun], RET)
            # set breakpoint
            # You can not wait inside the breakpoint otherwise gdb gets blocked before the child can be split away 
            def callback(dbg):
                log.debug("slave waiting for instructions")

                # Do it for int3 instead
                #if dbg.master is not None:
                #    dbg.master.slave_has_stopped.set()

                def thread(dbg):
                    log.critical("slave thread stopped")
                    dbg.wait_master()
                    dbg.__clear_stop("thread slave")
                    log.critical("slave thread can continue")
                    #log.debug("I won't run dbg.c(), see if you still get the breakpoint hit twice")
                    dbg.exit_broken_function()
                    #dbg.c() # There are some strange things happening here. Without this continue I need 2 ni to execute the ret since the first just restore the thread in gdb (Try without GEF)
                # I decided to avoid breaking. Is there a reason to do otherwise ? You are not blocking the master and the slave has nothing else to do
                context.Thread(target=thread, args=(dbg,)).start()
                return True
                #return False 
            # WHY IS THE BREAK HIT TWICE ??? [07/03/23]
            self.b(self.symbols[wait_fun], callback = callback)

            self.write(self.symbols["ptrace"], RET)
            def ptrace_callback(dbg):
                ptrace_command = dbg.args[0]
                assert ptrace_command == constants.PTRACE_TRACEME
                dbg.PTRACE_TRACEME()
                # The only reason to call this function is to be sure it will stop, right ?
                # Nope... [24/03/23]
                return False

            self.b(self.symbols["ptrace"], legacy_callback = ptrace_callback)

        else:
            log.debug("stop emulating slave. Removing waitpid and ptrace breakpoints")
            self.delete_breakpoint(self.symbols[wait_fun])
            self.delete_breakpoint(self.symbols["ptrace"])

        return self
    
    def emulate_ptrace_master(self, slave = None, *, wait_fun = "waitpid", stop_at_waitpid = True):
        """
        Tell the debugger to handle calls to ptrace
        
        Arguments:
            slave: pointer to a debugger of the tracee. If not set will look for the corresponding debugger in self.children
            wait_fun: function used to wait for the tracee
            stop_at_waitpid: flag to set a breakpoint on the wait function (Default True to help manual debugging)
        """
        if slave is None:
            log.debug(f"emulating master {self.pid}. You haven't set the slave yet")
        else:
            log.debug(f"emulating master {self.pid} over {slave.pid}")
            self.slaves[slave.pid] = slave
        # patch ptrace
        self.write(self.symbols["ptrace"], RET)

        # Waiting for pwntools update
        if context.arch == "amd64":
            constants.PTRACE_GETREGS = 12
            constants.PTRACE_SETREGS = 13
            constants.PTRACE_SETOPTIONS = 0x4200 # really ??
            constants.PTRACE_O_EXITKILL = 0x00100000
            constants.PTRACE_O_SUSPEND_SECCOMP = 0x00200000
            constants.PTRACE_O_MASK     = 0x003000ff


        ptrace_dict = {constants.PTRACE_POKEDATA: self.PTRACE_POKETEXT,
            constants.PTRACE_POKETEXT: self.PTRACE_POKETEXT, 
            constants.PTRACE_PEEKTEXT: self.PTRACE_PEEKTEXT, 
            constants.PTRACE_PEEKDATA: self.PTRACE_PEEKTEXT, 
            constants.PTRACE_GETREGS: self.PTRACE_GETREGS, 
            constants.PTRACE_SETREGS: self.PTRACE_SETREGS,
            constants.PTRACE_ATTACH: self.PTRACE_ATTACH,
            constants.PTRACE_CONT: self.PTRACE_CONT,
            constants.PTRACE_DETACH: self.PTRACE_DETACH,
            constants.PTRACE_SETOPTIONS: self.PTRACE_SETOPTIONS,
            constants.PTRACE_SINGLESTEP: self.PTRACE_SINGLESTEP,}

        def ptrace_callback(dbg):
            ptrace_command = dbg.args[0]
            pid = dbg.args[1]
            arg1 = dbg.args[2]
            arg2 = dbg.args[3]
            if pid in dbg.slaves:
                slave = dbg.slaves[pid]
            elif pid in dbg.children:
                assert ptrace_command in [constants.PTRACE_ATTACH, constants.PTRACE_SEIZE]
                slave = dbg.children[pid]
                log.debug(f"the slave for {self.pid} will be {pid}")
                dbg.slaves[pid]
            else:
                raise Exception(f"master tried to trace {pid}, which isn't known as a child nor a slave")

            log.debug(f"ptrace {pid} -> {ptrace_command}: ({hex(arg1)}, {hex(arg2)})")
            action = ptrace_dict[ptrace_command] # The slave can be a parent

            # Why am I using a context.Thread since I can't use dbg.next() ?
            #context.Thread(target = action, args = (arg1, arg2), kwargs = {"slave": slave}).start() # Magari fa problemi di sincronizzazione con le wait
            action(arg1, arg2, slave=slave)

            # The problem with return False is that if I walk over the breakpoint manualy I loose control of the debugger because the program continues
            return False

        # Legacy_callback so that the program does run off if we step over the breakpoint manualy
        # Is this still needed ? [05/05/23] # Yes, you have to patch gdb's implementation of nexti and finish first
        self.b(self.symbols["ptrace"], legacy_callback=ptrace_callback)

        # Set breakpoint for wait_attach
        # Not in attach because TRACEME doesn't call attach
        # gdb has a bug, [#0] Id 1, Name: "traps_withSymbo", stopped 0x448ac0 in waitpid (), reason: SIGINT. even without a breakpoint
        self.write(self.symbols[wait_fun], RET)
        # You have to choose between return False and temporary for now...
        def callback_wait(dbg):
            dbg.return_value = dbg.args[0] #slave.pid # Not really, but just != 0
            status_pointer = dbg.args[1]
            # Should be set in relation to the slave... But for now rip
            wait_signal = self._wait_signal if self._wait_signal is not None else 0x13
            self._wait_signal = None
            dbg.write(status_pointer, p32(wait_signal * 0x100 + 0x7f)) # Random status that currently works. For sigabort it is \x13\x7f \x13 is SIGSTOP \x7f means that the process has stopped
            if stop_at_waitpid:
                return True
            else:
                return False

        self.b(self.symbols[wait_fun], legacy_callback = callback_wait)

        return self

    ########################## PTRACE EMULATION ##########################
    def PTRACE_ATTACH(self, pid, _, *, slave):
        log.debug(f"pretending to attach to process {pid}")
        slave.master = self
        # I don't think it is needed to stop the child
        #slave.interrupt() ?
        self.slave_has_stopped.set()
        self.return_value = 0

    # Copied from attach for now
    def PTRACE_SEIZE(self, pid, options, *, slave):
        raise Exception("not implemented yet")
        log.debug(f"pretending to seize process {slave.pid}")
        slave.master = self
        self.PTRACE_SETOPTIONS(pid, options, slave=self.slave)
        # I don't think it is needed to stop the child
        #slave.interrupt() ?
        self.slave_has_stopped.set()
        self.return_value = 0

    # Only function called by the slave
    def PTRACE_TRACEME(self):
        log.debug("slave wants to be traced")
        self.return_value = 0
        if context.bits == 64:
            self.r8 = -1
        # TODO: Wait for a master
        if self.pid not in self.master.slaves:
            log.debug(f"setting {self.pid} as slave for {self.master.pid}")
            self.master.slaves[self.pid] = self
        self.master.slave_has_stopped.set()

    def PTRACE_CONT(self, _, __, *, slave):
        print("slave can continue !")
        slave.master_wants_you_to_continue.set()

    def PTRACE_DETACH(self, _, __, *, slave):
        log.debug(f"ptrace detached from {slave.pid}")
        slave.master_wants_you_to_continue.set()
        slave.master = None

    def PTRACE_POKETEXT(self, address, data, *, slave):
        log.debug(f"poking {hex(data)} into process {slave.pid} at address {hex(address)}")
        slave.write(address, pack(data))
        self.return_value = 0 # right ?

    def PTRACE_PEEKTEXT(self, address, _, *, slave):
        data = unpack(slave.read(address, context.bytes))
        log.debug(f"peeking {hex(data)} from process {slave.pid} at address {hex(address)}")
        self.return_value = data

    def PTRACE_GETREGS(self, _, pointer_registers, *, slave):
        registers = user_regs_struct()
        for register in slave.registers:
            value = getattr(slave, register)
            log.debug(f"reading child's register {register}: {hex(value)}")
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            setattr(registers, register, value)
        self.write(pointer_registers, registers.get())
        self.return_value = 0 # right ?
    
    def PTRACE_SETREGS(self, _, pointer_registers, *, slave):
        log.warn_once("funziona solo per registri non triviali")
        registers = user_regs_struct()
        registers.set(self.read(pointer_registers, registers.size))
        for register in slave.registers:
            #if register in ["rip", "eip"]:
            #    register = "ip"
            #elif register in ["rsp", "esp"]:
            #    register = "sp"
            assert register in registers.registers
            value = getattr(registers, register)
            log.debug(f"setting child's register {register}: {hex(value)}")
            setattr(slave, register, value)
        self.return_value = 0 

    def PTRACE_SETOPTIONS(self, _, options, *, slave):
        log.debug(hex(options))
        if options & constants.PTRACE_O_EXITKILL:
            options -= constants.PTRACE_O_EXITKILL
            log.debug("Option EXITKILL set")
            #log.debug("They want to kill the slave if you remove the master")
            log.debug(hex(options))
        
        if options & constants.PTRACE_O_TRACESYSGOOD:
            options -= constants.PTRACE_O_TRACESYSGOOD
            log.debug("Option TRACESYSGOOD set")
            #log.debug("")
            log.debug(hex(options))

        if options != 0:
            raise(f"{hex(options)}: Not implemented yet")

        self.return_value = 0

    def PTRACE_SINGLESTEP(self, _, __, *, slave):
        log.debug("ptrace single step")
        slave.step()
        self._wait_signal = 0x5 
        self.return_value = 0

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
            inferior = self._inferior
        
        old_inferior = self.switch_inferior(inferior)

        if address is None:
            log.debug("allocating memory for shellcode")
            address = self.alloc(len(shellcode))

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
        # I don't want the libc syscall, but a simple \x0f\x05\xc3
        elif "_syscall" in self.symbols:
            # Context.arch handles constants.SYS ! I love pwntools <3
            log.debug("calling sys_mprotect. Should be 0xa on 64bit arch")
            log .debug(f"{context.arch=}")
            self.restore_arch()
            log .debug(f"{context.arch=}")
            ans = self.syscall(constants.SYS_mprotect.real, [address & 0xfffffffffffff000, size, constants.PROT_EXEC | constants.PROT_READ | constants.PROT_WRITE])
        else:
            log.critical("please, I at least need an address to a syscall ; ret gadget in symbols[\"_syscall\"]")
            
        # parse ans == 0 ?
        
        self.switch_inferior(old_inferior)

        return address

    def inject_sleep(self, address, inferior=None):
        """
        Inject a shellcode that stoppes the execution at a specific address

        Is meant to be used in the binary code, so it expects an address and returns the bytes that have been overwriten
        """
        #test:
        #jmp test
        # I put a nop to let step(force=True) work in case [29/04/23]
        shellcode = b"\x90\xeb\xfe"
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
    #    log.debug(f"looking for attr {name}")
    #    #getattr is only called when an attribute is NOT found in the instance's dictionary
    #    #I may wan't to use this instead of the 300 lines of registers, but have to check how to handle the setter
        if name in ["p", "elf", "gdb"]: #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self.registers in __setattr__
            return False
        if name in self.special_registers + self.registers + self.minor_registers:
            res = int(self.gdb.parse_and_eval(f"${name}")) % 2**context.bits
            return res
        elif self.p and hasattr(self.p, name):
            return getattr(self.p, name)
        # May want to also expose in case you want to access something like inferiors() 
        elif self.gdb and hasattr(self.gdb, name):
            return getattr(self.gdb, name)
        else:
            # Get better errors when can't resolve properties
            self.__getattribute__(name)

    def __setattr__(self, name, value):
        if self.elf and name in self.special_registers + self.registers + self.minor_registers:
            self.restore_arch()
            self.execute(f"set ${name.lower()} = {value % 2**context.bits}")
        else:
            super().__setattr__(name, value)
