from pwn import *
from os import kill
from time import sleep
from functools import partial
from capstone import Cs, CS_ARCH_X86
from threading import Thread, Event
from queue import Queue
from gdb_plus.utils import Arguments, user_regs_struct, FakeELF, context

RET = b"\xc3"

#WARNING pwndbg breaks the API so you have to disable it. I advise to use GEF

#You don't have to interrupt the process to read and overwrite the memory. Only to access the registers or set breakpoints

class Debugger:
    # If possible patch the rpath (spwn and pwninit do it automaticaly) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target: [int, process, str, list], env={}, aslr:bool=True, script:str="", from_start:bool=True, binary:str=None, debug_from: int=None, timeout: int=10):
        log.debug(f"debugging {target if binary is None else binary} using arch: {context.arch} [{context.bits}bits]")

        self._capstone = None #To decompile assembly for next_inst
        self._auxiliary_vector = None #only used to locate the canary
        self._base_libc = None
        self._base_elf = None
        self._canary = None
        self._args = None
        self.closed = False
        self.pid = None # Taken out to be able to send kill() even if we don't use a process
        #self.inferior = None #inferior to easily access memory # Obsolete [03/03/23]
        self._inferior = 1 # Used to switch between inferiors [03/03/23]
        self.children = {} # Maybe put {self.pid: self} as first one
        self.slaves = {} # to emulate ptrace
        self.master = None
        # Maybe use a queue. Maybe even share the same one between slave and master so you don't need the pid. [26/03/23]
        self._wait_signal = None
        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        self.breakpoints = {} #Save all non temporary breakpoints for easy access # The fact that they can't be temporary is used by the callback [21/03/23]
        # How do you remove them with temporary breakpoints ? [19/03/23]
        self.real_callbacks = {} # Functions to execute AFTER the breakpoint. Should be more powerfull [03/03/23]
        self.debugging = None #I want to keep the exploits as clean as possible, so I'm gonna try to handle everything so I can still inherit the class when attacking in remote without having to worry about calls to breakpoint or execute
        #gdb.debug() was rulled out previously due to two bugs with older version of gdbserver in ubuntu 20.04
        #1) gdbserver crashes trying to locate the canary (at least with 32 bit binaries) -> patched in gdbserver 11.0.50 (working in ubuntu 22.04)
        #2) LD_PRELOAD uses the library for gdbserver and not the process -> solved in ubuntu 22.04 too
        
        if args.REMOTE or context.noptrace:
            self.debugging = False
        else:
            self.debugging = True

        # I want to set the right binary in the case where you use target = [loader, elf]
        if binary is None:
            if type(target) is int:
                raise Ecxeption("I need a binary to work !") # I need a quickfix. Who would debug without the binary ? [03/03/23]
                # Take bits from context... [03/03/23]
                log.info_once("You attached to a process from the pid but didn't pass a binary. Use binary=<path_to_elf> if possible")
                #self.inferior = self.gdb.inferiors()[0]
                bits = context.bits #64 if self.gdb.inferiors()[0].architecture().name().endswith("64") else 32 # Faster, I just hope it always works
                #bits = 64 if next(self.inferior.architecture().registers()).name == 'rax' else 32
                self.elf = FakeELF(bits)

            elif type(target) is process:
                self.elf = target.elf

            elif type(target) is str:
                self.elf = ELF(target)

            elif type(target) is list:
                log.warning("Which one is the binary you want to debug ? I guess the last, but please use binary=<elf_path>")
                self.elf = ELF(target[-1])

            else:
                raise "what type is target ???"

        else:
            self.elf = ELF(binary)

        if type(target) is int:
            # How can I pass the elf if I just use the pid ?
            self.pid = target
            _, self.gdb = gdb.attach(target, gdbscript=script, api=True)

        elif type(target) is process:
            self.p = target
            _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True) # will raise TypeError if noptrace, but why pass a process if you don't want to debug it ?

        elif args.REMOTE:
            self.elf = ELF(target, checksec=False)
        #Pwntools allows you to use NOPTRACE if you wan't to skip the attach so I keep the logic here

        elif context.noptrace:
            self.p = process(target, env=env, aslr=aslr)
        # I commented this part because I'm not sure how to handle the absense of a process for some features like access to registers

        elif from_start:
            self.p = gdb.debug(target, env=env, aslr=aslr, gdbscript=script, api=True)
            self.gdb = self.p.gdb
            
        else:
            self.p = process(target, env=env, aslr=aslr)
            _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)

        # I ended up using inferior to read and write the memory even with a process
        #if hasattr(self, "gdb"):
        #if self.debugging: # Dovrebbe essere equivalente, ma almeno non muore
        #    self.inferior = self.gdb.inferiors()[0]
        if self.p:
            self.pid = self.p.pid
            # We may have problems relying on context... Stay with elf [03/03/23]
        
        # pwntools symbols duplicate every entry in the plt and the got. This breaks my version of symbols because they have the same name as the libc [25/03/23]
        # This may break not stripped staticaly linked binaries, just wait for the libc to be loaded and those symbols will be overshadowed [25/03/23]
        # Let's still do it for dynamically linked binaries [04/04/23]
        if 
        for symbol_name in self.elf.symbols:
            if symbol_name.startswith("plt.") or symbol_name.startswith("got.") and (name := symbol_name[4:]) in self.elf.symbols:
                del self.elf.symbols[name]

        self.restore_arch()
        
        if self.debugging:
            self.elf.address = self.get_base_elf()


            # Start debugging from a specific address. Wait timeout seconds for the program to reach that address. Is blocking so you may need to use Thread() in some cases
            if debug_from is not None:  
                backup = self.inject_sleep(debug_from)
                self.detach()
                sleep(timeout)
                _, self.gdb = gdb.attach(self.p.pid, gdbscript=script, api=True) # P is gdbserver...
                self.write(debug_from, backup)
                #self.jump(debug_from) # Can't wait before gdb.myStopped is created and can't create it before because I will overwrite gdb
                self.b(debug_from, temporary=True)
                self.jump(debug_from, stop=False)

            # I create a new one because I can't disconnect their callback
            # I could do like with libdebug a custom event with priority_wait to let the user put a continue and wait even if callbacks have wait inside [04/04/23]
            self.gdb.myStopped = Event()


            # It is possible to have step() in a callback and execute the following callback before finishing the first one, so why so many problems with finish ? [25/03/23]
            #In [12]: [DEBUG] trying real_callback for 0x555555557e93
            #[DEBUG] stopped has been cleared by step
            #[DEBUG] trying real_callback for 0x555555557e95
            #[DEBUG] setting stopped in 0x555555557e95
            #[DEBUG] stopped has been cleared by wait


            # If the real_callback has to wait this can not work...
            # Yes it can work, but how can I handle it in such a way that my script doesn't resolve the wait instead of the callback ? [19/03/23]
            # Currently you can't wait in your script and in the callback at the same time. Use a custom event if you really have to. [19/03/23]
            # Other problem, dbg.c() doesn't always work in the handler. But Thread(target=lambda: dbg.c()).start() does... [20/03/23]
            def stop_handler(event):
                if (ip := self.parse_for_breakpoint(self.instruction_pointer)) in self.real_callbacks:
                    log.debug(f"trying real_callback for {hex(self.instruction_pointer)}")
                    # TODO, it may be interesting to have the option to put an array of breakpoints for recursive functions [21/03/23]
                    # something like
                    #if type(self.real_callbacks[self.instruction_pointer]) is list:
                    #   callback =  self.real_callbacks[ip].pop()
                    #   if len(self.real_callbacks[ip]) == 0:
                    #       del self.real_callbacks[ip]
                    #else:
                    callback = self.real_callbacks[ip]
                    # If the breakpoint was temporary remove the callback. But keep this code in the if not list
                    if ip not in self.breakpoints:
                        log.debug("deleting callback because breakpoint was temporary")
                        del self.real_callbacks[ip]
                    expect_to_wait = callback(self)
                    if expect_to_wait is None or expect_to_wait:
                        self._set_stop()
                    else:
                        Thread(target=lambda: self.c()).start()
                else:
                    # This is still not perfect. If the callback does self.next() but the script is waiting what will happen ?
                    # The script will catch the event before :< [19/03/23]
                    log.debug(f"no real_callback on {hex(self.instruction_pointer)}")
                    self._set_stop() # Altready handled by pwntools ? [03/03/23] YES ! create a new event instead [19/03/23]

            # Now I can wait for an exit [03/03/23]
            def exit_handler(event):
                log.debug("setting stop because process exited")
                self.gdb.myStopped.set()
                self.closed = True

            # Events are executed in the order they are set waiting for the previous one to start, but still blocking wait() [04/03/23]
            # Unfortunately you can't use it to run gdb+ commands... Is it just because they depend on wait() ? [04/03/23]
            # I can use Thread.start() in the handler. Just be carefull if the script wants to do other things after waiting [04/03/23]
            # Non è che vengono eseguiti sia dal parent che dal child, vero... Non dovrebbe, spero sia per quando la sessione gdb che si ferma, non i processi [04/03/23]
            # Tested and we can even put dbg.c() in the callbacks now <3 [19/03/23]
            self.gdb.events.stop.connect(stop_handler)
            self.gdb.events.exited.connect(exit_handler)

            # Manually set by split_child
            self.gdb.split = Queue()

            # Ptrace_cont
            self.gdb.master_wants_you_to_continue = Event()
            self.gdb.slave_has_stopped = Event()

            # This is the wait I should have done after the jump. I can't bacause gdb changes so gdb.myStopped wouldn't exist anymore for the wait [02/04/23]
            if debug_from is not None:
                self.wait()

    # Because pwntools isn't perfect
    def restore_arch(self):
        if context.arch != self.elf.arch:
            log.debug("wrong context ! Updating...")
        context.arch = self.elf.arch
        context.bits = self.elf.bits

    # Use as : dbg = Debugger("file").remote(IP, PORT)
    def remote(self, host: str, port: int):
        if args.REMOTE:
            self.p = remote(host, port)
        return self

    def detach(self, quit = True):
        try:
            self.execute("detach")
        except:
            log.debug("process already stopped")
        try:
            self.execute("quit") # Doesn't allways work if after interacting manualy
        except EOFError:
            log.debug("GDB successfully closed")

    def close(self):
        self.detach()
        # Can't close the process if I just attached to the pid
        if self.p:
            self.p.close()

    def execute(self, code: str):
        if self.debugging:
            return self.gdb.execute(code, to_string=True)
        else:
            log.warn_once("Debug is off, commands won't be executed")

    # I want a function to restart the process without closing and opening a new one
    def reset(self):
        # TODO
        pass
            
    ########################## CONTROL FLOW ##########################

    #I don't like continue_and_wait, continue_nowait. I'm not even sure I want to leave the option to have a wait in the fuction. Just do self.c() self.wait() and it will be easier to debug your exploit
    def c(self, wait=False, force_step=False):
        self.clear_stop("continue")
        if force_step:
            self.exit_broken_function()
        self.execute("continue")
        if wait:
            self.wait()

    cont = c

    # You have to remember you can not send SOME commands to gdb while the process is running
    # You don't have to interrupt the process to set breakpoints (except if you want callbacks) or access and overwrite the memory. Only work with the registers or access the canary for the first time (this last part could be improved)
    # Apparently now you have to for any breakpoint...
    # I have to introduce back the timeouts. I just modify the implementation of gdb.wait to do so [26/02/23]
    # TODO test if the old implementation can detect that the child has died [26/02/23]
    # Warning, risky bug: self.gdb.myStopped doesn't get cleared if you do `dbg.c(); sleep(1); dbg.finish()` and the next wait will return immediatly [03/03/23]
    def wait(self, timeout=None):
        self.gdb.myStopped.wait(timeout=timeout)
        self.clear_stop("wait")

    def clear_stop(self, name="someone", /):
        if self.gdb.myStopped.is_set():
            log.debug(f"stopped has been cleared by {name}")
            self.gdb.myStopped.clear()
        while self.gdb.myStopped.is_set():
            log.debug("something isn't right with stopped")
            self.gdb.myStopped.clear()

    def _set_stop(self):
        log.debug(f"setting stopped in {hex(self.instruction_pointer)}")
        self.gdb.myStopped.set()

    #def wait_fork(self):
    #    self.gdb.forked.wait()
    #    self.gdb.forked.clear()

    # TODO: return child pid [06/03/23]
    def wait_split(self):
        pid = self.gdb.split.get()
        return pid

    def advanced_continue_and_wait_split(self):
        self.b(self.symbols["fork"])
        self.c(wait=True)
        assert self.instruction_pointer == self.symbols["fork"], "Are you sure the libc was loaded before ? Check unexpected breakpoints otherwise"
        self.finish()
        return self.wait_split()


    # For now is handled by simple wait [06/03/23]
    #def wait_exit(self):

    def wait_master(self):
        self.gdb.master_wants_you_to_continue.wait()
        self.gdb.master_wants_you_to_continue.clear()

    # Should handle multiple slaves ?
    def wait_slave(self):
        self.gdb.slave_has_stopped.wait()
        self.gdb.slave_has_stopped.clear()

    
    #temporarely interrupt the execution of our process to get back control of gdb (equivalent of a manual ctrl+C)
    #don't worry about the "kill"
    def interrupt(self, wait=True, timeout=0.2):
        """
        Stop the process as you would with ctrl+C in gdb

        Parameters
        ----------
        wait : bool, optional
            By default you should wait for the process to stop, but if you aren't sure you can try setting wait to False
        timeout : floot, optional
            The timeout should be the time needed for gdb to interrupt the process. Too small your program may crash, too big and you are waisting time. Idealy you will never change it.
        """
        if not self.debugging:
            return
        #self.execute("interrupt") #pwntools uses this command, but I don't because it may not work if the continue command has been sent manualy in gdb
        # I won't use kill untill I take into consideration WHICH inferior i'm debugging (so which pid I should use) [04/03/23]
        # But pwntools cant handle "interrupt"... [07/03/23]
        kill(self.inferiors[self._inferior].pid, signal.SIGINT)
        if wait: # Set wait to false if you are not sure that the process is actualy running
            self.wait()
        else:
            # This is a case where a timeout in wait whould be usefull... I may consider re_intruducing it
            # If interrupt is called while the process isn't running wait() will never return so I don't want to call it if I'm not sure
            # but it still takes some time to interrupt the process if it si running so I HAVE to wait some time just in case.
            # (There is no way of reliably knowing if the process is running. Even setting a flag on continue wouldn't work if the command is sent manualy from gdb
            sleep(timeout)

    manual = interrupt

    # Next may break again on the same address, but not step
    def step(self, repeat:int=1, *, force = True):
        self.clear_stop("step")
        for _ in range(repeat):
            # If I want to handle here the case where gdb updates the stack_frame, but stays on the same address. Currently handled by "exit_broken_function" [23/03/23]
            old_address = self.instruction_pointer
            self.execute("si")
            self.wait()
            #if force:
            #    while old_address == self.instruction_pointer:
            #        log.debug("gdb step is still broken")
            #        self.execute("si")
            #        self.wait()

    #Finish a function with modifying code
    def step_until_address(self, address: int, callback=None, limit:int=10_000) -> bool:
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

    # May not want to wait if you are going over a functions that need user interaction
    def next(self, wait:bool=True, repeat:int=1):
        self.clear_stop("next")
        for _ in range(repeat):
            self.execute("ni")
            if wait:
                self.wait()

    # This one doesn't wait forever if we finish executing
    # Don't use repeat and no_wait toghether ... [06/03/23]
    # Not sure if repeat is so usefull... [21/03/23]
    # The callback is usefull if you have other breakpoints that will be hit before the function finishes so you can't just wait and run the code [21/03/23]
    def finish(self, *, wait:bool=True, repeat = 1, callback = None):
        self.clear_stop("finish")
        if callback is None:
            for _ in range(repeat):
                self.execute("finish")
                if wait:
                    self.wait()
        else:
            # I still use execute("finish") in the other case because I'm not sure return_address is always correct [21/03/23]
            log.warn_once("using finish with callback. This assumes that the function started with a push base_pointer. If it's not the case this won't work")
            return_address = unpack(self.read(self.base_pointer + context.bytes, context.bytes))
            self.b(return_address, real_callback=callback, temporary = True)
            self.c()

    def parse_for_breakpoint(self, address: [int, str]) -> str:
        """
        return the corresponding key used to save breakpoints for the given address
        """
        if type(address) is int:
            if address < 0x010000:
                address += self.base_elf
            address = f"*{hex(address)}"

        return address

    #May want to put breakpoints relative to the libc too?
    # Sembra avere bisogno di interrompere il processo per TUTTI i breakpoint se lancio con gdb.debug invece che attach
    # I want to keep legacy breakpoints for the ones I set with the library because we must be hable to work manually when emulating ptrace [23/03/23]
    def b(self, address: [int, str], callback=None, legacy_callback=None, temporary=False):
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


        if type(address) is not int and callback is not None:
                # We could invert the symbol dict and use realcallbacks with function names too. But I'm afraid of breakpoints like "main+0x4"
                log.critical('can only use real callbacks with a pointer. Passing as legacy callback. This mean you can\'t set a temporary breakpoint with return False and can only use the callback to access the memory')
                legacy_callback = callback
                callback = None

        address = self.parse_for_breakpoint(address)

        if callback is not None:
            log.debug("setting real callback")
            self.real_callbacks[address] = callback

        log.debug(f"putting breakpoint in {address}")

        
        # Not needed now that I use real_callbacks
        if legacy_callback is not None:
            # I don't know yet how to handle the conn if I don't go through self.gdb.Breakpoint so I create the class here :(
            log.warn_once("if your callbacks crash you may not notice it and you have to scroll a bit to find the error messages hidden in the gdb terminal")
            # For some reason this part require the process to be interrupted. I usualy do it from my exploit, but don't want to force everyone to do so
            #self.interrupt(wait=False) # Interrupt if running, but don't wait forever because I don't know if it is really running
            class MyBreakpoint(self.gdb.Breakpoint):
                def __init__(_self, address, callback, temporary=False):
                    super().__init__(address, temporary=temporary)
                    _self.callback = legacy_callback
                # WARNING IF A TEMPORARY BREAKPOINT DOESN'T STOP IT WON'T COUNT AS HIT AND STAY ACTIVE. May cause problems with the callback if you pass multiple times [26/02/23]
                # I should find an alternative to continue the execution if callback returns False, but I don't know how to do it yet [26/02/23]
                def stop(_self, *args):
                    _break = _self.callback(self) 
                    if _break is None:
                        return True
                    return _break
            res = MyBreakpoint(address, callback, temporary)

        else:
            res = self.gdb.Breakpoint(address, temporary=temporary)
        
        if not temporary:
            self.breakpoints[address] = res.server_breakpoint #[1:] to remove the '*' from the key if it's an adress, but leave intect if it's a function name
        return res
        
    breakpoint = b

    def delete_breakpoint(self, address: [int, str]) -> bool:
        self.clear_stop("delete breakpoint")
        address = self.parse_for_breakpoint(address)
        if address in self.breakpoints:
            self.breakpoints[address].delete()
            del self.breakpoints[address]

        if address in self.real_callbacks:
            del self.real_callbacks[address]
    
    def push(self, value: int):
        log.debug(f"pushing {pack(value)}")
        self.stack_pointer -= self.elf.bytes
        self.write(self.stack_pointer, pack(value))

    def pop(self) -> int:
        data = self.read(self.stack_pointer, self.elf.bytes)
        self.stack_pointer += self.elf.bytes
        return unpack(data)

    ########################## MEMORY ACCESS ##########################

    def read(self, address: int, size: int, inferior = None) -> bytes:

        if inferior == None:
            inferior = self._inferior
        
        #return self.p.readmem(address, size) # I don't want to relie on the process.
        return self.inferiors[inferior].read_memory(address, size).tobytes()

    # You don't allways wan't to write in the parents memory [03/03/23]
    def write(self, address: int, byte_array: bytes, *, inferior = None):

        if inferior == None:
            inferior = self._inferior
        
        #self.p.writemem(pointer, byte_array)
        log.debug(f"writing in inferior {inferior}")
        self.inferiors[inferior].write_memory(address, byte_array)
        

    @property
    def inferiors(self):
        return {inferior.num: inferior for inferior in self.gdb.inferiors()}
        #return (None,) + self.gdb.inferiors()

    # Useless ? I wanted it for the interrupt, but info inferior requires to be at a halt [07/03/23]
    @property
    def current_inferior(self):
        # trova ultimo id
        # prendi ultima riga non nulla
        data = self.execute("info inferior").split("\n") # shouldn't it be "info inferiorS" ?
        for line in data:
            line = line.split()
            if line[0] == "*":
                n = int(line[1])
                return self.inferiors[n]
    

    #Alloc and Dealloc instead of malloc and free because you may want to keep those names for function in your exploit

    # ??? [04/03/23]
    #gdb.error: The program being debugged was signaled while in a function called from GDB.
    #GDB remains in the frame where the signal was received.
    #To change this behavior use "set unwindonsignal on".
    #Evaluation of the expression containing the function
    #(__GI___libc_malloc) will be abandoned.
    #When the function is done executing, GDB will silently stop.


    def alloc(self, n: int, /, *, heap=True, inferior = None) -> int:
        """
        Allocate N bytes in the heap

        Parameters
        ----------
        n : int
            Size to allocate
        heap : bool, optional
            Set to False if you can't use the heap
            This way it will return a pointer to an area of the bss
        malloc : int, optional
            If you want to use malloc but the binary is staticaly linked and striped set malloc=ADDRESS_TO_MALLOC
        Returns
        -------
        pointer
        """

        if inferior == None:
            inferior = self._inferior
        
        if heap:
        # TODO handle switching between inferiors [03/03/23]
            old_inferior = self.switch_inferior(inferior)
            
            # calling with gdb should be safer, but if you don't have debug symbols you can't. [02/03/23]
            #if self.elf.statically_linked: # You may not have access to the symbols to call malloc if the binary is statically linked and stripped [02/03/23]
            #    log.debug("calling malloc from local address")
            #    pointer = hex(self.call(self.elf.symbols["malloc"], [n])) # Let's return a string to stay consistants [02/03/23]
            #else:
            #    pointer = self.execute(f"call (long) malloc({n})").split()[-1]
            return self.gdb_call("malloc", [n])

            self.switch_inferior(old_inferior)

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

            #if self.elf.statically_linked: # You may not have access to the symbols to call malloc if the binary is statically linked and stripped [02/03/23]
            #    self.call(self.symbols["free"], [pointer])
            #else:
            #    self.execute(f"call (void) free({hex(pointer)})")
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
    # I would want something that doesn't requires a process
    def get_base_libc(self):
        #if not hasattr(self, "libc"):
        # I think process has a libc = None by default
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
                    

    @property # I don't wan't to rely on self.elf.address which isin't set by default for PIE binaries
    def base_elf(self):
        # I don't want to set it myself either because I want to be able to test leak == dbg.base_elf during my exploit
        #if self.elf.address == 0:
        #    self.elf.address = self.get_base_elf()
        #return self.elf.address
        if self._base_elf is None:
            self._base_elf = self.get_base_elf()
        return self._base_elf

    # WARNING SOLO 3.9
    @property
    def symbols(self):
        #if hasattr(self, "libc"):
        if hasattr(self, "libc") and self.libc is not None: # If I attack to a pid I self.p doesn't have libc = None
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
            canary = self.read(canary_location, self.elf.bytes)
            self._canary = b"\x00"+canary[1:]
        return self._canary
        #taken from GEF
        #[+] The canary of process 17016 is at 0xff87768b, value is 0x2936a700
        #return int(self.execute("canary").split()[-1], 16)

    @property
    def registers(self):
        registers = ["eflags", "cs", "ss", "ds", "es", "fs", "gs"]
        if self.elf.bits == 32:
            registers += ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]
        elif self.elf.bits == 64:
            registers += ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rbp", "rsp", "rip"]
        else:
            log.critical("Bits not known")
        return registers

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
        if self.elf.bits == 64:
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
        if self._capstone is None:
            self._capstone = Cs(CS_ARCH_X86, self.elf.bytes)
        inst = next(self._capstone.disasm(self.read(self.instruction_pointer, 16), self.instruction_pointer)) #15 bytes is the maximum size for an instruction in x64
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        return inst

    ########################## Generic references ##########################

    @property
    def return_value(self):
        if self.elf.bits == 32:
            return self.eax
        else:
            return self.rax

    @return_value.setter
    def return_value(self, value):
        if self.elf.bits == 32:
            self.eax = value
        else:
            self.rax = value

    @property
    def stack_pointer(self):
        if self.elf.bits == 32:
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
            
            if self.elf.bits == 32:
                self.esp = value
            else:
                self.rsp = value


    @property
    def base_pointer(self):
        if self.elf.bits == 32:
            return self.ebp
        else:
            return self.rbp
    
    @base_pointer.setter
    def base_pointer(self, value):
        if self.elf.bits == 32:
            self.ebp = value
        else:
            self.rbp = value

    # Prevent null pointers
    @property
    def instruction_pointer(self):
        ans = 0
        #while ans == 0:
        if self.elf.bits == 32:
            ans = self.eip
        else:
            ans = self.rip
        ## log
        #if ans == 0:
        #    log.debug("null pointer in ip ! retrying...")
        return ans

    @instruction_pointer.setter
    def instruction_pointer(self, value):
        if self.elf.bits == 32:
            self.eip = value
        else:
            self.rip = value

    #Generic convertion to bytes for addresses
    # pwntools has pack() ! 
    def pbits(self, value):
        if self.elf.bits == 32:
            return p32(value) 
        else:
            return p64(value)

    ########################## FORKS ##########################
    # TODO find a beter name [28/02/23]
    # TODO by default find the last inferior [01/03/23 10:30] # Done
    # TODO make inferior and n the same parameter ? [04/03/23]

    # Call shellcode has problems: https://sourceware.org/gdb/onlinedocs/gdb/Registers.html. Can't push rip
    def split_child(self, n = None, /, inferior = None):
        """
        return a child as different debugging session

        You must have used `set detach-on-fork off` before the fork for this feature to work
        """
        log.warn_once("breakpoints won't be tranfered, you have to set them again")
        
        if inferior is None:
            if n is None:
                # trova ultimo id
                # prendi ultima riga non nulla
                data = self.execute("info inferior").split("\n")[-2].split()
                n = data[0]
                if n == "*":
                    n = data[1]
                n = int(n)
            pid = self.inferiors[n].pid

        else:   
            log.debug(f"spliting inferior {inferior}")
            pid = inferior.pid
            n = inferior.num
        
        log.debug(f"spliting inferior {n} with pid {pid}")
        # devi trovare un modo per farlo dormire
        
        # loop:
        # cmp rax, rax
        # je loop
        # ret
        # Why is the shellcode injected in the parent !? [04/03/23 11:30]
        self.switch_inferior(n)
        shellcode = b"\x48\x39\xC0\x74\xFB\xC3"
        log.debug("injecting shellcode")
        address_shellcode = self.inject_shellcode(shellcode)
        log.debug(f"calling shellcode at address {hex(address_shellcode)}")
        # save flag
        flags = self.eflags
        # TODO: understand why you get 0xa...
        self.return_value = 0
        self.push(self.instruction_pointer)
        self.jump(address_shellcode)
        self.switch_inferior(1)
        log.info("detach from child")
        self.execute(f"detach inferiors {n}")
        with context.local(arch = context.arch):
            child = Debugger(pid, binary=self.elf.path)
        log.debug("new debugger opened")
        child.write(address_shellcode + 3, b"\x75") # cambia je -> jne
        log.debug("shellcode patched")
        # 3 -> exit fake function, exit sub fork and exit fork
        child.finish(repeat=3)
        # restore flag
        self.eflags = flags
        self.gdb.split.put(pid)
        return child
    
    # entrambi dovrebbero essere interrotti, il parent alla fine di fork, il child a metà
    # Ho deciso di lasciare correre il parent. Te la gestisci te se vuoi mettere un breakpoint mettilo dopo
    # I just discovered "gdb.events.new_inferior"... I can take the pid from event.inferior.pid, but can I do more ?
    def set_split_on_fork(self, off=False, c=False, keep_breakpoints=False):
        """
        The function should split a new session every time you hit a fork
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

            def fork_handler(event):
                inferior = event.inferior
                # old tests [03/03/23]
                #self.interrupt()
                #sleep(3)
                #print(self.next_inst.toString()) # Questo funziona...
                #self.next()  # Questo però non può perchè sta runnando...
                pid = inferior.pid
                def split(inferior):
                    print(f"spliting child {inferior}")
                    self.interrupt(wait=False, timeout=0.1)
                    self.children[pid] = self.split_child(inferior=inferior)
                context.Thread(target=split, args = (inferior,)).start()

            self.gdb.events.new_inferior.connect(fork_handler)

            #def finish(dbg):
            #    log.debug("process forked")
            #    next_ip = unpack(self.read(self.stack_pointer, context.bytes))
            #    #
            #    def split(dbg):
            #        child = dbg.split_child()
            #        dbg.childen[child.pid] = child
            #        return False
            #    #
            #    dbg.b(next_ip, real_callback=split, temporary=True)
            #    return False
            ##
            #self.b(self.symbols["fork"], callback=finish)
            
            return self

    # Let's handle the bug on the overwriten waitpid
    def exit_broken_function(self):
        old_ip = self.instruction_pointer
        callback = None

        # Remove callback to avoid calling it twice (Nice, this wasn't possible with legacy_callbacks) (I'm not sure if we could simply disable a brakepoint for a turn)
        if self.parse_for_breakpoint(old_ip) in self.real_callbacks:
            callback = self.real_callbacks[self.parse_for_breakpoint(old_ip)]
            del self.real_callbacks[self.parse_for_breakpoint(old_ip)]

        self.step()

        while self.instruction_pointer == old_ip:
                log.debug("Bug ret still present")
                self.step()

        if callback is not None:
            self.real_callbacks[self.parse_for_breakpoint(old_ip)] = callback

    # Taken from GEF to handle slave interuption
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

    # Non dovrebbe gestire gli int3 piuttosto ? Un set event if not in breakpoints execute code ? [06/03/23]
    # Boh, tanto si ferma e basta... 
    # Però si, dovrebbe dirlo al master
    # Il problema è che spesso si ferma prima di sapere chi sia il master
    # Maybe add a callback for SIGSTOP... [25/03/23]
    def emulate_ptrace_slave(self, master = None, *, off = False, wait_fun="waitpid"):
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
                #    dbg.master.gdb.slave_has_stopped.set()

                def thread(dbg):
                    log.critical("slave thread stopped")
                    dbg.wait_master()
                    dbg.clear_stop("thread slave")
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
    
    def emulate_ptrace_master(self, slave, *, wait_fun = "waitpid"):
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
            slave = dbg.slaves[pid]
            log.debug(f"ptrace {pid} -> {ptrace_command}: ({hex(arg1)}, {hex(arg2)})")
            action = ptrace_dict[ptrace_command] # The slave can be a parent

            # Why am I using a Thread since I can't use dbg.next() ?
            #context.Thread(target = action, args = (arg1, arg2), kwargs = {"slave": slave}).start() # Magari fa problemi di sincronizzazione con le wait
            action(arg1, arg2, slave=slave)

            # The problem with return False is that if I walk over the breakpoint manualy I loose control of the debugger because the program continues
            return False

        # Legacy_callback so that the program does stop if we step over the breakpoint manualy
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
            return True

        self.b(self.symbols[wait_fun], legacy_callback = callback_wait)

        return self

    ########################## PTRACE EMULATION ##########################
    def PTRACE_ATTACH(self, _, __, *, slave):
        log.debug(f"pretending to attach to process {slave.pid}")
        slave.master = self
        # I don't think it is needed to stop the child
        #slave.interrupt() ?
        self.gdb.slave_has_stopped.set()
        self.return_value = 0


        # set slave. ?

    # Only function called by the slave
    def PTRACE_TRACEME(self):
        log.debug("slave wants to be traced")
        self.return_value = 0
        if context.bits == 64:
            self.r8 = -1
        # TODO: Wait for a master
        self.master.gdb.slave_has_stopped.set()

    def PTRACE_CONT(self, _, __, *, slave):
        print("slave can continue !")
        slave.gdb.master_wants_you_to_continue.set()

    def PTRACE_DETACH(self, _, __, *, slave):
        log.debug(f"ptrace detached from {slave.pid}")
        slave.gdb.master_wants_you_to_continue.set()
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
            if register in ["rip", "eip"]:
                register = "ip"
            elif register in ["rsp", "esp"]:
                register = "sp"
            assert register in registers.registers
            setattr(registers, register, value)
        self.write(pointer_registers, registers.get())
        self.return_value = 0 # right ?
    
    def PTRACE_SETREGS(self, _, pointer_registers, *, slave):
        log.warn_once("funziona solo per registri non triviali")
        registers = user_regs_struct()
        registers.set(self.read(pointer_registers, registers.size))
        for register in slave.registers:
            if register in ["rip", "eip"]:
                register = "ip"
            elif register in ["rsp", "esp"]:
                register = "sp"
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


    # Return old_inferior to know where to go back
    def switch_inferior(self, n: int) -> int:
        # May not be acurate if you switched manually before
        old_inferior = self._inferior
        if self._inferior != n:
            log.debug(f"switching to inferior {n}")
            self.execute(f"inferior {n}")
            self._inferior = n
        return old_inferior
    
    # TODO just a jump with breakpoint
    def jump(self, address, stop = True):   
        if stop:
            self.clear_stop("jump")
            log.debug("breaking destination")
            self.b(address, temporary=True)
            
        if type(address) is int:
            self.execute(f"jump *{hex(address)}")
        elif type(address) is str:
            self.execute(f"jump {address}")
        else:
            log.critical(f"What is this function {address} ?")
        
        if stop:
            log.debug("Waiting for jump to conlude")
            self.wait()

    # Now can return from anywhere in the function
    def ret(self, value: int = None, *, stop = False):
        if self.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
            pass
        elif self.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
            self.pop() # Remove the base pointer # No need to place it back in rbp
        else:
            self.stack_pointer = self.base_pointer
            self.base_pointer = self.pop()
        ret_address = self.pop()
        if value is not None:
            self.return_value = value
        self.jump(ret_address, stop)

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
            except Exception: #gdb.error: The program being debugged was signaled while in a function called from GDB.
                log.debug(f"gdb got int3 executing {function}. Retrying...")
                self.finish()
                # For some reason I just get 0x0
                #return self.return_value()
                return self.gdb_call(function, args) # Should work this time
        
        elif function in self.symbols:
            return self.call(self.symbols[function], args)
            
        else:
            raise Ecxeption(f"I don't know how to handle this function! {function} not in symbols")

    def call(self, function_address: int, args: list, *, end_pointer=None, heap=True, ret_bucket=None, wait = True):

        self.clear_stop("call")
        self.restore_arch()


        """
        Call any function in the binary with the parameters you want

        Parameters
        ----------
        function_address : [str, int]
            Pointer to the function to call
        args : list[int | str | bytes]
            List of parameters to pass to the function
            All strings passed this way will be saved in the binary with a null terminator
            Byte arrays will be saved as they are
        end_pointer : int, optional
            The function will run with a 'finish' command. If for some reason you know that it won't work this way you can set an instruction to stop at. (I currently expect it to be a ret and will step on it to leave)
        heap : bool, optional
            Byte arrays and strings passed to the functions are by default saved on the heap with a malloc(). If you can't set this to False to save them on the bss (WARNING I can't guaranty I won't overwrite data this way)
        ret_bucket : Queue, optional
            If you want to run call in a Thread and need the return value use a Queue to get back the return value
            run with `Thread(target=Debugger.call, args=(dbg, 0x1750, [b"\x00"]), kwargs={"ret_bucket":ret_val}).run()`
            or I may use callbacks inside the breakpoints instead of Thread
        """
        log.warn_once("calls should work, but we have noticed bugs sometimes with the waits. Patch them into sleeps if needed and remove restore and return if possible")
        log.warn_once("I can not guaranty yet that the program will continue executing correctly after this")
        #If we hit a breakpoint in the process you are fucked... Could think about temporarely disabeling them all
        #Here knowing which breakpoints we have and being able to temporarely disable them would be interesting
        #TODO disable breakpoints. Keep a manual flag to let breakpoints and don't run untill finish. Of course there won't be return values though

        # If the address is small it is probably a relative address
        # Can send just the name if jump can understand it
        if type(function_address) is int and function_address < 0x10000:
            function_address += self.base_elf
        #Save strings and get a pointer
        to_free = []
        def convert_arg(arg):
            if type(arg) is str:
                arg = arg.encode() + b"\x00"
            if type(arg) is bytes:
                if heap:
                    log.warn_once("I'm calling malloc to save your data. Use heap=False if you want me to save it in the BSS (experimental)")
                pointer = self.alloc(len(arg), heap=heap) # I should probably put the null byte only for string in case I have to pass a structure...
                to_free.append((pointer, len(arg))) #I include the length to virtualy clear the bss too if needed (I won't set it to \x00 though)
                self.write(pointer, arg + b"\x00")
                arg = pointer
            return arg

        args = [convert_arg(arg) for arg in args]

        #save registers 
        values = []
        for register in self.registers: #Exclude return pointer
            values.append(getattr(self, register))    
        
        def restore_memory():
            for name, value in zip(self.registers, values): #Exclude return pointer. I haven't tested including it
                setattr(self, name, value)
            for pointer, n in to_free[::-1]: #I do it backward to have a coerent behaviour with heap=False, but I still don't really know if I sould implement a free in that case
                self.dealloc(pointer, len=n, heap=heap)

        #log.debug("breaking call")
        #self.b(function_address, temporary=True)

        if self.elf.bits == 64:
            calling_convention = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            for register in calling_convention:
                if len(args) == 0:
                    break
                log.debug("%s setted to %s", register, args[0])
                setattr(self, register, args.pop(0))
            
        #args.append(self.instruction_pointer)
        #Should I offset the stack pointer to preserve the stack frame ? No, right ?
        for arg in args:
            self.push(arg)
        
        self.push(self.instruction_pointer)
        self.jump(function_address)

        #if type(function_address) is int:
        #    self.execute(f"jump *{hex(function_address)}")
        #elif type(function_address) is str:
        #    self.execute(f"jump {function_address}")
        #else:
        #    log.critical(f"What is this function {function_address} ?")
        #log.debug("Waiting for jump to conluse")
        #self.wait() 
        
        log.debug("jumped to %s\nWaiting to finish", hex(self.instruction_pointer))
        # Vorrei poter gestire il fatto che l'utente potrebbe voler mettere dei breakpoints nel programma
        # Sarebbe interessante un breakpoint sull'istruzione di ritorno con callback che rimette a posto la memoria
        # I also want to just be able to send the code in a shellcode and let it sleep without blocking
        if wait:
            if end_pointer is None:
                # Wait why don't I just put a breakpoint on my address before calling the function and then wait ?
                self.finish() # Finish can only work if you have a leave ret. Set the last address otherwise
                log.debug("call finished")
                res = self.return_value
                restore_memory()
            else:
                log.warn_once("You chose to use 'end_pointer'. Only do it if you need breakpoints in the function and to restore memory when exiting!")
                log.warn_once("You will have to handle manualy the execution of your program from gdb untill you reach the pointer selected (Which should be a pointer to the ret instruction...)")
                log.debug("breaking return in %s", hex(end_pointer))
                from queue import Queue
                return_value = Queue()
                def callback(dbg):
                    return_value.put(dbg.return_value)
                    return True
                self.b(end_pointer, callback=callback, temporary=True)
                # Non mi convince come gestisco la wait [03/03/23]
                self.c()
                # TODO TEST IF THIS BLOCKS EVERYTHING (SPOILER PROBABLY)
                # Why don't I use return_value.get() to wait since it's blocking ? [02/03/23]
                while(return_value.empty()):
                    self.wait()
                self.step()
                res = return_value.get()
            if ret_bucket is not None:
                ret_bucket.put(res)
            return res
        else:
            log.debug("I'm not waiting :)")
            self.c()
            return None

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
        #self.restore_arch()
        #if context.bits == 64:
        #    if index < 6:
        #        register = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][index]
        #        return getattr(self, register)
        #    else:
        #        index -= 6
        #
        #index += 1 # stack pointer has the return address
        #pointer = self.stack_pointer + index * context.bytes
        #return self.read(pointer, context.bytes)


    # Can be used with signal code or name. Case insensitive.
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

        log.warn_once("the method signal() is still evolving. Use it if you don't want the prgram to continue after receiving the signal. If the signal will modify your code you HAVE to add the argument 'handler' with an address after the code has changed")
        # Sending signal will cause the process to resume his execution so we put a breakpoint and wait for the handler to finish executing
        # I may put a flag to precise if the code is self modifying or not and if it is handle breakpoints
        # If the code is self modifying you must use handler otherwise the breakpoint will be overwriten with bad code [26/02/23]
        if handler is None:
            self.b(self.instruction_pointer, temporary=True)
        # I don't understand why callback doesn't allways find my_address. I called signal 3 times and it works for the first 2, but not the next one...  [26/02/23]
        # Okay, the problem was that the breakpoints wasn't considered as hit since we don't stop, so all the callbacks I have set are called each time [26/02/23]
        else:
            from queue import Queue
            my_address = Queue()
            my_address.put(self.instruction_pointer)
            def callback(dbg):
                address = my_address.get()
                my_address.put(dbg.instruction_pointer)
                #def delete_callback(dbg):
                #    handler = my_address.get()
                #    dbg.breakpoints[hex(handler)].delete()
                #    return True
                dbg.b(address, temporary=True)
                # Can I delete this breakpoint ? Nope so let's do it in another callback... [26/02/23]
                #dbg.breakpoints[hex(dbg.instruction_pointer)].delete()
                return False  
            # Now thanks to real callbacks I can return to temprary breakpoints [20/03/23]
            self.b(handler, callback=callback, temporary=True)
        
        if type(n) is str:
            n = n.upper()
        self.execute(f"signal {n}")
        self.wait()
        #del my_address # Prevent callback to access it again at a future execution [26/02/23]
        #del dbg.my_address # I don't want to delete it in case I hit a different breakpoint before the callback is called [26/02/23]

    def syscall(self, code: int, args: list):
        log.debug(f"syscall {code}: {args}")
        self.rax = code
        # Can't I use search(syscall ; ret) ? Taking care of int80 vs syscall [04/03/23]
        return self.call(self.symbols["_syscall"], args)

    def inject_shellcode(self, shellcode, *, address = None, skip_mprotect = False, inferior = None):

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

    def inject_sleep(self, address):
        #test:
        #jmp test
        shellcode = b"\xeb\xfe"
        backup = self.read(address, len(shellcode))
        self.write(address, shellcode)
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
    #ITS SO UGLY ESPECIALY WITH THE REGISTERS
    #Since a few people hate OOP and prefer to write their exploit with p = Debugger() and handle it has a simple process let's make all methods of Process accessible from the debugger
    def __getattr__(self, name):
    #    log.debug(f"looking for attr {name}")
    #    #getattr is only called when an attribute is NOT found in the instance's dictionary
    #    #I may wan't to use this instead of the 300 lines of registers, but have to check how to handle the setter
        if name in ["p", "elf", "gdb"]: #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self.registers in __setattr__
            return False
        if name in self.registers + self.minor_registers:
            res = int(self.gdb.parse_and_eval(f"${name}")) % 2**self.elf.bits
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
        if self.elf and name in self.registers + self.minor_registers:
            self.restore_arch()
            self.execute(f"set ${name.lower()} = {value % 2**context.bits}")
        else:
            super().__setattr__(name, value)

# I'm having problems with a timeouts...
#class MyBreakpoint(gdb.Breakpoint):
#                def __init__(self, conn, address, callback, temporary=False):
#                    super().__init__(conn, address, temporary=temporary)
#                    self.callback = callback
#                
#                def stop(self, *args):
#                    must_break = _self.callback(self) 
#                    if must_break is None:
#                        must_break = True
#                    return must_break