from pwn import *
from os import kill
from time import sleep

#WARNING pwndbg breaks the API so you have to disable it. I advise to use GEF

#You don't have to interrupt the process to set breakpointes or read and overwrite the memory. Only to access the registers

class Debugger:
    #If possible patch the rpath (spwn and pwninit do it automaticaly) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target: [int, process, str], env={}, aslr:bool=True, script:str=None, from_start:bool=True, binary:str=None):
        self._capstone = None #To decompile assembly for next_inst
        self._auxiliary_vector = None #only used to locate the canary
        self._base_libc = None
        self._base_elf = None
        self.pid = None # Taken out to be able to send kill() even if we don't use a process
        self.inferior = None #inferior to easily access memory
        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        self.breakpoints = {} #Save all non temporary breakpoints for easy access
        self.debugging = None #I want to keep the exploits as clean as possible, so I'm gonna try to handle everything so I can still inherit the class when attacking in remote without having to worry about calls to breakpoint or execute
        #gdb.debug() was rulled out previously due to two bugs with older version of gdbserver in ubuntu 20.04
        #1) gdbserver crashes trying to locate the canary (at least with 32 bit binaries) -> patched in gdbserver 11.0.50 (working in ubuntu 22.04)
        #2) LD_PRELOAD uses the library for gdbserver and not the process -> solved in ubuntu 22.04 too
        
        if args.REMOTE or context.noptrace:
            self.debugging = False
        else:
            self.debugging = True

        #if context.remote:
        if args.REMOTE:
            self.elf = ELF(target, checksec=False)
        #Pwntools allows you to use NOPTRACE if you wan't to skip the attach so I keep the logic here
        elif context.noptrace:
            self.p = process(target, env=env, aslr=aslr)
        # I commented this part because I'm not sure how to handle the absense of a process for some features like access to registers
        elif type(target) is int:
            # How can I pass the elf if I just use the pid ?
            self.pid = target
            _, self.gdb = gdb.attach(target, gdbscript=script, api=True)
            # Just ask for it
            if elf is not None:
                self.elf = ELF(binary)
            else:
                log.info_once("You attached to a process from the pid but didn't pass a binary. Use binary=<path_to_elf> if possible")
                self.inferior = self.gdb.inferiors()[0]
                bits = 64 if self.inferior.architecture().name().endswith("64") else 32 # Faster, I just hope it always works
                #bits = 64 if next(self.inferior.architecture().registers()).name == 'rax' else 32
                self.elf = FakeELF(bits)
        elif type(target) is process:
            self.p = target
            self.pid = self.p.pid
            _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True) # will raise TypeError if noptrace
        elif from_start:
            self.p = gdb.debug(target, env=env, aslr=aslr, gdbscript=script, api=True)
            self.gdb = self.p.gdb
        else:
            self.p = process(target, env=env, aslr=aslr)
            _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)
        # I think I just need inferior when I don't have a process
        #if hasattr(self, "gdb"):
        #    self.inferior = self.gdb.inferiors()[0]
        if self.p:
            self.pid = self.p.pid
            self.elf = self.p.elf

    # Use as : dbg = Debugger("file").remote(IP, PORT)
    def remote(self, ip: str, port: int):
        if args.REMOTE:
            self.p = remote(ip, port)
        return self

    def detach(self):
        try:
            self.execute("quit") #Doesn't allways work if after interacting manualy
        except EOFError:
            log.debug("GDB successfully closed")

    def close(self):
        self.detach()
        self.p.close()

    def execute(self, code: str):
        if self.debugging:
            return self.gdb.execute(code, to_string=True)
        else:
            log.warn_once("Debug is off, commands won't be executed")
            
    ########################## CONTROL FLOW ##########################

    #I don't like continue_and_wait, continue_nowait. I'm not even sure I want to leave the option to have a wait in the fuction. Just do self.c() self.wait() and it will be easier to debug your exploit
    def c(self, wait=False):
        self.execute("continue")
        if wait:
            self.wait()

    cont = c

    #You have to remember you can not send SOME commands to gdb while the process is running
    #You don't have to interrupt the process to set breakpoints (except if you want callbacks) or access and overwrite the memory. Only work with the registers
    def wait(self):
        self.gdb.wait()

    #temporarely interrupt the execution of our process to get back control of gdb (equivalent of a manual ctrl+C)
    #don't worry about the "kill"
    def interrupt(self, wait=True, timeout=0.2):
        """
        Stop the process as you would with ctrl+C

        Parameters
        ----------
        wait : bool, optional
            By default you should wait for the process to stop, but if you aren't sure you can try setting wait to False
        timeout : floot, optional
            The timeout should be the time needed for gdb to interrupt the process. Too small your program may crash, too big and you are waisting time. Idealy you will never change it.
        """
        # self.execute("interrupt") #pwntools uses this command, but I don't because it may not work if the continue command has been sent manualy in gdb
        if not self.debugging:
            return
        kill(self.pid, signal.SIGINT)
        if wait: # Set wait to false if you are not sure that the process is actualy running
            self.wait()
        else:
            # This is a case where a timeout in wait whould be usefull... I may consider re_intruducing it
            # If interrupt is called while the process isn't running wait() will never return so I don't want to call it if I'm not sure
            # but it still takes some time to interrupt the process if it si running so I HAVE to wait some time just in case.
            # (There is no way of reliably knowing if the process is running. Even setting a flag on continue wouldn't work if the command is sent manualy from gdb
            sleep(timeout)

    manual = interrupt

    def step(self):
        self.execute("si")
        self.wait()

    #Finish a function with modifying code
    def step_until_address(self, address: int, callback=None, limit:int=10_000) -> bool:
        for i in range(limit):
            if callback is not None:
                callback(self)
            if self.ip == address:
                return i
                break
            self.step()
        else:
            log.warn_once(f"I made {limit} steps and haven't reached the address you are looking for...")
            return -1

    def step_until_ret(self, callback=None, limit:int=10_000):
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

    def next(self, wait:bool=True):
        self.execute("ni")
        if wait:
            self.wait()

    def finish(self, wait:bool=True):
        self.execute("finish")
        if wait:
            self.wait()
        
    #May want to put breakpoints relative to the libc too?
    def b(self, address: [int, str], callback=None, temporary=False):
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
        if not self.debugging:
            return

        if type(address) is int:
            if address < 0x010000:
                address += self.base_elf
            address = f"*{hex(address)}"
        if callback is None:
            res = self.gdb.Breakpoint(address, temporary=temporary)
        else:
            # I don't know yet how to handle the conn if I don't go through self.gdb.Breakpoint so I create the class here :(
            log.warn_once("callbacks should work, but if you have problems scroll a bit to fing the error messages hidden above in gdb :)")
            # For some reason this part require the process to be interrupted. I usualy do it from my exploit, but don't want to force everyone to do so
            #self.interrupt(wait=False) # Interrupt if running, but don't wait forever because I don't know if it is really running
            class MyBreakpoint(self.gdb.Breakpoint):
                def __init__(_self, address, callback, temporary=False):
                    super().__init__(address, temporary=temporary)
                    _self.callback = callback
                def stop(_self, *args):
                    _break = _self.callback(self) 
                    if _break is None:
                        return True
                    return _break
            res = MyBreakpoint(address, callback, temporary)
            #self.c() # This is a problem... I may break someone's exploit if the process was stopped by the user
        if not temporary:
            self.breakpoints[address[1:] if address[0] == "*" else address] = res #[1:] to remove the '*' from the key if it's an adress, but leave intect if it's a function name
        return res
        
    breakpoint = b

    def push(self, value):
        self.sp -= self.elf.bytes
        self.write(self.sp, self.pbits(value))

    def pop(self):
        self.read(self.sp, self.elf.bytes)
        self.sp += self.elf.bytes

    ########################## MEMORY ACCESS ##########################

    def read(self, address: int, size: int) -> bytes:
        #return self.p.readmem(address, size) # I don't want to relie on the process.
        return self.inferior.read_memory(address, size).tobytes()

    def write(self, pointer: int, byte_array: bytes):
        self.p.writemem(pointer, byte_array)
        
    #Alloc and Dealloc instead of malloc and free because you may want to keep those names for function in your exploit
    def alloc(self, n: int, heap=True) -> int:
        """
    	Allocate N bytes in the heap

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
        if heap:
            pointer = self.execute(f"call (long) malloc({n})").split()[-1]
        else:
            if self._free_bss is None:
                self._free_bss = self.bss() # I have to think about how to preserve eventual data already present
            pointer = hex(self._free_bss)
            self._free_bss += n
        return int(pointer, 16)

    def dealloc(self, pointer, len=0, heap=True):
        if heap:
            self.execute(f"call (void) free({hex(pointer)})")
        else:
            self._free_bss -= len
            #I know it's not perfect, but damn I don't want to implement a heap logic for the bss ahahah
            #Just use the heap if you can
    
    # get base address of libc
    # I would want something that doesn't requires a process
    def get_base_libc(self):
        if self.p and hasattr(self, libc):
            return self.p.libs()[self.libc.path]
        else:
            data = self.execute("info files")
            for line in data.split("\n"):
                line = line.strip()
                if "libc" in line and line.startswith("0x"):
                    address = int(line.split()[0], 16)
                    return address - address % 0x1000
    @property
    def base_libc(self):
        if self._base_libc is None:
            self._base_libc = self.get_base_libc()
        return self.get_base_libc()

    # get base address of binary
    def get_base_elf(self):
        if self.p:
            return self.p.libs()[self.elf.path]
        else:
            data = self.execute("info files")
            for line in data.split("\n"):
                line = line.strip()
                if line.startswith("Entry point:"):
                    address = int(line.split()[-1], 16)
                    return address - address%0x1000 #Not always true...
                    

    @property # I don't wan't to rely on self.elf.address which isin't set by default for PIE binaries
    def base_elf(self):
        if self._base_elf is None:
            self._base_elf = self.get_base_elf()
        return self._base_elf
        
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

    @property
    def canary(self):
        auxval = self.auxiliary_vector
        canary_location = auxval["AT_RANDOM"]
        canary = self.read(canary_location, self.elf.bytes)
        return b"\x00"+canary[1:]
        #taken from GEF
        #[+] The canary of process 17016 is at 0xff87768b, value is 0x2936a700
        #return int(self.execute("canary").split()[-1], 16)

    @property
    def registers(self):
        if self.elf.bits == 32:
            return ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]
        elif self.elf.bits == 64:
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
        "di", "dil"]
        if self.elf.bits == 64:
            _minor_registers += ["eax", "ebx", "ecx", "edx", "esi", "edi",
            "r8d", "r8w", "r8l",
            "r9d", "r9w", "r9l",
            "r10d", "r10w", "r10l"
            "r11d", "r11w", "r11l",            
            "r12d", "r12w", "r12l",
            "r13d", "r13w", "r13l",
            "r14d", "r14w", "r14l",
            "r15d", "r15w", "r15l"]
        return _minor_registers

    @property
    def next_inst(self):
        from functools import partial
        if self._capstone is None:
            from capstone import Cs, CS_ARCH_X86
            self._capstone = Cs(CS_ARCH_X86, self.elf.bytes)
        inst = next(self._capstone.disasm(self.read(self.ip, 16), self.ip)) #15 bytes is the maximum size for an instruction in x64
        from functools import partial
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        return inst

    ########################## Generic references ##########################

    @property
    def return_pointer(self):
        if self.elf.bits == 32:
            return self.eax
        else:
            return self.rax

    @return_pointer.setter
    def sp(self, value):
        if self.elf.bits == 32:
            self.eax = value
        else:
            self.rax = value

    @property
    def sp(self):
        if self.elf.bits == 32:
            return self.esp
        else:
            return self.rsp

    @sp.setter
    def sp(self, value):
        if self.elf.bits == 32:
            self.esp = value
        else:
            self.rsp = value

    @property
    def ip(self):
        if self.elf.bits == 32:
            return self.eip
        else:
            return self.rip

    @ip.setter
    def ip(self, value):
        if self.elf.bits == 32:
            self.eip = value
        else:
            self.rip = value

    #Generic convertion to bytes for addresses
    def pbits(self, value):
        if self.elf.bits == 32:
            return p32(value) 
        else:
            return p64(value)

    ########################## REV UTILS ##########################

    def call(self, function_address: int, args: list, end_pointer=None, heap=True):
        """
    	Call any function in the binary with the parameters you want

    	Parameters
    	----------
    	function_address : int
    		Pointer to the function to call
    	args : list
    		List of parameters to pass to the function
			All strings passed this way will be saved in the binary with a null terminator
			Byte arrays will be saved as they are
    	end_pointer : TYPE, optional
    		The function will run with a 'finish' command. If for some reason you know that it won't work this way you can set an instruction to stop at. (I currently expect it to be a ret and will step on it to leave)
    	heap : BOOL, optional
    		Byte arrays and strings passed to the functions are by default saved on the heap with a malloc(). If you can't set this to False to save them on the bss (WARNING I can't guaranty I won't overwrite data this way)
    	"""
        log.warn_once("calls should work, but we have noticed bugs sometimes with the waits. Patch them into sleeps if needed and remove restore and return if possible")
        log.warn_once("I can not guaranty yet that the program will continue executing correctly after this")
        #If we hit a breakpoint in the process you are fucked... Could think about temporarely disabeling them all
        #Here knowing which breakpoints we have and being able to temporarely disable them would be interesting
        #TODO disable breakpoints. Keep a manual flag to let breakpoints and don't run untill finish. Of course there won't be return values though

        # If the address is small it is probably a relative address
        if function_address < 0x10000:
            function_address += self.base_elf
        #Save strings and get a pointer
        to_free = []
        def convert_arg(arg):
            if type(arg) is str:
                arg = arg.encode() + b"\x00"
            if type(arg) is bytes:
                if heap:
                    log.warn_once("I'm calling malloc to save your data. Use heap=False if you want me to save it in the BSS (experimental)")
                pointer = self.alloc(len(arg), heap) # I should probably put the null byte only for string in case I have to pass a structure...
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

        log.debug("breaking call to %s", hex(function_address))
        self.b(function_address, temporary=True)

        if self.elf.bits == 64:
            calling_convention = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            for register in calling_convention:
                if len(args) == 0:
                    break
                log.debug("%s setted to %s", register, args[0])
                setattr(self, register, args.pop(0))
            
        args.append(self.ip)
        #Should I offset the stack pointer to preserve the stack frame ? No, right ?
        for arg in args:
            self.push(arg)
        
        log.debug("jumping to %s", hex(function_address))
        self.execute(f"jump *{hex(function_address)}")
        self.wait()
        # Vorrei poter gestire il fatto che l'utente potrebbe voler mettere dei breakpoints nel programma
        # Sarebbe interessante un breakpoint sull'istruzione di ritorno con callback che rimette a posto la memoria
        if end_pointer is None:
            self.finish() # Finish can only work if you have a leave ret. Set the last address otherwise
            log.debug("call finished")
            res = self.return_pointer
            restore_memory()
        else:
            log.warning("You chose to use 'end_pointer'. Only do it if you need breakpoints in the function and to restore memory when exiting!")
            log.warning("You will have to handle manualy the execution of your program from gdb untill you reach the pointer selected (Which should be a pointer to the ret instruction...)")
            log.debug("breaking return in %s", hex(end_pointer))
            from queue import Queue
            return_value = Queue()
            def callback(dbg):
                return_value.put(dbg.return_pointer)
                return True
            self.b(end_pointer, callback=callback, temporary=True)
            self.c()
            # TODO TEST IF THIS BLOCKS EVERYTHING (SPOILER PROBABLY)
            while(return_value.empty()):
                self.wait()
            self.step()
            res = return_value.get()
        return res

    #Can be used with signal code or name. Case insensitive.
    def signal(self, n, handler=None):
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
        # Sending signal will cause the process to resume his execution so we put a breakpoint and wait for the handler to finish executing
        # I may put a flag to precise if the code is self modifying or not and if it is handle breakpoints
        if handler is None:
            self.b(self.ip, temporary=True)
        else:
            from queue import Queue
            my_address = Queue()
            my_address.put(self.ip)
            def callback(dbg):
                dbg.b(my_address.get(), temporary=False)
                return False
            self.b(handler, temporary=True, callback=callback)
        if type(n) is str:
            n = n.upper()
        self.execute(f"signal {n}")
        self.wait()

    ########################## GEF shortcuts ##########################
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
    #Since a few people hate OOP and prefer to write their exploit with p = Debugger() and handle it has a simple process let's make all methods of process accessible from the debugger
    def __getattr__(self, name):
        #getattr is only called when an attribute is NOT found in the instance's dictionary
        #I may wan't to use this instead of the 300 lines of registers, but have to check how to handle the setter
        if name in ["p", "elf"]: #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self.registers in __setattr__
            return False
        if name in self.registers + self.minor_registers:
            res = int(self.gdb.parse_and_eval(f"${name}")) % 2**self.elf.bits
            return res
        elif self.p and name in dir(self.p):
            return getattr(self.p, name)
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if self.elf and name in self.registers + self.minor_registers:
            self.execute(f"set ${name.lower()} = {value}")
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

# I just need the elf to know if I should use eip or rip... I may just do it this way if I don't have the binary
class FakeELF:
    def __init__(self, bits):
        self.bits = bits
        self.bytes = self.bits // 8