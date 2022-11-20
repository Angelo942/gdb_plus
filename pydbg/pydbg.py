from pwn import *
from os import kill
from time import sleep

#WARNING pwndbg breaks the API so you have to disable it. I advise to use GEF

#You don't have to interrupt the process to set breakpointes or read and overwrite the memory. Only to access the registers

class Debugger:
    #If possible patch the rpath (spwn and pwninit do it automaticaly) instead of using env to load the correct libc. This will let you get a shell not having problems trying to preload bash too
    def __init__(self, target, env={}, aslr=True, script=None, from_start=True):
        self._capstone = None #To decompile assembly for next_inst
        self._auxiliary_vector = None #only used to locate the canary
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
            pass
        #Pwntools allows you to use NOPTRACE if you wan't to skip the attach so I keep the logic here
        #The only reason I have to keep it separated is that gdb.attach doesn't return, so the unpack "_, self.gdb" breaks my code
        #elif context.noptrace:
        #    self.p = process(target, env=env, aslr=aslr)
        try:
            # I commented this part because I'm not sure how to handle the absense of a process for some features like access to registers
            #if type(target) is int:
            #    _, self.gdb = gdb.attach(target, gdbscript=script, api=True)
            #elif type(target) is process:
            if type(target) is process:
                self.p = target
                _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True) # will raise TypeError if noptrace
            #assert type(target) is str, f"I don't know how to handle {type(target)} as target" 
            elif from_start:
                self.p = gdb.debug(target, env=env, aslr=aslr, gdbscript=script, api=True)
                self.gdb = self.p.gdb # will raise AttributeError if noptrace
            else:
                self.p = process(target, env=env, aslr=aslr)
                _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)
        except (TypeError, AttributeError):
            log.info_once("I think you used noptrace. If not raise an Issue")

    def detach(self):    
        try:
            #self.interrupt(wait=False)
            self.execute("quit") #Doesn't allways work if I interact with gdb manualy
        except Exception:
            pass #quando muore gdb raisa EOF

    def close(self):
        self.detach()
        self.p.close()

    #I would like to make them viable even in remote to not have to comment out or put checks at every call in my scripts.
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
    def interrupt(self, wait=True):
        #self.execute("interrupt") #pwntools uses this command, but I don't because it may not work if the continue command has been sent manualy in gdb
        kill(self.p.pid, signal.SIGINT)
        if wait: # Set wait to false if you are not sure that the process is actualy running
            self.wait()
        else:
            # This is a case where a timeout whould be usefull... I may consider re_intruducing it
            log.warn_once("WARNING interrupt without waiting is curently broken")
            # If interrupt is called while the process isn't running wait() will never return so I don't want to call it if I'm not sure
            # but it still takes some time to interrupt the process if it si running so I HAVE to wait some time just in case.
            # (There is no way of reliably knowing if the process is running. Even setting a flag on continue wouldn't work if the command is sent manualy from gdb
            sleep(0.2)

    manual = interrupt

    def step(self):
        self.execute("si")
        self.wait()

    #Finish a function with modifying code
    def step_until_address(self, address: int, callback=None, limit=10_000) -> bool:
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

    def step_until_ret(self, callback=None, limit=10_000):
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

    def next(self):
        self.execute("ni")
        self.wait()

    def finish(self):
        self.execute("finish")
        self.wait()
        
    #May want to put breakpoints relative to the libc too?
    def b(self, address, callback=None, temporary=False, relative=False):
        '''
        callback takes a pointer to the debugger as parameter and should return True if you want to interrupt the execution, False otherwise. If you forget a return value the default behaviour is to interrupt the process
        You can use Queue to pass data between your exploit and the callbacks
        '''
        if not self.debugging:
            return

        if type(address) is int:
            if address < 0x010000:
                relative = True
            if relative:
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
        self.sp -= self.p.elf.bytes
        self.write(self.sp, self.pbits(value))

    def pop(self):
        self.read(self.sp, self.p.elf.bytes)
        self.sp += self.p.elf.bytes

    ########################## MEMORY ACCESS ##########################

    def read(self, address: int, size: int):
        return self.p.readmem(address, size)
        
    def write(self, pointer, byte_array):
        self.p.writemem(pointer, byte_array)
        
    #Alloc and Dealloc instead of malloc and free because you may want to keep those names for function in your exploit
    def alloc(self, n, heap=True):
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
    
    #get base address of libc
    def get_base_libc(self):
        return self.p.libs()[self.libc.path]

    @property
    def base_libc(self):
        return self.get_base_libc()

    #get base address of binary
    def get_base_elf(self):
        return self.p.libs()[self.elf.path]

    @property # I don't wan't to rely on self.p.elf.address which isin't set by default for PIE binaries
    def base_elf(self):
        return self.get_base_elf()
        
    #taken from GEF
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
        canary = self.read(canary_location, self.p.elf.bytes)
        return b"\x00"+canary[1:]
        #taken from GEF
        #[+] The canary of process 17016 is at 0xff87768b, value is 0x2936a700
        #return int(self.execute("canary").split()[-1], 16)

    @property
    def registers(self):
        if self.p.elf.bits == 32:
            return ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip"]
        elif self.p.elf.bits == 64:
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
        if self.p.elf.bits == 64:
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
            self._capstone = Cs(CS_ARCH_X86, self.p.elf.bytes)
        inst = next(self._capstone.disasm(self.read(self.ip, 16), self.ip)) #15 bytes is the maximum size for an instruction in x64
        from functools import partial
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        return inst

    ########################## Generic references ##########################

    @property
    def return_pointer(self):
        if self.p.elf.bits == 32:
            return self.eax
        else:
            return self.rax

    @property
    def sp(self):
        if self.p.elf.bits == 32:
            return self.esp
        else:
            return self.rsp

    @sp.setter
    def sp(self, value):
        if self.p.elf.bits == 32:
            self.esp = value
        else:
            self.rsp = value

    @property
    def ip(self):
        if self.p.elf.bits == 32:
            return self.eip
        else:
            return self.rip

    @ip.setter
    def ip(self, value):
        if self.p.elf.bits == 32:
            self.eip = value
        else:
            self.rip = value

    #Generic convertion to bytes for addresses
    def pbits(self, value):
        if self.p.elf.bits == 32:
            return p32(value) 
        else:
            return p64(value)

    ########################## REV UTILS ##########################

    def call(self, function_address: int, args: list, end_pointer=None, heap=True):
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
                arg = arg.encode()
            if type(arg) is bytes:
                if heap:
                    log.warn_once("I'm calling malloc to save your data. Use heap=False if you want me to save it in the BSS (experimental)")
                pointer = self.alloc(len(arg) + 1, heap) # I should probably put the null byte only for string in case I have to pass a structure...
                to_free.append((pointer, len(arg) + 1)) #I include the length to virtualy clear the bss too if needed (I won't set it to \x00 though)
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

        if self.p.elf.bits == 64:
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
            self.execute(f"finish") #Use a breakpoint instead if you know the last address
            self.wait()
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
    def signal(self, n):
        #Sending signal will cause the process to resume his execution so we put a breakpoint and wait for the handler to finish executing
        log.warn_once("WARNING sending signals will continue the execution of your code. Put a breakpoint on the address you are at unless the code is self modifying.") 
        log.warn_once("I won't put a breakpoint for you because it may corrupt the code if the code is self modifying") 
        log.warn_once("If the code is self modifying: 1) Find the handler 2) Put a breakpoint on the return instruction 3) Save your instruction pointer 4) Call signal() 5) Put a breapoint on your save instruction pointer when you reach the handler finishes executing 5) continue")
        #self.b(self.ip, temporary=True)
        if type(n) is str:
            n = n.upper()
        self.execute(f"signal {n}")
        #self.wait()

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
        if name == "p": #If __getattr__ is called with p it means I haven't finished initializing the class so I shouldn't call self.registers in __setattr__
            return False
        if name in self.registers + self.minor_registers:
            res = int(self.gdb.parse_and_eval(f"${name}")) % 2**self.p.elf.bits
            return res
        elif name in dir(self.p):
            return getattr(self.p, name)
        else:
            raise AttributeError

    def __setattr__(self, name, value):
        if self.p and name in self.registers + self.minor_registers:
            self.execute(f"set ${name.lower()} = {value}")
        else:
            super().__setattr__(name, value)
        