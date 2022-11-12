from pwn import *
from os import kill

#WARNING pwndbg breaks the API so you have to disable it. I advise to use GEF

#You don't have to interrupt the process to set breakpointes or read and overwrite the memory. Only to access the registers

class Debugger:
    #If possible patch the binary with spwn or pwninit instead of using env. This will let you get a shell instead of having problems trying to preload bash too
    def __init__(self, target, env={}, aslr=True, script=None, from_start=False):
        self._auxiliary_vector = None #only used to locate the canary
        self._free_bss = None #Used to allocate data in the bss if you can't use the heap
        #What is best ? A simple list or a dictionary with the address as a key?
        self.breakpoints = {}
        #gdb.debug() was rulled out previously due to two bugs with older version of gdbserver used in ubuntu 20.04
        #1) gdbserver crashes trying to locate the canary (at least with 32 bit binaries) -> patched in gdbserver 11.0.50 (working in ubuntu 22.04)
        #2) LD_PRELOAD uses the library for gdbserver and not the process -> solved in ubuntu 22.04 too
        
        #Pwntools allows you to use NOPTRACE if you wan't to skip the attach so I keep the logic here
        if context.noptrace:
            self.p = process(target, env=env, aslr=aslr)
        elif from_start:
            self.p = gdb.debug(target, env=env, aslr=aslr, gdbscript=script, api=True)
            self.gdb = self.p.gdb
        else:
            self.p = process(target, env=env, aslr=aslr)
            _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)
        
    #You have to remember you can not send SOME commands to gdb while the process is running
    #You don't have to interrupt the process to set breakpointes or access and overwrite the memory. Only for the registers
    #pseudo-timeout for backward compatibility
    def wait(self, timeout=1):
        if timeout != 0:
            self.gdb.wait()

    #get base address of libc
    def get_base_libc(self):
        return self.p.libs()[self.libc.path]
        #if self._base_libc is None:
        #    data = self.execute("info files")
        #    for line in data.split("\n"):
        #        line = line.strip()
        #        if "libc" in line and line.startswith("0x"):
        #            address = int(line.split()[0], 16)
        #            self._base_libc = address - address%0x1000
        #return self._base_libc

    #get base address of binary
    def get_base_elf(self):
        return self.p.libs()[self.elf.path]
        #if self._base_elf is None:
        #    data = self.execute("info files")
        #    for line in data.split("\n"):
        #        line = line.strip()
        #        if line.startswith("Entry point:"):
        #            address = int(line.split()[-1], 16)
        #            self._base_elf = address - address%0x1000 #Not always true...
        #return self._base_elf
        
    #temporarely interrupt the execution of our process to get back control of gdb (equivalent of a manual ctrl+C)
    #don't worry about the "kill" 
    def interrupt(self):
        kill(self.p.pid, signal.SIGINT)
        #self.execute("interrupt") #pwntools uses this command, but I don't because it may not work if the continue command has been sent manualy in gdb
        self.wait()

    manual = interrupt
        
    #Alloc and Dealloc instead of malloc and free because you may want to keep those names for function in your exploit
    def alloc(self, n, heap=True):
        if heap:
            pointer = self.execute(f"call (long) malloc({n})").split()[-1]
        else:
            if self._free_bss is None:
                self._free_bss = self.bss()
            pointer = hex(self._free_bss)
            self._free_bss += n
        return int(pointer, 16)

    def dealloc(self, pointer, len=0, heap=True):
        if heap:
            execute(f"call (void) free({hex(pointer)})")
        else:
            self._free_bss -= len

    def read(self, address: int, size: int):
        return self.p.readmem(address, size)
        
    def write(self, pointer, byte_array):
        self.p.writemem(pointer, byte_array)

    #I would like to make them viable even in remote to not have to comment out or put checks at every call in my scripts.
    def execute(self, code: str):
        if not context.noptrace:
            return self.gdb.execute(code, to_string=True)
        else:
            log.warn_once("Debug is off, commands won't be executed")
            
    #May want to put breakpoints relative to the libc too?
    def b(self, address, callback=None, temporary=False, relative=False):
        '''
        callback takes a pointer to the debugger as parameter and should return True if you want to interrupt the execution, False otherwise. If you forget a return value the default behaviour is to interrupt the process
        You can use Queue to pass data between your exploit and the callbacks
        '''
        if type(address) is int:
            if address < 0x010000:
                relative = True
            if relative:
                address += self.get_base_elf()
            address = f"*{hex(address)}"
        if callback is None:
            res = self.gdb.Breakpoint(address, temporary=temporary)
        else:
            #I don't know yet how to handle the conn if I don't go through self.gdb.Breakpoint so I create the class here :(
            log.warn_once("callbacks should work, but if you have problems scroll a bit for the error messages hidden above in gdb :)")
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
        if not temporary:
            self.breakpoints[address[1:]] = res #[1:] to remove the '*' from the key
        return res
        
    breakpoint = b
    
    #timeout for backward compatibility
    def c(self, timeout=0):
        self.execute("continue")
        self.wait(timeout) #timeout = 0 if you do not want to wait

    def call(self, function_address: int, args: list, end_pointer=None, breakpoint=False, heap=True):
        log.info_once("calls should work, but we have noticed bugs sometimes with the waits. Patch them into sleeps if needed and remove resore and return if possible")
        #If we hit a breakpoint in the process you are fucked... Could think about temporarely disabeling them all
        #Here knowing which breakpoints we have and being able to temporarely disable them would be interesting
        #TODO disable breakpoints. Keep a manual flag to let breakpoints and don't run untill finish. Of course there won't be return values though

        #Save strings in the heap
        to_free = []
        def convert_arg(arg):
            if type(arg) is str:
                arg = arg.encode()
            if type(arg) is bytes:
                if heap:
                    log.warn_once("I'm calling malloc to save your data. Use heap=False (not implemented yet) if you want me to save it elswhere")
                pointer = self.alloc(len(arg) + 1, heap)
                to_free.append((pointer, len(arg) + 1)) #I include the length to virtualy clear the bss too if needed (I won't set it to \x00 though)
                self.write(pointer, arg + b"\x00")
                arg = pointer
            return arg

        args = [convert_arg(arg) for arg in args]

        #save registers 
        values = []
        for register in self.registers:
            values.append(getattr(self, register))    
        
        def restore_memory():
            for name, value in zip(self.registers, values):
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
        #Should I offset the stack pointer to preserve the stack frame ?
        for arg in args:
            self.push(arg)
        
        log.debug("jumping to %s", hex(function_address))
        self.execute(f"jump *{hex(function_address)}")
        self.wait()
        if end_pointer is None:
            self.execute(f"finish") #Use a breakpoint instead if you know the last address
        else:
            log.debug("breaking return in %s", hex(end_pointer))
            self.b(end_pointer, temporary=True)
            self.c()
        self.wait()
        log.debug("call finished")
        res = self.rax if self.p.elf.bits == 64 else self.eax
        self.execute("ni") #Esci dalla funzione
        self.wait()
        restore_memory()
        return res

    #Can be used with signal code or name. Case insensitive.
    def signal(self, n, timeout):
        if type(n) is str:
            n = n.upper()
        self.execute(f"signal {n}")
        #sending signal will cause the process to resume his execution so we include the wait to make sure you don't forget
        self.wait(timeout)

    def close(self):
        try:
            self.execute("quit")
        except Exception:
            pass #quando muore gdb raisa EOF

    #Works only with GEF. I use them to avoid writing down print(self.execute("heap bins")) every time
    def bins(self):
        print(self.execute("heap bins"))

    def chunks(self):
        print(self.execute("heap chunks"))
        
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
        canary = self.read(canary_location, self.p.elf.bits//8)
        return b"\x00"+canary[1:]
        #taken from GEF
        #[+] The canary of process 17016 is at 0xff87768b, value is 0x2936a700
        #return int(self.execute("canary").split()[-1], 16)

    @property
    def registers(self):
        if self.p.elf.bits == 32:
            return ["eax", "ebx", "ecx", "edx", "edi", "esi"]
        elif self.p.elf.bits == 64:
            return ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        else:
            log.critical("Bits not known")

    @property
    def rax(self):
        return int(self.gdb.parse_and_eval("$rax"))

    @rax.setter
    def rax(self, value):
        self.execute(f"set $rax = {value}")
         
            
    @property
    def eax(self):
        return int(self.gdb.parse_and_eval("$eax"))

    @eax.setter
    def eax(self, value):
        self.execute(f"set $eax = {value}")
         
            
    @property
    def rbx(self):
        return int(self.gdb.parse_and_eval("$rbx"))

    @rbx.setter
    def rbx(self, value):
        self.execute(f"set $rbx = {value}")
         
            
    @property
    def ebx(self):
        return int(self.gdb.parse_and_eval("$ebx"))

    @ebx.setter
    def ebx(self, value):
        self.execute(f"set $ebx = {value}")
         
            
    @property
    def rcx(self):
        return int(self.gdb.parse_and_eval("$rcx"))

    @rcx.setter
    def rcx(self, value):
        self.execute(f"set $rcx = {value}")
         
            
    @property
    def ecx(self):
        return int(self.gdb.parse_and_eval("$ecx"))

    @ecx.setter
    def ecx(self, value):
        self.execute(f"set $ecx = {value}")
         
            
    @property
    def rdx(self):
        return int(self.gdb.parse_and_eval("$rdx"))

    @rdx.setter
    def rdx(self, value):
        self.execute(f"set $rdx = {value}")
         
            
    @property
    def edx(self):
        return int(self.gdb.parse_and_eval("$edx"))

    @edx.setter
    def edx(self, value):
        self.execute(f"set $edx = {value}")
         
            
    @property
    def rdi(self):
        return int(self.gdb.parse_and_eval("$rdi"))

    @rdi.setter
    def rdi(self, value):
        self.execute(f"set $rdi = {value}")
         
            
    @property
    def edi(self):
        return int(self.gdb.parse_and_eval("$edi"))

    @edi.setter
    def edi(self, value):
        self.execute(f"set $edi = {value}")
         
            
    @property
    def rsi(self):
        return int(self.gdb.parse_and_eval("$rsi"))

    @rsi.setter
    def rsi(self, value):
        self.execute(f"set $rsi = {value}")
         
            
    @property
    def esi(self):
        return int(self.gdb.parse_and_eval("$esi"))

    @esi.setter
    def esi(self, value):
        self.execute(f"set $esi = {value}")
         
            
    @property
    def rsp(self):
        return int(self.gdb.parse_and_eval("$rsp"))

    @rsp.setter
    def rsp(self, value):
        self.execute(f"set $rsp = {value}")
         
            
    @property
    def esp(self):
        return int(self.gdb.parse_and_eval("$esp"))

    @esp.setter
    def esp(self, value):
        self.execute(f"set $esp = {value}")
         
            
    @property
    def rbp(self):
        return int(self.gdb.parse_and_eval("$rbp"))

    @rbp.setter
    def rbp(self, value):
        self.execute(f"set $rbp = {value}")
         
            
    @property
    def ebp(self):
        return int(self.gdb.parse_and_eval("$ebp"))

    @ebp.setter
    def ebp(self, value):
        self.execute(f"set $ebp = {value}")
         
            
    @property
    def rip(self):
        return int(self.gdb.parse_and_eval("$rip"))

    @rip.setter
    def rip(self, value):
        self.execute(f"set $rip = {value}")
         
            
    @property
    def eip(self):
        return int(self.gdb.parse_and_eval("$eip"))

    @eip.setter
    def eip(self, value):
        self.execute(f"set $eip = {value}")
         
            
    @property
    def r8(self):
        return int(self.gdb.parse_and_eval("$r8"))

    @r8.setter
    def r8(self, value):
        self.execute(f"set $r8 = {value}")
         
            
    @property
    def r9(self):
        return int(self.gdb.parse_and_eval("$r9"))

    @r9.setter
    def r9(self, value):
        self.execute(f"set $r9 = {value}")
         
            
    @property
    def r10(self):
        return int(self.gdb.parse_and_eval("$r10"))

    @r10.setter
    def r10(self, value):
        self.execute(f"set $r10 = {value}")
         
            
    @property
    def r11(self):
        return int(self.gdb.parse_and_eval("$r11"))

    @r11.setter
    def r11(self, value):
        self.execute(f"set $r11 = {value}")
         
            
    @property
    def r12(self):
        return int(self.gdb.parse_and_eval("$r12"))

    @r12.setter
    def r12(self, value):
        self.execute(f"set $r12 = {value}")
         
            
    @property
    def r13(self):
        return int(self.gdb.parse_and_eval("$r13"))

    @r13.setter
    def r13(self, value):
        self.execute(f"set $r13 = {value}")
         
            
    @property
    def r14(self):
        return int(self.gdb.parse_and_eval("$r14"))

    @r14.setter
    def r14(self, value):
        self.execute(f"set $r14 = {value}")
         
            
    @property
    def r15(self):
        return int(self.gdb.parse_and_eval("$r15"))

    @r15.setter
    def r15(self, value):
        self.execute(f"set $r15 = {value}")

    #Generic stack and instruction pointers
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

    def push(self, value):
        self.sp -= self.p.elf.bits // 8
        self.write(self.sp, self.pbits(value))

    def pop(self):
        self.read(self.sp, self.p.elf.bits // 8)
        self.sp += self.p.elf.bits // 8
