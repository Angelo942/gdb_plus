from pwn import *
from os import kill

#You don't have to interrupt the process to set breakpointes or access and overwrite the memory. Only for the registers

class Debugger:
    def __init__(self, target, env={}, aslr=True, script=None, from_start=False):
        self.stopped = False
        self._auxiliary_vector = None #only used to locate the canary
        #gdb.debug() was rulled out previously due to two bugs with older version of gdbserver used in ubuntu 20.04
        #1) gdbserver crashes trying to locate the canary (at least with 32 bit binaries) -> patched in gdbserver 11.0.50 (working in ubuntu 22.04)
        #2) LD_PRELOAD uses the library for gdbserver and not the process -> solved in ubuntu 22.04 too
        
        #Pwntools allows you to use NOPTRACE if you wan't to skip the attach so I keep the logic here
        if not context.noptrace:
            if from_start:
                self.p = gdb.debug(target, env=env, gdbscript=script, api=True)
                self.gdb = self.p.gdb
            else:
                self.p = process(target, env=env, aslr=aslr)
                _, self.gdb = gdb.attach(self.p, gdbscript=script, api=True)
            #inferior to easily access memory
            self.inferior = self.gdb.inferiors()[0]
        else:
            self.p = process(target, env=env, aslr=aslr)
                
        
    #You have to remember you can not send commands to gdb while the process is running
    #pseudo-timeout for backward compatibility
    def wait(self, timeout=1):
        if timeout != 0:
            self.gdb.wait()

    #get base address of libc
    def get_base_libc(self):
        data = self.execute("info files")
        for line in data.split("\n"):
            line = line.strip()
            if "libc" in line and line.startswith("0x"):
                address = int(line.split()[0], 16)
                return address - address%0x1000

    #get base address of binary
    def get_base_elf(self):
        data = self.execute("info files")
        for line in data.split("\n"):
            line = line.strip()
            if line.startswith("Entry point:"):
                address = int(line.split()[-1], 16)
                return address - address%0x1000
        
    #temporarely interrupt the execution of our process to get back control of gdb (equivalent of a manual ctrl+C)
    #don't worry about the "kill" 
    def interrupt(self):
        kill(self.p.pid, signal.SIGINT)
        #"Cannot execute *this* command while the selected thread is running" The problem is not about 'execute' by itself
        #self.execute("interrupt") #pwntools uses this command, but I don't because it may not work if the continue command has been sent manualy in gdb
        self.wait()

    manual = interrupt
        
    def alloc(self, n):
        pointer = self.execute(f"call (long) malloc({n})").split()[-1]
        return int(pointer, 16)

    def read(self, address: int, size: int):
        return self.inferior.read_memory(address, size).tobytes()
        
    def write(self, pointer, byte_array):
        self.inferior.write_memory(pointer, byte_array)

    def execute(self, code: str):
        return self.gdb.execute(code, to_string=True)
    
    def b(self, address, temporary=False):
        if type(address) is int:
            address = f"*{hex(address)}"
        res = self.gdb.Breakpoint(address, temporary=temporary)
        #Still don't know if and where I should save them... Let's just return it for now even if I never used it so far
        return res
        
    breakpoint = b
    
    #timeout for backward compatibility
    def c(self, timeout=0):
        self.execute("continue")
        self.wait(timeout) #timeout = 0 if you do not want to wait
    
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
