from gdb_plus import *
from os import kill
from time import sleep
from functools import partial
from capstone import Cs, CS_ARCH_X86
from gdb_plus.utils import Inner_Breakpoint

INT3 = b"\xcc"
constants.PTRACE_GETREGS = 0xc
constants.PTRACE_SETREGS = 0xd

# Only work if parent is tracing child (otherwise why would you need this class ?) and if the child is at a stop [02/03/23]
class Inner_Debugger:
    def __init__(self, dbg: Debugger, pid: int):
        self.dbg = dbg
        self.pid = pid
        self._mem_file = None # instead of opening it every time
        self.breakpoints = {}

        self.dbg.restore_arch()

    def get_regs(self):
        registers = user_regs_struct()
        pointer_registers = self.dbg.alloc(registers.size)
        res = self.dbg.call("ptrace", [constants.PTRACE_GETREGS, self.pid, 0, pointer_registers])
        assert res != 2**context.bits - 1
        #self.dbg.syscall(constants.SYS_ptrace, [constants.PTRACE_GETREGS, self.pid, 0, pointer_registers])
        registers.set(self.dbg.read(pointer_registers, registers.size))
        self.dbg.dealloc(pointer_registers)
        return registers

    def set_regs(self, registers):
        pointer_registers = self.dbg.alloc(registers.size)
        self.dbg.write(pointer_registers, registers.get())
        self.dbg.call("ptrace", [constants.PTRACE_SETREGS, self.pid, 0, pointer_registers])
        self.dbg.dealloc(pointer_registers)
        return registers

    def read_memory(self, addr, size) -> bytes:
        buffer = self.dbg.alloc(size)
        self.dbg.syscall(constants.SYS_lseek.real, [self.mem_file, addr, constants.SEEK_SET.real])
        self.dbg.syscall(constants.SYS_read.real, [self.mem_file, buffer, size])
        data = self.dbg.read(buffer, size)
        self.dbg.dealloc(buffer)
        return data
        
    read = read_memory

    # Maybe it's faster to write a single shellcode and execute that one
    def write_memory(self, addr: int, data: bytes):
        size = len(data)
        buffer = self.dbg.alloc(size)
        self.dbg.write(buffer, data)
        self.dbg.syscall(constants.SYS_lseek, [self.mem_file, addr, constants.SEEK_SET])
        self.dbg.syscall(constants.SYS_write, [self.mem_file, buffer, size])
        self.dbg.dealloc(buffer)
        
    write = write_memory

    # This part should be useless
    #def peek(self, address: int, small = True) -> bytes:
    #    log.debug(f"peeking {hex(address)}")
    #    data = pack(self.dbg.call("ptrace", [constants.PTRACE_PEEKDATA, self.pid, address, 0]))
    #    if not small:
    #        data += pack(self.dbg.call("ptrace", [constants.PTRACE_PEEKDATA, self.pid, address+self.dbg.elf.bytes, 0]))
    #    return data
    #    
    #def poke(self, address: int, data: bytes) -> None:
    #    log.debug(f"poking {hex(address)} -> {data}")
    #    pack(self.dbg.call("ptrace", [constants.PTRACE_POKEDATA, self.pid, address, unpack(data)]))
        
    def view_code(self, n=3) -> None:
        ip = self.instruction_pointer
        print("next instructions:")
        data = self.read_memory(ip, 7*n)
        for inst in self.capstone.disasm(data, ip):
            print(f"{hex(inst.address)}: {inst.mnemonic} {inst.op_str}")

    def view_stack(self, n=10) -> None:
        # Sarebbe da fare _disable e _enable dei breakpoint per non averli in mezzo
        sp = self.stack_pointer
        data = self.read_memory(sp, n*context.bytes)
        print("stack :")
        for i in range(n):
            print(f"{hex(sp)}: {hex(unpack(data[i*context.bytes:(i+1)*context.bytes]))}")
            sp += context.bytes

    # Per evitare chiamate ciclice provando a gestire i breakpoints
    def _cont(self, wait = False):
        self.dbg.call("ptrace", [constants.PTRACE_CONT, self.pid, 0, 0])
        if wait:
            self.wait()

    # Please, never ever put two breakpoints next to each others as a user (using next is fine) [03/03/23]
    def cont(self, *, wait=False, until=None) -> None:
        ip = self.instruction_pointer
        if until is not None:
            address = self.dbg.parse_address(until)
            self.b(address, temporary=True)
            wait = True
        # Attento a non fare riferimenti ciclici
        if ip in self.breakpoints:
            self.step()
        self._cont(wait)
        if until is not None and address != self.instruction_pointer:
            log.critical(f"couldn't reach address {hex(address)}. Stopped at address {hex(self.instruction_pointer)} instead")

    c = cont

    def interrupt(self) -> None:
        # PTRACE_INTERRUPT may not work
        #self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_INTERRUPT.real, self.pid, 0, 0])
        kill(self.pid, signal.SIGINT)
        self.wait() # Necessario ? [03/03/23]

    def _set_breakpoint(self, address, temporary=False):
        self.breakpoints[address] = Inner_Breakpoint(b"", temporary)
        self._restore_breakpoint(address)
    
    b = _set_breakpoint

    breakpoint = b

    def _restore_breakpoint(self, address):
        if address in self.breakpoints:
            byte = self.read_memory(address, 1)
            if byte == 0xcc:
                print("breakpoint already present")
            self.breakpoints[address].byte = byte
            self.write_memory(address, INT3)


    def _disable_breakpoint(self, address):
        if address in self.breakpoints:
            self.write_memory(address, self.breakpoints[address].byte)
    
    def _disable_breakpoints(self):
        for address, breakpoint in self.breakpoints.items():
            self.write_memory(address, breakpoint.byte)

    def _enable_breakpoints(self):
        for address, breakpoint in self.breakpoints.items():
            byte = self.read_memory(address, 1)
            if byte != INT3:
                breakpoint.byte = byte
    # No need to emulate jumps. Ptrace can do it
    def step(self):
        constants.PTRACE_SINGLESTEP = 0x9
        ip = self.instruction_pointer
        self._disable_breakpoint(ip)
        self.dbg.call("ptrace", [constants.PTRACE_SINGLESTEP, self.pid, 0, 0])
        self.wait()
        self._restore_breakpoint(ip)

    def next(self):
        ip = self.instruction_pointer
        inst = self.next_inst
        if inst.mnemonic == "call":
            self._disable_breakpoint(ip)
            self.cont(until=ip + inst.size)
            self._restore_breakpoint(ip)
        else:
            self.step()

    def wait(self):
        status_pointer = self.dbg.alloc(4)
        self.dbg.call("waitpid", [self.pid, status_pointer, 0x40000000, 0])
        # be carefull that INT3 is executed as an instruction! You have to back down
        
        log.debug(f"wait finished with status: {hex(u32(self.dbg.read(status_pointer, 4)))}")
        self.dbg.dealloc(status_pointer)
        
        ip = self.instruction_pointer - 1
        breakpoint = self.breakpoints.get(ip)
        
        if breakpoint is None:
            return

        self.instruction_pointer = ip

        if breakpoint.temporary:
            self._disable_breakpoint(ip)
            del self.breakpoints[ip]

    def detach(self):
        self.dbg.call("ptrace", [constants.PTRACE_DETACH, self.pid, 0, 0])

    @property
    def next_inst(self):
        ip = self.instruction_pointer # avoid calling it twice
        inst = next(self.capstone.disasm(self.read_memory(ip, 16), ip))
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        return inst

    # Find a way to cache registers while you don't move [21/04/23] but be carefull if the parent uses SETREGS
    @property
    def registers(self):
        return self.get_regs()

    @registers.setter
    def registers(self, registers: user_regs_struct):
        self.set_regs(registers)

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
        if context.bits == 32:
            ans = self.eip
        else:
            ans = self.rip
        return ans

    @instruction_pointer.setter
    def instruction_pointer(self, value):
        if context.bits == 32:
            self.eip = value
        else:
            self.rip = value

    @property
    def capstone(self):
        if self.dbg._capstone is None:
            self.dbg._capstone = Cs(CS_ARCH_X86, context.bytes)
        return self.dbg._capstone

    @property
    def mem_file(self):
        if self._mem_file is None: # I wait to know how to move back and forth in the file [02/03/23] There are no problems, even if the data changes ! [03/03/23]
            if "open" in self.dbg.symbols:
                self._mem_file = self.dbg.call("open", [f"/proc/{self.pid}/mem".encode(), constants.O_RDWR])
            else: 
                self._mem_file = self.dbg.syscall(constants.SYS_open, [f"/proc/{self.pid}/mem".encode(), constants.O_RDWR])
        return self._mem_file

    def __getattr__(self, name):
    
        if name in ["dbg"]: #If __getattr__ is called with dbg it means I haven't finished initializing the class so I shouldn't call self.registers in __setattr__
            return False
        
        if name in self.dbg.special_registers + self.dbg.registers:
            return getattr(self.registers, name)

        else:
            # Get better errors when can't resolve properties
            self.__getattribute__(name)

    def __setattr__(self, name, value):
        if self.dbg and name in self.dbg.special_registers + self.dbg.registers:
            registers = self.registers
            setattr(registers, name, value)
            self.registers = registers
        else:
            super().__setattr__(name, value)