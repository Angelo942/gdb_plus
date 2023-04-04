from gdb_plus import *
from os import kill
from time import sleep
from functools import partial
from capstone import Cs, CS_ARCH_X86

INT3 = b"\xcc"

# Only work if parent is tracing child (otherwise why would you need this class ?) and if the child is at a stop [02/03/23]
class Inner_Debugger:
    def __init__(self, dbg: Debugger, pid: int):
        #self.gdb = dbg.gdb
        self.dbg = dbg
        self.pid = pid
        #self.elf = dbg.elf
        self._mem_file = None # instead of opening it every time
        self.breakpoints = {}
        self.temporary_breakpoints = {}

    def read_registers(self):
        registers = user_regs_struct()
        pointer_registers = self.dbg.alloc(registers.size)
        #self.dbg.call(dbg.elf.symbols["ptrace"], [constants.PTRACE_GETREGS.real, pid, 0, pointer_registers])
        self.dbg.call(self.dbg.symbols["ptrace"], [0xc, self.pid, 0, pointer_registers])
        registers.set(self.dbg.read(pointer_registers, registers.size))
        return registers

    # Potrei anche fare injection di shellcode se non trovo le funzioni di libc...
    def read_memory(self, addr, size) -> bytes:
        # I was gonna use ptrace POKEDATA and PEEKDATA, but oper should be faster if I can find the functions
        #if self.dbg.elf.statically_linked:
        if "open" in self.dbg.symbols and "read" in self.dbg.symbols and "lseek" in self.dbg.symbols and "close" in self.dbg.symbols:
            buffer = self.dbg.alloc(size)
            self.dbg.call(self.dbg.symbols["lseek"], [self.mem_file, addr, constants.SEEK_SET.real]) # How do I reset to the begining of the file ? [02/03/23]
            self.dbg.call(self.dbg.symbols["read"], [self.mem_file, buffer, size])
            data = self.dbg.read(buffer, size)
            self.dbg.dealloc(buffer)
            return data
        elif "_syscall" in self.dbg.symbols:
            buffer = self.dbg.alloc(size)
            self.dbg.syscall(constants.SYS_lseek.real, [self.mem_file, addr, constants.SEEK_SET.real])
            self.dbg.syscall(constants.SYS_read.real, [self.mem_file, buffer, size])
            data = self.dbg.read(buffer, size)
            self.dbg.dealloc(buffer)
            return data
        else:
            log.warn_once("reading with PEEKDATA because I can't find funtions open/read/close/lseek. This is slow. If possible include these functions in elf.symbols or at least a syscall gadget in symbols[\"_syscall\"]")
            data = b""
            for i in range(0, size, context.bytes):
                data += self.peek(addr+i)
            return data[:size]
        #else:
        #    raise Ecxeption("optimisation libc not implemented yet")

    read = read_memory

    def write_memory(self, addr: int, data: bytes):
        # I was gonna use ptrace POKEDATA and PEEKDATA, but oper should be faster if I can find the functions
        size = len(data)
        #if self.dbg.elf.statically_linked:
        if "open" in self.dbg.symbols and "write" in self.dbg.symbols and "lseek" in self.dbg.symbols and "close" in self.dbg.symbols:
            buffer = self.dbg.alloc(size)
            self.dbg.write(buffer, data)
            self.dbg.call(self.dbg.symbols["lseek"], [self.mem_file, addr, constants.SEEK_SET.real]) # How do I reset to the begining of the file ? [02/03/23]
            self.dbg.call(self.dbg.symbols["write"], [self.mem_file, buffer, size])
            self.dbg.dealloc(buffer)
        elif "_syscall" in self.dbg.symbols:
            buffer = self.dbg.alloc(size)
            self.dbg.write(buffer, data)
            self.dbg.syscall(constants.SYS_lseek.real, [self.mem_file, addr, constants.SEEK_SET.real])
            self.dbg.syscall(constants.SYS_write.real, [self.mem_file, buffer, size])
            self.dbg.dealloc(buffer)
        else:
            log.warn_once("writing with POKEDATA because I can't find funtions open/read/close/lseek. This is slow. If possible include these functions in elf.symbols or at least a syscall gadget in symbols[\"_syscall\"]")
            ... # Still to be implemented
            data = b""
            for i in range(0, size, context.bytes):
                data += self.poke(addr+i, data[i*context.bytes:(i+1)*context.bytes])
        #else:
        #    raise Ecxeption("optimisation libc not implemented yet")

    write = write_memory

    # Magari voglio assicurarmi di avere almeno max(len(inst)) come size... [02/03/23]
    def peek(self, address: int, small = True) -> bytes:
        log.debug(f"peeking {hex(address)}")
        data = pack(self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_PEEKDATA.real, self.pid, address, 0]))
        if not small:
            data += pack(self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_PEEKDATA.real, self.pid, address+self.dbg.elf.bytes, 0]))
        return data

    def poke(self, address: int, data: bytes) -> None:
        log.debug(f"poking {hex(address)} -> {data}")
        pack(self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_POKEDATA.real, self.pid, address, unpack(data)]))
        
    def view_code(self, n=3) -> None:
        ip = self.registers.ip
        print("next instructions:")
        data = self.read_memory(ip, 7*n)
        for inst in self.capstone.disasm(data, ip):
            print(f"{hex(inst.address)}: {inst.mnemonic} {inst.op_str}")

    def view_stack(self, n=10) -> None:
        sp = self.registers.sp
        data = self.read_memory(sp, n*context.bytes)
        print("stack :")
        for i in range(n):
            print(f"{hex(sp)}: {hex(unpack(data[i*context.bytes:(i+1)*context.bytes]))}")
            sp += context.bytes

    # Per evitare chiamate ciclice provando a gestire i breakpoints
    def _cont(self, wait = False):
        self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_CONT.real, self.pid, 0, 0])
        if wait:
            self.wait()

    # Please, never ever put two breakpoints next to each others as a user (using next is fine) [03/03/23]
    def cont(self) -> None:
        # Attento a non fare riferimenti ciclici
        if (ip := self.registers.ip) in self.breakpoints:
            self.restore_breakpoint(ip)
            self.step()
            self.set_breakpoint(ip)
        self._cont()

    def interrupt(self) -> None:
        # Mi sa che ho capito male come funziona PTRACE_INTERRUPT
        #self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_INTERRUPT.real, self.pid, 0, 0])
        kill(self.pid, signal.SIGINT)
        self.wait() # Necessario ? [03/03/23]

    def set_breakpoint(self, address, temporary=False):
        log.critical("I don't know yet what to do once I hit a breakpoint to go back 1 instruction")
        #data = u64(self.peek(address))
        #byte = data % 0x100     
        byte = self.read_memory(address, 1)
        if byte == 0xcc:
            print("breakpoint already present")
        #    return None
        #self.poke(address, pack(data - byte + 0xcc))
        self.write_memory(address, b"\xcc")
        if temporary:
            self.temporary_breakpoints[address] = byte
        else:
            self.breakpoints[address] = byte

    b = set_breakpoint

    def restore_breakpoint(self, address):
        #data = u64(self.peek(address))
        #byte = data % 0x100
        #assert byte == 0xcc
        #self.poke(address, pack(data - byte + {**self.breakpoints, **self.temporary_breakpoints}[address]))
        self.write_memory(address, {**self.breakpoints, **self.temporary_breakpoints}[address])
        # Should also do ip -= 1

    # No need to emulate jumps. Ptrace can do it
    def step(self):
        constants.PTRACE_SINGLESTEP = 0x9
        self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_SINGLESTEP, self.pid, 0, 0])
        self.wait()

    def next(self):
        ip = self.registers.ip
        inst = self.next_inst
        if inst.mnemonic == "call":
            pointer = ip + inst.size
            self.set_breakpoint(pointer, temporary=True)
            self._cont()
            self.wait() # I will have to think about how to implement it, but for 1 instruction (fuck there are the function calls too)... [02/03/23]
            self.restore_breakpoint(pointer)
        else:
            self.step()
        

        #if gef.arch.is_conditional_branch(insn):
        #is_taken, reason = gef.arch.is_branch_taken(insn)
        #if 
        #else:
        #    
        #data = unpack(self.peek(pointer))

    def wait(self):
        status_pointer = self.dbg.alloc(4)
        self.dbg.call(self.dbg.symbols["waitpid"], [self.pid, status_pointer, 0x40000000, 0])
        # be carefull that INT3 is executed as an instruction! You have to back down
        if (ip := self.registers.ip - 1) in self.temporary_breakpoints:
            self.restore_breakpoint(ip)
            del self.temporary_breakpoints[ip]

        elif ip in self.breakpoints:
            log.info(f"breakpoint {self.breakpoints.index(ip)} ({hex(ip)}) hit") # Will become log.debug later [03/03/23]
            self.restore_breakpoint(ip)

        log.debug(f"wait finished with status: {hex(u32(self.dbg.read(status_pointer, 4)))}")
        self.dbg.dealloc(status_pointer)

    def detach(self):
        self.dbg.call(self.dbg.symbols["ptrace"], [constants.PTRACE_DETACH.real, self.pid, 0, 0])

    @property
    def next_inst(self):
        ip = self.registers.ip # avoid calling it twice
        inst = next(self.capstone.disasm(self.peek(ip), ip))
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        return inst

    @property
    def registers(self):
        return self.read_registers()

    @property
    def capstone(self):
        if self.dbg._capstone is None:
            self.dbg._capstone = Cs(CS_ARCH_X86, self.dbg.elf.bytes)
        return self.dbg._capstone

    @property
    def mem_file(self):
        if self._mem_file is None: # I wait to know how to move back and forth in the file [02/03/23] There are no problems, even if the data changes ! [03/03/23]
            if "open" in self.dbg.symbols:
                self._mem_file = self.dbg.call(self.dbg.symbols["open"], [f"/proc/{self.pid}/mem".encode(), constants.O_RDWR.real])
            elif "_syscall" in self.dbg.symbols: 
                self._mem_file = self.dbg.syscall(constants.SYS_open.real, [f"/proc/{self.pid}/mem".encode(), constants.O_RDWR.real])
            else:
                raise("can't open file. No symbol open or syscall saved")
        return self._mem_file