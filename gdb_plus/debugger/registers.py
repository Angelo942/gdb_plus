from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_RISCV, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN
# Migrate to capstone v6, but keep support for v5
try:
    from capstone import CS_ARCH_AARCH64
except ImportError:
    from capstone import CS_ARCH_ARM64
    CS_ARCH_AARCH64 = CS_ARCH_ARM64
from pwn import context, log, unpack

from gdb_plus.utils import DEBUG, Fake_arguments, Arguments, Arguments_syscall, is_call, call_return_address
from gdb_plus.debugger._base import DebuggerBase, DEBUG_OFF, IMPORTANT_DEBUG_OFF, context_decorator

if TYPE_CHECKING:
    from typing import Iterator
    from capstone import CsInsn

class RegistersMixin(DebuggerBase):
    """
    Registers by role (instruction_pointer, stack_pointer, base_pointer, return_value, return_pointer), the register
    tables of each architecture, function and syscall arguments (args, syscall_args), backup / restore_backup, and
    the current instruction (next_inst, disassemble). A register by name (dbg.rax) goes through Debugger.__getattr__
    / __setattr__.
    """
    # Since reset doesn't work
    # Could be expanded with memory regions
    def backup(self) -> list[int] | None:
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

        
    def restore_backup(self, backup: list[int]) -> None:
        """
        Reset the state of all registers from a given backup
        """
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        for name, value in zip(self._special_registers + self._registers, backup):
                setattr(self, name, value)

        
    @property
    def args(self) -> Arguments | Fake_arguments:
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
    def syscall_args(self) -> Arguments_syscall | Fake_arguments:
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

    @property
    def sys_num(self) -> int:
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return 0
        return self.syscall_args.sys_num

    @sys_num.setter
    def sys_num(self, value: int):
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return
        self.syscall_args.sys_num = value

     
    @property
    @context_decorator
    def _special_registers(self) -> list[str]:
        if context.arch == "i386":
            return ["eflags", "cs", "ss", "ds", "es", "fs", "gs", "orig_eax"]
        elif context.arch == "amd64":
            return ["eflags", "cs", "ss", "ds", "es", "fs", "gs", "orig_rax"]
        elif context.arch == "aarch64":
            return ["cpsr", "fpsr", "fpcr"] # "vg" is is not always present. Only for SVE
        elif context.arch == "arm":
            return ["cpsr"]
        elif context.arch in ["riscv32", "riscv64"]:
            return []
        elif context.arch in ["mips", "mips64"]:
            return ["hi", "lo", "at"]
        else:
            raise Exception(f"what arch is {context.arch}")

    # WARNING reset expects the last two registers to be sp and ip. backup expects the last register to be ip
    @property
    @context_decorator
    def _registers(self) -> list[str]:
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
        elif context.arch == "mips64":
            return [f"v{i}" for i in range(2)] + [f"a{i}" for i in range(8)] + [f"t{i}" for i in range(4)] + [f"s{i}" for i in range(8)] + [f"k{i}" for i in range(2)] + ["ra", "gp", "fp", "sp"] + ["pc"]
        else:
            raise Exception(f"what arch is {context.arch}")

    # Making ax accessible will probably be faster that having to write 
    @property
    @context_decorator
    def _minor_registers(self) -> list[str]:
        if context.arch == "aarch64":
            return [f"w{x}" for x in range(31)]
        elif context.arch == "arm":
            return [] # Arm can not access 16bits or less in a register
        elif context.arch == "i386":    
            return ["ax", "al", "ah",
        "bx", "bh", "bl",
        "cx", "ch", "cl",
        "dx", "dh", "dl",
        "si", "sil",
        "di", "dil",
        "sp", "spl",
        "bp", "bpl"]
        elif context.arch == "amd64":
            return ["ax", "al", "ah",
        "bx", "bh", "bl",
        "cx", "ch", "cl",
        "dx", "dh", "dl",
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
        elif context.arch in ["mips", "mips64"]:
            return []
        else:
            raise Exception(f"what arch is {context.arch}")

    # We should add a new type of registers for aliases so that the user can access them, but we don't duplicate them when doing backups. 
    # Would also be useful to access floating points [21/01/25]
    @property
    @context_decorator
    def _long_registers(self) -> list[str]:
        if context.arch == "amd64":
            return [f"xmm{i}" for i in range(32)]
        else:
            return []

    @property
    @context_decorator
    def next_inst(self) -> CsInsn: # CsInsn with toString and is_call added
        inst = next(self.disassemble(self.instruction_pointer, 16)) #15 bytes is the maximum size for an instruction in x64
        inst.toString = partial(lambda self: f"{self.mnemonic} {self.op_str}".strip(), inst)
        inst.is_call = is_call(inst, context.arch)
        inst.return_address = call_return_address(inst, context.arch)
        return inst

    # May be useful for Inner_Debugger
    # BUG capstone v5, Risky Business start function. disassemble(ip, 1000) will stop after 4 instructions
    @context_decorator
    def disassemble(self, address: int, size: int) -> Iterator[CsInsn]:
        endian = CS_MODE_BIG_ENDIAN if context.endian == "big" else CS_MODE_LITTLE_ENDIAN
        if self._capstone is None:
            if context.arch == "amd64":
                self._capstone = Cs(CS_ARCH_X86, CS_MODE_64)
            elif context.arch == "i386":
                self._capstone = Cs(CS_ARCH_X86, CS_MODE_32)
            elif context.arch == "aarch64":
                self._capstone = Cs(CS_ARCH_AARCH64, CS_MODE_ARM)
            elif context.arch == "arm":
                self._capstone = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif context.arch == "riscv32":
                self._capstone = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC) # CS_MODE_RISCVC is needed for 16 bits instructions
            elif context.arch == "riscv64":
                self._capstone = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC) 
            elif context.arch == "mips":
                self._capstone = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + endian)
            elif context.arch == "mips64":
                self._capstone = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + endian)
            else:
                raise Exception(f"what arch is {context.arch}")
            self._capstone.detail = True

        return self._capstone.disasm(self.read(address, size), address)

    @property
    @context_decorator
    def return_value(self) -> int:
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
        elif context.arch in ["mips", "mips64"]:
            return self.v0
        else:
            raise NotImplementedError(f"return_value is not implemented for the given architecture")

    @return_value.setter
    @context_decorator
    def return_value(self, value: int) -> None:
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
        elif context.arch in ["mips", "mips64"]:
            self.v0 = value
        else:
            raise NotImplementedError(f"return_value is not implemented for the given architecture")

    @property
    @context_decorator
    def stack_pointer(self) -> int:
        if context.arch == "amd64":
            return self.rsp
        elif context.arch == "i386":
            return self.esp
        elif context.arch in ["arm", "aarch64"]:
            return self.sp
        elif context.arch in ["riscv32", "riscv64"]:
            return self.sp
        elif context.arch in ["mips", "mips64"]:
            return self.sp
        else:
            raise NotImplementedError(f"stack_pointer is not implemented for the given architecture")

    # issue: setting $sp is not allowed when other stack frames are selected... https://sourceware.org/gdb/onlinedocs/gdb/Registers.html [04/03/23]
    @stack_pointer.setter
    @context_decorator
    def stack_pointer(self, value: int) -> None:
        if not self.debugging:
            log.warn_once(DEBUG_OFF)
            return

        # May move this line to push and pop if someone can argue a good reason to.
        if context.arch == "amd64":
            self.rsp = value
        elif context.arch == "i386":
            self.esp = value
        elif context.arch in ["arm", "aarch64"]:
            self.sp = value
        elif context.arch in ["riscv32", "riscv64"]:
            self.sp = value
        elif context.arch in ["mips", "mips64"]:
            self.sp = value
        else:
            raise NotImplementedError(f"stack_pointer is not implemented for the given architecture")
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
            elif context.arch in ["mips", "mips64"]:
                self.sp = value
            else:
                raise NotImplementedError(f"stack_pointer is not implemented for the given architecture")

    @property
    @context_decorator
    def base_pointer(self) -> int:
        if context.arch == "amd64":
            return self.rbp
        elif context.arch == "i386":
            return self.ebp
        elif context.arch == "arm":
            return self.fp
        elif context.arch == "aarch64":
            return self.x29
        elif context.arch in ["riscv32", "riscv64"]:
            raise NotImplementedError(f"base_pointer is not implemented for the given architecture")
        elif context.arch in ["mips", "mips64"]:
            return self.fp
        else:
            raise NotImplementedError(f"base_pointer is not implemented for the given architecture")

    
    @base_pointer.setter
    @context_decorator
    def base_pointer(self, value: int) -> None:
        if context.arch == "amd64":
            self.rbp = value
        elif context.arch == "i386":
            self.ebp = value
        elif context.arch == "arm":
            self.fp = value
        elif context.arch == "aarch64":
            self.x29 = value
        elif context.arch in ["riscv32", "riscv64"]:
            raise NotImplementedError(f"base_pointer is not implemented for the given architecture")
        elif context.arch in ["mips", "mips64"]:
            self.fp = value
        else:
            raise NotImplementedError(f"base_pointer is not implemented for the given architecture")

    # Prevent null pointers
    @property
    @context_decorator
    def instruction_pointer(self) -> int:
        ans = 0
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
            elif context.arch in ["mips", "mips64"]:
                ans = self.pc
            else:
                raise NotImplementedError(f"instruction_pointer is not implemented for the given architecture")
            
            if ans == 0:
                log.warn("null pointer in ip ! retrying...")
            else:
                break        
        return ans

    @instruction_pointer.setter
    @context_decorator
    def instruction_pointer(self, value: int) -> None:
        if context.arch == "amd64":
            self.rip = value
        elif context.arch == "i386":
            self.eip = value
        elif context.arch in ["arm", "aarch64"]:
            self.pc = value
        elif context.arch in ["riscv32", "riscv64"]:
            self.pc = value
        elif context.arch in ["mips", "mips64"]:
            self.pc = value
        else:
            raise NotImplementedError(f"instruction_pointer is not implemented for the given architecture")

    @context_decorator
    def _find_rip(self) -> int:
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
    @context_decorator
    def _saved_ip(self) -> int:
        link_register = {"aarch64": "x30", "riscv32": "ra", "riscv64": "ra", "mips": "ra", "mips64": "ra"}.get(context.arch)

        # Doesn't work with qemu [05/07/23]
        # But trust it first before assuming anything
        return self._backend.saved_ip(link_register)

        ## rip = 0x7ffff7fe45b8 in _dl_start_final (./elf/rtld.c:507); saved rip = 0x7ffff7fe32b8
        #data = self.execute("info frame 0").splitlines()
        #log.debug(data)
        #for line in data:
        #    if " saved " in line and "ip = " in line:
        #        ip = line.split("saved ")[-1].split("= ")[-1]
        #        if "<" in ip:
        #            return 0
        #        return int(ip, 16)

    @property
    def return_pointer(self) -> int:
        if not self.debugging:
            log.warn_once(IMPORTANT_DEBUG_OFF)
            return 0
        return self._saved_ip
