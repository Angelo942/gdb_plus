from __future__ import annotations
from typing import TYPE_CHECKING, cast, overload
from pwn import context, pack, unpack
from gdb_plus.utils.logger import DEBUG

if TYPE_CHECKING:
    from typing import Iterable
    from gdb_plus.debugger import Debugger

# First register is where to save the syscall num
syscall_calling_convention: dict[str, list[str]] = {
    "amd64": ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
    "i386": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
    "aarch64": ["x8"]+[f"x{i}"for i in range(6)],
    "arm": ["r7"]+[f"r{i}"for i in range(6)],
    "riscv32": ["a7"]+[f"a{i}"for i in range(6)],
    "riscv64": ["a7"]+[f"a{i}"for i in range(6)],
    "mips": ["v0"] + [f"a{i}" for i in range(4)],
    "mips64": ["v0"] + [f"a{i}" for i in range(6)],
}
function_calling_convention: dict[str, list[str]] = {
    "amd64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
    "i386": [],
    "aarch64": [f"x{i}"for i in range(8)],
    "arm": [f"r{i}"for i in range(4)],
    "riscv32": [f"a{i}"for i in range(8)],
    "riscv64": [f"a{i}"for i in range(8)],
    "mips": [f"a{i}" for i in range(4)],
    "mips64": [f"a{i}" for i in range(6)],
}

class Fake_arguments:
    def __init__(self) -> None:
        pass

    @overload
    def __getitem__(self, index: int) -> int: ...
    @overload
    def __getitem__(self, index: slice) -> list[int]: ...
    def __getitem__(self, index: int | slice) -> int | list[int]:
        #assert type(index) is int, "I can't handle slices to access multiple arguments"
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        return 0

    @overload
    def __setitem__(self, index: int, value: int) -> None: ...
    @overload
    def __setitem__(self, index: slice, value: Iterable[int]) -> None: ...
    def __setitem__(self, index: int | slice, value: int | Iterable[int]) -> None:
        pass

# Only works to read and set the arguments of the CURRENT function
class Arguments:
    def __init__(self, dbg: Debugger) -> None:
        # Do we want to cache the registers and part of the stack ?
        # It would require to delete it when we execute an action
        self.dbg = dbg

    @overload
    def __getitem__(self, index: int) -> int: ...
    @overload
    def __getitem__(self, index: slice) -> list[int]: ...
    def __getitem__(self, index: int | slice) -> int | list[int]:
        #assert type(index) is int, "I can't handle slices to access multiple arguments"
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            index -= len(calling_convention)
        # It would be better to force the user to save the arguments at the entry point and read them later instead... [25/07/23]
        if context.arch in ["amd64", "i386"]:
            if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
                pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
            elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
            else:
                pointer = self.dbg.base_pointer + (index + 2) * context.bytes
            return unpack(self.dbg.read(pointer, context.bytes))
        elif context.arch in ["arm", "aarch64"]:
            pointer = self.dbg.stack_pointer + index * context.bytes
            return unpack(self.dbg.read(pointer, context.bytes))


    # How do we handle pushes ? Do I only write arguments when at the beginning of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    @overload
    def __setitem__(self, index: int, value: int) -> None: ...
    @overload
    def __setitem__(self, index: slice, value: Iterable[int]) -> None: ...
    def __setitem__(self, index: int | slice, value: int | Iterable[int]) -> None:
        if type(index) is slice:
            for i, el in zip(range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step), cast("Iterable[int]", value)):
                self[i] = el
            return
        calling_convention = function_calling_convention[context.arch]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return setattr(self.dbg, register, value)
        else:
            index -= len(calling_convention)
        if context.arch in ["amd64", "i386"]:
            if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
                pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
            elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
                pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
            else:
                pointer = self.dbg.base_pointer + (index + 2) * context.bytes
            self.dbg.write(pointer, pack(value))
        elif context.arch in ["arm", "aarch64"]:
            pointer = self.dbg.stack_pointer + index * context.bytes
            self.dbg.write(pointer, pack(value))

class Arguments_syscall:
    def __init__(self, dbg: Debugger) -> None:
        self.dbg = dbg

    @overload
    def __getitem__(self, index: int) -> int: ...
    @overload
    def __getitem__(self, index: slice) -> list[int]: ...
    def __getitem__(self, index: int | slice) -> int | list[int]:
        if type(index) is slice:
            # An open-ended slice stops at the last argument register
            n_args = len(syscall_calling_convention[context.arch]) - 1
            return [self[i] for i in range(0 if index.start is None else index.start, n_args if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        calling_convention = syscall_calling_convention[context.arch][1:] # The first one would have been the sys_num
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

    # How do we handle pushes ? Do I only write arguments when at the beginning of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    @overload
    def __setitem__(self, index: int, value: int) -> None: ...
    @overload
    def __setitem__(self, index: slice, value: Iterable[int]) -> None: ...
    def __setitem__(self, index: int | slice, value: int | Iterable[int]) -> None:
        if type(index) is slice:
            n_args = len(syscall_calling_convention[context.arch]) - 1
            for i, el in zip(range(0 if index.start is None else index.start, n_args if index.stop is None else index.stop, 1 if index.step is None else index.step), cast("Iterable[int]", value)):
                self[i] = el
            return
        calling_convention = syscall_calling_convention[context.arch][1:]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            setattr(self.dbg, register, value)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

    @staticmethod
    def _in_syscall(debugger: Debugger) -> bool:
        """
        True if the process stopped inside a syscall: entry or exit catchpoint, step out of a syscall, interrupted while blocked in one.
        False if the syscall instruction has not been executed yet.
        Only x86 needs it: the other architectures keep the number in the same register for the whole syscall.
        """
        if context.arch not in ["amd64", "i386"]:
            return False
        mask = (1 << context.bits) - 1
        orig = debugger.orig_rax if context.arch == "amd64" else debugger.orig_eax
        # The kernel sets orig_*ax to -1 on every stop that doesn't come from a syscall (breakpoint, step, jump...)
        if orig & mask == mask:
            return False
        # orig_*ax survives the step out of a syscall: back on a syscall instruction means the next one hasn't run yet
        # syscall, int 0x80, sysenter (i386 vdso)
        return debugger.safe_read(debugger.instruction_pointer, 2) not in [b"\x0f\x05", b"\xcd\x80", b"\x0f\x34"]

    @property
    def sys_num(self) -> int:
        reg = syscall_calling_convention[context.arch][0]
        if context.arch in ["amd64", "i386"]:
            if self._in_syscall(self.dbg):
                reg = "orig_" + reg
        return getattr(self.dbg, reg)

    @sys_num.setter
    def sys_num(self, value: int) -> None:
        reg = syscall_calling_convention[context.arch][0]
        if context.arch in ["amd64", "i386"]:
            if self._in_syscall(self.dbg):
                reg = "orig_" + reg
        setattr(self.dbg, reg, value)
    