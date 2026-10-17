from pwn import context, pack, unpack
from gdb_plus.utils.logger import DEBUG
from gdb_plus.utils.arch import function_calling_convention, syscall_calling_convention

class Fake_arguments:
    def __init__(self):
        pass

    def __getitem__(self, index: [int, slice]):
        #assert type(index) is int, "I can't handle slices to access multiple arguments"
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        return 0

    def __setitem__(self, index, value):
        pass

# Only works to read and set the arguments of the CURRENT function
class Arguments:
    def __init__(self, dbg):
        # Do we want to cache the registers and part of the stack ?
        # It would require to delete it when we execute an action
        self.dbg = dbg

    def __getitem__(self, index: [int, slice]):
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
    def __setitem__(self, index, value):
        if type(index) is slice:
            for i, el in zip(range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step), value):
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
    def __init__(self, dbg):
        self.dbg = dbg

    def __getitem__(self, index: [int, slice]):
        if type(index) is slice:
            return [self[i] for i in range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step)]
        calling_convention = syscall_calling_convention[context.arch][1:] # The first one would have been the sys_num
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            return getattr(self.dbg, register)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

    # How do we handle pushes ? Do I only write arguments when at the beginning of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    def __setitem__(self, index, value):
        if type(index) is slice:
            for i, el in zip(range(0 if index.start is None else index.start, -1 if index.stop is None else index.stop, 1 if index.step is None else index.step), value):
                self[i] = el
            return
        calling_convention = syscall_calling_convention[context.arch][1:]
        if index < len(calling_convention):
            register = calling_convention[index]
            if DEBUG: self.dbg.logger.debug(f"argument {index} is in register {register}")
            setattr(self.dbg, register, value)
        else:
            raise Exception(f"We don't have {index + 1} arguments in a syscall!")

    @property
    def sys_num(self) -> int:
        getattr(self.dbg, syscall_calling_convention[context.arch][0])

    @sys_num.setter
    def sys_num(self, value: int):
        setattr(self.dbg, syscall_calling_convention[context.arch][0], value)
    