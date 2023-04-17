# I just need the elf to know if I should use eip or rip... I may just do it this way if I don't have the binary
# Redundant with context. May be still used for path and address, but I would remove it.

from pwn import *
from threading import Event
from queue import Queue

class FakeELF:
    def __init__(self, bits):
        self.bits = bits
        self.bytes = self.bits // 8
        self.path = None
        self.address = 0
        #statically_linked ? always True ? # Needed to call malloc [02/03/23]

class user_regs_struct:
    def __init__(self):
        # I should use context maybe... At least you don't have suprises like me when pack breaks [02/03/23]
        self.registers = {64: ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_ax", "ip", "cs", "eflags", "sp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]}[context.bits]
        self.size = len(self.registers)*context.bytes

    def set(self, data):
        for i, register in enumerate(self.registers):
            setattr(self, register, unpack(data[i*context.bytes:(i+1)*context.bytes])) # I said I don't like unpack, but shhh [02/03/23]

    def get(self):
        data = b""
        for register in self.registers:
            value = getattr(self, register, 0)
            data += pack(value)
        return data

    def __repr__(self):
        return ", ".join([f"{register} = {hex(getattr(self, register))}" for register in self.registers])

    def __str__(self):
        return "\n".join([f"{register} = {hex(getattr(self, register))}" for register in self.registers])


# Only works to read and set the arguments of the CURRENT function
class Arguments:
    def __init__(self, dbg):
        self.dbg = dbg

    def __getitem__(self, index: int):
        assert type(index) is int, "I can't handle slices to access multiple arguments"
        self.dbg.restore_arch()
        if context.bits == 64:
            if index < 6:
                register = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][index]
                log.debug(f"argument {index} is in register {register}")
                return getattr(self.dbg, register)
            else:
                index -= 6
        if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
            pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
        elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
            pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
        else:
            pointer = self.dbg.base_pointer + (index + 2) * context.bytes
        return self.dbg.read(pointer, context.bytes)

    # How do we handle pushes ? Do I only write arguments when at the begining of the function and give up on using this property to load arguments before a call ?
    # Only valid for arguments already set
    def __setitem__(self, index, value):
        self.dbg.restore_arch()
        if context.bits == 64:
            if index < 6:
                register = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][index]
                return setattr(self.dbg, register)
            else:
                index -= 6
        if self.dbg.next_inst.toString() in ["endbr64", "push rbp", "push ebp"]:
            pointer = self.dbg.stack_pointer + (index + 1) * context.bytes
        elif self.dbg.next_inst.toString() in ["mov rbp, rsp", "mov ebp, esp"]:
            pointer = self.dbg.stack_pointer + (index + 2) * context.bytes
        else:
            pointer = self.dbg.base_pointer + (index + 2) * context.bytes
        return self.dbg.write(pointer, pack(value))

class MyEvent(Event):
    def __init__(self):
        super().__init__()
        self.cleared = Event()
        #self.secret = Event()
        self.priority = 0

    # I still need a standard wait for actions not initiated by dbg.cont and dbg.next
    def priority_wait(self):
        priority = self.priority
        log.debug(f"waiting with priority {priority}")
        while True:
            #super().wait()
            self.wait()
            if priority == self.priority:
                log.debug(f"priority {priority} met")
                self.priority -= 1
                break
            # If I call wait again while the event is set it won't block ! [04/04/23]
            self.cleared.wait()

    
    def clear(self):
        #self.secret.clear()
        if self.is_set():
            super().clear()
            self.cleared.set()