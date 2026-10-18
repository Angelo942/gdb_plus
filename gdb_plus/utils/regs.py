from __future__ import annotations
from pwn import context, pack, unpack

# Only support amd64
class user_regs_struct:
    def __init__(self) -> None:
        # I should use context maybe... At least you don't have surprises like me when pack breaks [02/03/23]
        self.registers: list[str] = {64: ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_ax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]}[context.bits]
        self.size: int = len(self.registers)*context.bytes

    def set(self, data: bytes) -> user_regs_struct:
        for i, register in enumerate(self.registers):
            setattr(self, register, unpack(data[i*context.bytes:(i+1)*context.bytes])) # I said I don't like unpack, but shhh [02/03/23]
        return self

    def get(self) -> bytes:
        data = b""
        for register in self.registers:
            value = getattr(self, register, 0)
            data += pack(value)
        return data

    def __repr__(self) -> str:
        return ", ".join([f"{register} = {hex(getattr(self, register))}" for register in self.registers])

    def __str__(self) -> str:
        return "\n".join([f"{register} = {hex(getattr(self, register))}" for register in self.registers])
