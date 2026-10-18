from __future__ import annotations
from typing import TYPE_CHECKING
from pwn import context
from capstone import CS_GRP_CALL

if TYPE_CHECKING:
    from capstone import CsInsn

class _Instructions(dict[str, bytes]):
    """
    The mips encodings depend on the endianness
    each 4 byte instruction is reversed when looked up.
    """
    def __getitem__(self, arch: str) -> bytes:
        code = super().__getitem__(arch)
        if arch in ["mips", "mips64"] and context.endian == "big":
            return b"".join(code[i:i+4][::-1] for i in range(0, len(code), 4))
        return code

# test: nop; jmp test / nop; b 0x0
shellcode_sleep = _Instructions({
    "amd64": b"\x90\xeb\xfe",
    "i386": b"\x90\xeb\xfe",
    "aarch64": b'\x1f\x20\x03\xd5\x00\x00\x00\x14',
    "arm": b'\x00\xf0\x20\xe3\xfe\xff\xff\xea',
})

# syscall / int 0x80 / svc #0
shellcode_syscall = _Instructions({
    "amd64": b"\x0f\x05",
    "i386": b"\xcd\x80",
    "aarch64": b'\x01\x00\x00\xd4',
    "arm": b'\x00\x00\x00\xef',
    "riscv32": b's\x00\x00\x00',
    "riscv64": b's\x00\x00\x00',
    "mips": b'\x0c\x00\x00\x00',
    "mips64": b'\x0c\x00\x00\x00',
})

return_instruction = _Instructions({
    "amd64": b"\xc3",
    "i386": b"\xc3",
    "aarch64": b'\xc0\x03_\xd6',
    "arm": b'\x1e\xff\x2f\xe1',
    "riscv32": b'g\x80\x00\x00',
    "riscv64": b'g\x80\x00\x00',
    "mips": b'\x08\x00\xe0\x03',
    "mips64": b'\x08\x00\xe0\x03',
})

nop = _Instructions({
    "amd64": b"\x90",
    "i386": b"\x90",
    "aarch64": b'\x1f\x20\x03\xd5',
    "arm": b'\x00\xf0\x20\xe3',
    "riscv32": b'\x13\x00\x00\x00',
    "riscv64": b'\x13\x00\x00\x00',
    "mips": b'\x00\x00\x00\x00',
    "mips64": b'\x00\x00\x00\x00',
})

# capstone 5 marks every jal/jalr as CALL (even j/jr/ret) and misses jal/bal on mips, so those use mnemonics
_RISCV_CALLS = {"jal", "jalr", "c.jal", "c.jalr"}
_MIPS_CALLS = {"jal", "jalr", "jalr.hb", "jalx", "bal", "bgezal", "bltzal", "bgezall", "bltzall", "jalrc", "jalrc.hb", "balc", "jialc"}
_MIPS_COMPACT_CALLS = {"jalrc", "jalrc.hb", "balc", "jialc"}

def is_call(inst: CsInsn, arch: str) -> bool:
    if arch in ["riscv32", "riscv64"]:
        return inst.mnemonic in _RISCV_CALLS
    elif arch in ["mips", "mips64"]:
        return inst.mnemonic in _MIPS_CALLS
    else: # amd64, i386, arm, aarch64: requires detail mode
        return inst.group(CS_GRP_CALL)

def call_return_address(inst: CsInsn, arch: str) -> int:
    if arch in ["mips", "mips64"] and inst.mnemonic not in _MIPS_COMPACT_CALLS:
        return inst.address + 8 # skip the delay slot
    return inst.address + inst.size