"""
What the tests need to know about each architecture of the target axis, written independently of gdb_plus
(the tests must not use the code they check as their oracle).
"""
import re

from pwn import context

CALLS = {"call", "bl", "blx", "blr", "jal", "jalr", "bal", "c.jal", "c.jalr"}

# Two general purpose registers that can hold any value, the frame pointer and the generic roles
REGISTERS = {
    "amd64": {"gprs": ["rax", "r11"], "ip": "rip", "sp": "rsp", "ret": "rax", "fp": "rbp"},
    "i386": {"gprs": ["eax", "ebx"], "ip": "eip", "sp": "esp", "ret": "eax", "fp": "ebp"},
    "arm": {"gprs": ["r0", "r5"], "ip": "pc", "sp": "sp", "ret": "r0", "fp": "fp"},
    "aarch64": {"gprs": ["x0", "x11"], "ip": "pc", "sp": "sp", "ret": "x0", "fp": "x29"},
    "riscv32": {"gprs": ["a0", "t1"], "ip": "pc", "sp": "sp", "ret": "a0", "fp": None},
    "riscv64": {"gprs": ["a0", "t1"], "ip": "pc", "sp": "sp", "ret": "a0", "fp": None},
    "mips": {"gprs": ["v0", "t0"], "ip": "pc", "sp": "sp", "ret": "v0", "fp": "fp"},
    "mips64": {"gprs": ["v0", "t0"], "ip": "pc", "sp": "sp", "ret": "v0", "fp": "fp"},
}

# A function that returns 0x1337, hand assembled (no cross binutils needed)
RETURN_0x1337 = {
    "amd64": bytes.fromhex("b837130000c3"),                      # mov eax, 0x1337; ret
    "i386": bytes.fromhex("b837130000c3"),
    "aarch64": bytes.fromhex("e0668252c0035fd6"),                # mov w0, #0x1337; ret
    "arm": bytes.fromhex("370301e31eff2fe1"),                    # movw r0, #0x1337; bx lr
    "riscv32": bytes.fromhex("3715000013057533" "67800000"),     # lui a0, 1; addi a0, a0, 0x337; ret
    "riscv64": bytes.fromhex("3715000013057533" "67800000"),
    "mips": bytes.fromhex("34021337" "03e00008" "00000000"),     # ori v0, zero, 0x1337; jr ra; nop (big endian)
    "mips64": bytes.fromhex("34021337" "03e00008" "00000000"),
}


def registers():
    return REGISTERS[context.arch]


def word_mask():
    return (1 << context.bits) - 1


def has_delay_slot():
    return context.arch in ["mips", "mips64"]


def is_call(instruction):
    if instruction.mnemonic in ["jalr", "c.jalr"]:
        return instruction.op_str.startswith("ra")  # jalr zero, ... is a jump or a return
    if instruction.mnemonic in ["jal", "c.jal"] and context.arch.startswith("riscv"):
        return not instruction.op_str.startswith("zero")
    return instruction.mnemonic in CALLS


def is_return(instruction):
    text = f"{instruction.mnemonic} {instruction.op_str}".strip()
    return (instruction.mnemonic == "ret" or text in ["bx lr", "jr $ra", "c.jr ra", "jalr zero, 0(ra)"]
            or (instruction.mnemonic in ["pop", "ldm", "ldmia", "pop.w"] and "pc" in instruction.op_str))


def call_target(instruction):
    """Absolute address called by a direct call (capstone prints riscv's jal offset relative to the pc)"""
    immediate = int(re.findall(r"-?0x[0-9a-f]+", instruction.op_str)[-1], 16)
    if context.arch.startswith("riscv") and instruction.mnemonic in ["jal", "c.jal"]:
        return (instruction.address + immediate) % 2**context.bits
    return immediate


def read_c_long(dbg, location):
    """A C `long`: as wide as a pointer on every ABI of the targets (read_long() is always 8 bytes)"""
    return dbg.read_pointer(location)


def after_call(instruction):
    """Where a call returns: the next instruction, or the one after the delay slot on mips"""
    return instruction.address + instruction.size * (2 if has_delay_slot() else 1)


def calls_in(dbg, function, end=None, size=0x200):
    """Direct calls inside a function, read from memory (so it also works on the copy under QEMU)"""
    start = dbg.symbols[function]
    length = (dbg.symbols[end] - start) if end is not None else size
    return [i for i in dbg.disassemble(start, length) if is_call(i)]


def call_to(dbg, caller, callee, end=None):
    """The (only) call to `callee` in `caller`"""
    calls = [i for i in calls_in(dbg, caller, end) if _calls(i, dbg.symbols[callee])]
    assert calls, f"no call to {callee} in {caller}"
    return calls[0]


def _calls(instruction, address):
    try:
        return call_target(instruction) == address
    except (IndexError, ValueError):
        return False
