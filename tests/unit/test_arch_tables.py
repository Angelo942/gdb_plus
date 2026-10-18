"""
Every architecture has an entry in the tables of utils/arch.py,
and every shellcode must decode (with gdb_plus' own disassembler) to what its name says.
The calling conventions are checked in test_arguments.py.
"""
import pytest
from pwn import context

from gdb_plus.utils import arch
from support.offline import offline_debugger

ARCHES = ["i386", "amd64", "arm", "aarch64", "riscv32", "riscv64", "mips", "mips64"]
EMULATED_ONLY = ["riscv32", "riscv64", "mips", "mips64"]

TABLES = {
    "shellcode_syscall": arch.shellcode_syscall,
    "shellcode_sleep": arch.shellcode_sleep,
    "return_instruction": arch.return_instruction,
    "nop": arch.nop,
}


def _known_gap(table, name):
    # inject_sleep is used by debug_from, migrate(new_libdebug) and fork splitting, which are native only
    if table == "shellcode_sleep" and name in EMULATED_ONLY:
        return pytest.param(table, name, marks=pytest.mark.xfail(strict=True, reason="no sleep shellcode: debug_from/split unsupported under QEMU"))
    return pytest.param(table, name)


@pytest.mark.parametrize("table, name", [_known_gap(table, name) for table in TABLES for name in ARCHES])
def test_every_architecture_has_an_entry(table, name):
    """
    This table of utils/arch.py (nop, return instruction, syscall and sleep shellcodes...) has an entry for this
    architecture.
    """
    assert name in TABLES[table]


def _decode(name, code):
    """Decode `code` with Debugger.disassemble() as gdb_plus would for context.arch = name."""
    with context.local(arch=name):
        dbg = offline_debugger()
        dbg.memory.map(0x10000, code, size=0x100)
        return list(dbg.disassemble(0x10000, len(code)))


@pytest.mark.parametrize("name", ARCHES)
def test_nop_decodes_as_nop(name):
    """The nop of this architecture decodes, with capstone, as one nop instruction."""
    instructions = _decode(name, arch.nop[name])
    assert len(instructions) == 1
    assert instructions[0].mnemonic in ["nop", "c.nop"]


@pytest.mark.parametrize("name", ARCHES)
def test_return_instruction_decodes_as_return(name):
    """The return instruction of this architecture decodes as one return (ret, or a jump to the link register)."""
    instructions = _decode(name, arch.return_instruction[name])
    assert len(instructions) == 1
    instruction = instructions[0]
    assert instruction.mnemonic in ["ret", "jr", "bx", "jalr", "c.jr"], f"{instruction.mnemonic} {instruction.op_str}"
    if instruction.mnemonic != "ret":
        assert "ra" in instruction.op_str or "lr" in instruction.op_str


@pytest.mark.parametrize("name", ARCHES)
def test_shellcode_syscall_decodes_as_syscall(name):
    """The syscall shellcode of this architecture decodes as one syscall instruction (syscall, int 0x80, svc, ecall)."""
    instructions = _decode(name, arch.shellcode_syscall[name])
    assert len(instructions) == 1
    assert instructions[0].mnemonic in ["syscall", "int", "svc", "ecall"], instructions[0].mnemonic


@pytest.mark.parametrize("name", [n for n in ARCHES if n in arch.shellcode_sleep])
def test_shellcode_sleep_ends_with_a_jump_to_itself(name):
    """
    The sleep shellcode starts with a nop (step(force=True) relies on it) and ends with a jump to itself, so the parked
    process loops forever.
    """
    instructions = _decode(name, arch.shellcode_sleep[name])
    assert sum(len(i.bytes) for i in instructions) == len(arch.shellcode_sleep[name])
    # step(force=True) relies on the first instruction being a nop
    assert instructions[0].mnemonic == "nop"
    last = instructions[-1]
    target = int(last.op_str.split()[-1].lstrip("#"), 16)
    assert target == last.address
