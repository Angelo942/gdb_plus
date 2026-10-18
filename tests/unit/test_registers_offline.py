"""Register lists, generic register properties, backups and instruction decoding per architecture."""
import pytest
from pwn import context

from support.offline import offline_debugger

ARCHES = ["i386", "amd64", "arm", "aarch64", "riscv32", "riscv64", "mips", "mips64"]


def debugger(name, **registers):
    with context.local(arch=name):
        return offline_debugger(registers=registers)


@pytest.mark.parametrize("name", ARCHES)
def test_register_names_are_clean(name):
    """Every register name in the tables of this architecture is lower case without spaces, so dbg.<name> finds it."""
    with context.local(arch=name):
        dbg = offline_debugger()
        for register in dbg._special_registers + dbg._registers + dbg._minor_registers + dbg._long_registers:
            assert register == register.strip().lower(), repr(register)


@pytest.mark.parametrize("register", ["ah", "bh", "ch", "dh", "al", "bl", "cl", "dl", "r8d", "r15w"])
def test_amd64_sub_registers_are_accessible(register):
    """
    This amd64 sub-register (ah, al, r8d, r15w...) is listed among the minor registers, so it can be read and written.
    """
    with context.local(arch="amd64"):
        assert register in offline_debugger()._minor_registers


@pytest.mark.parametrize("name, ip, sp, ret", [
    ("amd64", "rip", "rsp", "rax"),
    ("i386", "eip", "esp", "eax"),
    ("aarch64", "pc", "sp", "x0"),
    ("arm", "pc", "sp", "r0"),
    ("riscv64", "pc", "sp", "a0"),
    ("mips", "pc", "sp", "v0"),
])
def test_generic_registers(name, ip, sp, ret):
    """instruction_pointer, stack_pointer and return_value read and write the right register of each architecture."""
    with context.local(arch=name):
        dbg = debugger(name, **{ip: 0x1000, sp: 0x2000, ret: 0x3000})
        assert (dbg.instruction_pointer, dbg.stack_pointer, dbg.return_value) == (0x1000, 0x2000, 0x3000)
        dbg.stack_pointer = 0x2010
        dbg.return_value = 0x3010
        dbg.instruction_pointer = 0x1010
        assert (getattr(dbg, ip), getattr(dbg, sp), getattr(dbg, ret)) == (0x1010, 0x2010, 0x3010)


@pytest.mark.parametrize("name, register", [("amd64", "rbp"), ("i386", "ebp"), ("aarch64", "fp"), ("mips", "fp")])
def test_base_pointer(name, register):
    """base_pointer reads and writes the frame pointer of the architecture (rbp, ebp, fp)."""
    with context.local(arch=name):
        dbg = debugger(name, **{register: 0x4000})
        assert dbg.base_pointer == 0x4000
        dbg.base_pointer = 0x5000
        assert getattr(dbg, register) == 0x5000


def test_riscv_has_no_base_pointer():
    """base_pointer raises NotImplementedError on riscv, whose ABI has no frame pointer role."""
    with context.local(arch="riscv64"):
        with pytest.raises(NotImplementedError):
            offline_debugger().base_pointer


@pytest.mark.parametrize("name", ARCHES)
def test_backup_and_restore(name):
    """backup() saves every register of the architecture and restore_backup() writes all of them back."""
    with context.local(arch=name):
        dbg = offline_debugger()
        names = dbg._special_registers + dbg._registers
        for i, register in enumerate(names):
            setattr(dbg, register, 0x100 + i)
        backup = dbg.backup()
        assert len(backup) == len(names)
        for register in names:
            setattr(dbg, register, 0)
        dbg.restore_backup(backup)
        assert [getattr(dbg, register) for register in names] == [0x100 + i for i in range(len(names))]


def test_backup_without_debugger():
    """With debugging=False backup() returns None."""
    with context.local(arch="amd64"):
        assert offline_debugger(debugging=False).backup() is None


# (arch, encoding of a call, mnemonic) - little endian, as pwntools assembles by default
CALLS = [
    ("amd64", b"\xe8\x00\x00\x00\x00", "call"),
    ("i386", b"\xe8\x00\x00\x00\x00", "call"),
    ("aarch64", b"\x00\x00\x00\x94", "bl"),
    ("arm", b"\x00\x00\x00\xeb", "bl"),
    ("riscv64", b"\xef\x00\x00\x00", "jal"),
    ("mips", b"\x00\x00\x00\x0c", "jal"),
]


@pytest.mark.parametrize("name, code, mnemonic", CALLS)
def test_next_inst_recognises_calls(name, code, mnemonic):
    """
    next_inst.is_call is true for the call instruction of each architecture (call, bl, blr, jal, jalr...): next() relies
    on it to step over calls.
    """
    # next() steps over calls only if next_inst.is_call
    with context.local(arch=name):
        dbg = offline_debugger()
        dbg.memory.map(0x10000, code + b"\x00" * 12)
        dbg.instruction_pointer = 0x10000
        instruction = dbg.next_inst
        assert instruction.mnemonic == mnemonic
        assert instruction.is_call


def test_next_inst_to_string():
    """next_inst.toString() prints "mnemonic operands", and is_call is False for an ordinary instruction."""
    with context.local(arch="amd64"):
        dbg = offline_debugger()
        dbg.memory.map(0x10000, b"\x48\x89\xe5" + b"\x90" * 13)
        dbg.rip = 0x10000
        assert dbg.next_inst.toString() == "mov rbp, rsp"
        assert dbg.next_inst.is_call is False


def test_dir_lists_registers():
    """dir(dbg) includes the registers, flags and sub-registers, so a REPL can complete them."""
    with context.local(arch="amd64"):
        assert {"rax", "rip", "eflags", "eax"} <= set(dir(offline_debugger()))
