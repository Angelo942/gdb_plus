"""dbg.args[i] and dbg.syscall_args[i] on every calling convention, without a process."""
import pytest
from pwn import context, pack

from gdb_plus.utils.arguments import Fake_arguments, function_calling_convention, syscall_calling_convention
from support.offline import offline_debugger

STACK = 0x7ff000
CODE = 0x401000
ARCHES = ["i386", "amd64", "arm", "aarch64", "riscv32", "riscv64", "mips", "mips64"]


@pytest.mark.parametrize("table", [function_calling_convention, syscall_calling_convention], ids=["function", "syscall"])
@pytest.mark.parametrize("name", ARCHES)
def test_every_architecture_has_a_calling_convention(table, name):
    """The function and syscall calling convention tables have an entry for this architecture."""
    assert name in table


def _register_names(name):
    with context.local(arch=name):
        dbg = offline_debugger()
        return set(dbg._special_registers + dbg._registers + dbg._minor_registers)


@pytest.mark.parametrize("name", ARCHES)
def test_calling_conventions_only_use_known_registers(name):
    """
    The calling conventions only name registers Debugger knows: an unknown name would be stored as a Python attribute
    instead of written to the process.
    """
    # An unknown name is silently stored as a python attribute instead of being written to the process
    known = _register_names(name)
    used = set(function_calling_convention[name]) | set(syscall_calling_convention[name])
    assert used <= known, f"not in Debugger._registers: {sorted(used - known)}"


@pytest.mark.parametrize("name", ARCHES)
def test_syscall_convention_starts_with_the_number_register(name):
    """
    The syscall convention lists the register of the syscall number first, followed by at least three argument
    registers.
    """
    convention = syscall_calling_convention[name]
    assert len(convention) >= 4
    assert convention[0] not in function_calling_convention[name][:1]


def _debugger(name, code=b"\x90" * 16, stack_words=()):
    """Debugger stopped at CODE (whose first instruction is `code`) with `stack_words` at the stack pointer."""
    with context.local(arch=name):
        dbg = offline_debugger()
        dbg.memory.map(CODE, code, size=0x100)
        dbg.memory.map(STACK, b"".join(pack(word) for word in stack_words), size=0x1000)
        dbg.instruction_pointer = CODE
        dbg.stack_pointer = STACK
        return dbg


@pytest.mark.parametrize("name", ["amd64", "aarch64", "arm", "riscv64", "mips"])
def test_register_arguments_follow_the_calling_convention(name):
    """dbg.args[i] reads and writes the i-th register of the calling convention, by index and by slice."""
    with context.local(arch=name):
        dbg = _debugger(name)
        convention = function_calling_convention[name]
        for i, register in enumerate(convention):
            setattr(dbg, register, 0x100 + i)
        assert [dbg.args[i] for i in range(len(convention))] == [0x100 + i for i in range(len(convention))]
        assert dbg.args[0:2] == [0x100, 0x101]
        dbg.args[1] = 0xdead
        assert getattr(dbg, convention[1]) == 0xdead


# Where the 7th argument lives depends on how far the prologue went
@pytest.mark.parametrize("prologue, stack, base_offset", [
    pytest.param(b"\x55", [0x401234, 7, 8], None, id="entry: push rbp"),
    pytest.param(b"\xf3\x0f\x1e\xfa", [0x401234, 7, 8], None, id="entry: endbr64"),
    pytest.param(b"\x48\x89\xe5", [0x7fffffff0000, 0x401234, 7, 8], None, id="after push rbp: mov rbp, rsp"),
    pytest.param(b"\x90", [0x7fffffff0000, 0x401234, 7, 8], 0, id="function body: through rbp"),
])
def test_amd64_stack_arguments(prologue, stack, base_offset):
    """
    On amd64 the 7th and 8th arguments are found on the stack after each prologue state (entry, after push rbp, after
    mov rbp, rsp, with locals below).
    """
    with context.local(arch="amd64"):
        dbg = _debugger("amd64", prologue, stack)
        if base_offset is not None:
            dbg.rbp = STACK + base_offset
            dbg.rsp = STACK - 0x40  # locals: rsp must not matter anymore
        assert dbg.args[6] == 7
        assert dbg.args[7] == 8
        dbg.args[7] = 0x88
        assert dbg.args[7] == 0x88


def test_i386_arguments_are_all_on_the_stack():
    """On i386 every argument is on the stack above the return address, and writing one writes that stack slot."""
    with context.local(arch="i386"):
        dbg = _debugger("i386", b"\x55", [0x8049000, 1, 2, 3])
        assert dbg.args[0:3] == [1, 2, 3]
        dbg.args[0] = 0x41
        assert dbg.read(STACK + 4, 4) == pack(0x41)


def test_aarch64_stack_arguments():
    """On aarch64 the 9th and 10th arguments are read from and written to the stack at the function entry."""
    with context.local(arch="aarch64"):
        dbg = _debugger("aarch64", stack_words=[8, 9])
        assert dbg.args[8] == 8
        assert dbg.args[9] == 9
        dbg.args[9] = 0x99
        assert dbg.args[9] == 0x99


@pytest.mark.xfail(strict=True, reason="Arguments has no stack lookup for riscv and mips yet")
@pytest.mark.parametrize("name", ["riscv64", "mips"])
def test_stack_arguments_on_other_architectures(name):
    """
    The first stack argument on riscv64 (at sp) and mips (after the 16 bytes reserved for a0-a3). Expected to fail:
    Arguments has no stack lookup there yet.
    """
    with context.local(arch=name):
        registers = len(function_calling_convention[name])
        # riscv: 9th argument at sp. mips o32: the caller reserves 16 bytes for a0-a3
        offset_words = 0 if name.startswith("riscv") else 4
        dbg = _debugger(name, stack_words=[0] * offset_words + [0x42])
        assert dbg.args[registers] == 0x42


@pytest.mark.parametrize("name", sorted(syscall_calling_convention))
def test_syscall_arguments_skip_the_number_register(name):
    """dbg.syscall_args[i] reads the i-th argument register of the syscall convention, not the number register."""
    with context.local(arch=name):
        dbg = offline_debugger()
        number_register, *registers = syscall_calling_convention[name]
        for i, register in enumerate(registers):
            setattr(dbg, register, 0x200 + i)
        setattr(dbg, number_register, 0x1)
        assert [dbg.syscall_args[i] for i in range(len(registers))] == [0x200 + i for i in range(len(registers))]


@pytest.mark.parametrize("name", sorted(syscall_calling_convention))
def test_syscall_arguments_setter_matches_getter(name):
    """Writing dbg.syscall_args[i] writes the register that reading it reads, and leaves the syscall number alone."""
    # catch_syscall callbacks rewrite arguments with dbg.syscall_args[1] = buffer
    with context.local(arch=name):
        dbg = offline_debugger()
        number_register, *registers = syscall_calling_convention[name]
        setattr(dbg, number_register, 0x1)
        for i, register in enumerate(registers):
            dbg.syscall_args[i] = 0x300 + i
            assert getattr(dbg, register) == 0x300 + i, f"syscall_args[{i}] did not write {register}"
        assert getattr(dbg, number_register) == 0x1


@pytest.mark.parametrize("name", sorted(syscall_calling_convention))
def test_open_ended_syscall_slice_covers_every_argument(name):
    """dbg.syscall_args[:] (used by strace) covers every argument register, for reading and writing."""
    # set_strace reads dbg.syscall_args[:]
    with context.local(arch=name):
        dbg = offline_debugger()
        number_register, *registers = syscall_calling_convention[name]
        values = [0x400 + i for i in range(len(registers))]
        dbg.syscall_args[:] = values
        assert [getattr(dbg, register) for register in registers] == values
        assert dbg.syscall_args[:] == values
        assert dbg.syscall_args[1:] == values[1:]


def test_too_many_syscall_arguments():
    """syscall_args[6] raises: there are only six syscall arguments."""
    with context.local(arch="amd64"):
        dbg = offline_debugger()
        with pytest.raises(Exception):
            dbg.syscall_args[6]
        with pytest.raises(Exception):
            dbg.syscall_args[6] = 0


def test_fake_arguments_without_debugger():
    """Fake_arguments (used when nothing is debugged) reads 0 everywhere and ignores writes."""
    fake = Fake_arguments()
    assert fake[3] == 0
    assert fake[0:3] == [0, 0, 0]
    fake[2] = 5  # silently ignored


def test_args_property_when_not_debugging():
    """With debugging=False (the NOPTRACE switch) dbg.args and dbg.syscall_args are Fake_arguments."""
    with context.local(arch="amd64"):
        dbg = offline_debugger(debugging=False)
        assert isinstance(dbg.args, Fake_arguments)
        assert isinstance(dbg.syscall_args, Fake_arguments)


@pytest.mark.parametrize("orig_rax, register", [(2**64 - 1, "rax"), (39, "orig_rax")], ids=["before_the_syscall", "inside_the_syscall"])
def test_sys_num_setter_on_amd64(orig_rax, register):
    """
    Assigning dbg.sys_num on amd64 writes rax before the syscall instruction ran (orig_rax is -1) and orig_rax once
    inside the syscall (on a catchpoint), which is the register the kernel reads the number from then.
    """
    dbg = _debugger("amd64", code=b"\x90" * 16)
    dbg.orig_rax = orig_rax
    with context.local(arch="amd64"):
        dbg.sys_num = 110
        assert getattr(dbg, register) == 110
        assert dbg.sys_num == 110


@pytest.mark.parametrize("name, register", [("aarch64", "x8"), ("arm", "r7"), ("riscv64", "a7"), ("mips", "v0")])
def test_sys_num_setter_elsewhere(name, register):
    """Assigning dbg.sys_num writes the syscall number register of the architecture's Linux ABI."""
    dbg = _debugger(name)
    with context.local(arch=name):
        dbg.sys_num = 64
        assert getattr(dbg, register) == 64
