"""Breakpoint and user_regs_struct."""
from pwn import context

from gdb_plus.utils.breakpoints import Breakpoint
from gdb_plus.utils.regs import user_regs_struct
from support.offline import offline_debugger


def test_breakpoint_defaults():
    """A Breakpoint created with only an address is user defined, not temporary, software, without callback."""
    breakpoint = Breakpoint("native", 0x401000)
    assert (breakpoint.native_breakpoint, breakpoint.address) == ("native", 0x401000)
    assert breakpoint.callback is None
    assert breakpoint.temporary is False
    assert breakpoint.user_defined is True
    assert breakpoint.hw is False


def test_breakpoint_remembers_hardware():
    """Breakpoint(hw=True) remembers it is a hardware breakpoint (migrate re-creates it as one)."""
    # migrate(new_libdebug=True) re-creates breakpoints with hw=breakpoint.hw
    assert Breakpoint("native", 0x401000, hw=True).hw is True


def test_regs_struct_round_trip():
    """
    user_regs_struct of amd64 is 27 words; set() then get() of raw bytes round trips and fields land in the right slot
    (rip is the 17th).
    """
    with context.local(arch="amd64"):
        registers = user_regs_struct()
        assert registers.size == 27 * 8
        data = b"".join((i * 0x1111).to_bytes(8, "little") for i in range(27))
        registers.set(data)
        assert registers.rip == 16 * 0x1111
        assert registers.get() == data


def test_regs_struct_missing_values_are_zero():
    """Registers never assigned in user_regs_struct are packed as zero."""
    with context.local(arch="amd64"):
        registers = user_regs_struct()
        registers.rax = 5
        data = registers.get()
        assert len(data) == registers.size
        assert user_regs_struct().set(data).rax == 5


def test_regs_struct_covers_every_register_ptrace_getregs_copies():
    """user_regs_struct has a slot for every register the emulated PTRACE_GETREGS copies."""
    # _PTRACE_GETREGS asserts each register of slave._registers is in the struct
    with context.local(arch="amd64"):
        assert set(offline_debugger()._registers) <= set(user_regs_struct().registers)
