"""insaaaaaaane (amd64, no PIE): breakpoints, callbacks and syscalls from the legacy suite."""
import pytest
from pwn import constants, u64


@pytest.fixture
def dbg(debugger, challenge):
    return debugger(challenge("insaaaaaaane"))


def test_ltrace_and_plt_breakpoint(dbg):
    """
    With set_ltrace() on, a user breakpoint on fgets' PLT entry still runs its callback and reads the second argument.
    """
    dbg.set_ltrace()
    data = [0]

    def callback(d):
        data[0] = d.args[1]
        return False
    dbg.b(dbg.exe.plt["fgets"], callback=callback)
    dbg.p.sendline(b"ciao")
    dbg.c()
    assert data[0] == 0x63


@pytest.mark.skip(reason="interactive in the legacy suite: it waits for a human to continue from the gdb prompt")
def test_continue_until_over_a_temporary_breakpoint(dbg):
    """continue_until stops on the user's breakpoint and waits until gdb is continued by hand."""
    dbg.b(0x403ad7, temporary=True)
    dbg.continue_until(0x403adb)
    assert dbg.instruction_pointer == 0x403adb


def test_non_blocking_continue_until(dbg):
    """
    continue_until(..., wait=False) returns an event set once the program, after receiving its input, reaches the
    address.
    """
    done = dbg.continue_until(0x4038c2, wait=False)
    dbg.p.sendline(b"ciao")
    done.wait()
    assert dbg.instruction_pointer == 0x4038c2


def test_crowded_breakpoints_are_not_overshot(dbg):
    """A breakpoint on every instruction of a block: each c() stops on the next one, none is skipped."""
    for instruction in dbg.disassemble(dbg.instruction_pointer + dbg.next_inst.size, 0x24):
        dbg.b(instruction.address)
        dbg.c()
        assert instruction.address == dbg.instruction_pointer


def test_crowded_callbacks_do_not_lose_the_until(dbg):
    """
    Continuing callbacks on every instruction run in order while until() runs past them, and until() still stops at its
    target.
    """
    addresses, counter = [], [0]

    def callback(d):
        assert d.instruction_pointer == addresses[counter[0]]
        counter[0] += 1
        return False
    for instruction in dbg.disassemble(dbg.instruction_pointer + dbg.next_inst.size, 0x1f):
        addresses.append(instruction.address)
        dbg.b(instruction.address, callback)
    dbg.until(dbg.instruction_pointer + 0x24)
    assert dbg.instruction_pointer == dbg.exe.entry + 0x24


def test_crowded_callbacks_still_stop_a_step(dbg):
    """si() onto an instruction covered by a continuing callback still stops after one instruction."""
    for instruction in dbg.disassemble(dbg.instruction_pointer + dbg.next_inst.size, 0x24):
        dbg.b(instruction.address, lambda d: False)
    dbg.si()
    assert dbg.instruction_pointer == dbg.exe.entry + 0x2


def test_callback_reads_memory_and_stops(dbg):
    """A callback can push(), read the stack and pop() without changing the registers, then stop the process."""
    data = []

    def callback(d):
        d.push(d.rsi)
        data.append(u64(d.read(d.rsp, 8)) != d.rsi)
        d.rsi = d.pop()
        return True
    dbg.b(0x400786, callback=callback, temporary=True)
    dbg.c(wait=True)
    assert not sum(data)


def test_callback_sets_a_breakpoint_and_continues(dbg):
    """
    A temporary breakpoint's callback sets another temporary breakpoint and continues: the process stops on the new one
    and both are removed.
    """
    def callback(d):
        d.b(0x403ad9, temporary=True)
        return False
    dbg.b(0x403ad0, callback=callback, temporary=True)
    dbg.c(wait=True)
    assert dbg.rip == 0x403ad9
    assert not len(dbg.breakpoints[0x403ad0] + dbg.breakpoints[0x403ad9])


def test_callback_steps_and_stops(dbg):
    """step() inside a temporary breakpoint's callback, then stop: the process is one instruction further."""
    def callback(d):
        d.step()
        return True
    dbg.b(0x403ad0, callback=callback, temporary=True)
    dbg.c(wait=True)
    assert dbg.rip == 0x403ad2


def test_callback_finishes_and_continues(dbg):
    """
    finish() inside a continuing callback does not wake the until() of the script, which still stops at its target.
    """
    def callback(d):
        d.finish()
        return False
    dbg.b(0x400870, callback=callback)
    dbg.until(0x40388e)
    assert dbg.rip == 0x40388e


def test_syscalls(debugger, challenge, tmp_path):
    """syscall(open / write / close) on the non PIE binary writes a real file on the host."""
    dbg = debugger(challenge("insaaaaaaane"), from_entry=True)
    path = str(tmp_path / "data.txt")
    open(path, "wb").close()
    fd = dbg.syscall(constants.SYS_open, [path, constants.O_WRONLY, 0x0])
    data = b"ciao, come stai ?"
    dbg.syscall(constants.SYS_write, [fd, data, len(data)])
    dbg.syscall(constants.SYS_close, [fd])
    assert open(path, "rb").read() == data
