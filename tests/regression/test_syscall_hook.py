"""test_syscall_hook: open + write + close through syscall(). Writes ./data.txt in the test directory."""
import time
from pathlib import Path

import pytest

from gdb_plus import SKIP_SYSCALL


@pytest.fixture
def dbg(debugger, challenge):
    Path("data.txt").write_bytes(b"")
    return debugger(challenge("test_syscall_hook"), aslr=False)


def test_rewrite_the_syscall_arguments(dbg):
    """
    A catch_syscall("write") callback points the buffer to other bytes: the file the program writes contains the new
    data.
    """
    data = b"syscall altered"
    address = dbg.write(None, data)

    def callback(d, entry):
        if entry:
            d.syscall_args[1] = address
            d.syscall_args[2] = len(data)
        return False
    dbg.catch_syscall("write", callback)
    dbg.b(0x555555555229)
    dbg.until(0x555555555226)
    assert dbg.instruction_pointer == 0x555555555226
    dbg.close()
    assert Path("data.txt").read_bytes() == data


def test_skip_the_syscall(dbg):
    """
    The callback writes the file itself and returns SKIP_SYSCALL with a fake return value: the program's own write never
    happens.
    """
    data = b"syscall skipped"

    def callback(d, entry):
        if entry:
            Path("data.txt").write_bytes(data)
            d.return_value = d.syscall_args[2]
            return SKIP_SYSCALL
    dbg.catch_syscall("write", callback)
    dbg.b(0x555555555229)
    dbg.until(0x555555555226)
    assert dbg.instruction_pointer == 0x555555555226
    dbg.close()
    assert Path("data.txt").read_bytes() == data


def test_breakpoint_where_a_syscall_returned(dbg):
    """
    A breakpoint on the address where a caught syscall returned is hit exactly once, and the rewritten write still lands
    in the file.
    """
    data = b"syscall altered"
    address = dbg.write(None, data)

    def rewrite(d, entry):
        if entry:
            d.syscall_args[1] = address
            d.syscall_args[2] = len(data)
        return False

    counter = [0]

    def count(d):
        counter[0] += 1
        return True

    dbg.catch_syscall("write", rewrite)
    dbg.catch_syscall("open", lambda d, entry: not entry)  # run the syscall, stop when it returns
    dbg.c()
    syscall_address = dbg.instruction_pointer
    dbg.b(syscall_address, count)
    dbg.c()
    time.sleep(2)
    assert dbg.instruction_pointer == syscall_address
    assert counter[0] == 1
    dbg.close()
    assert Path("data.txt").read_bytes() == data
