"""The bookkeeping of catchpoints (catch_event / delete_catch) without gdb: what is sent to gdb and what is remembered."""
import pytest
from pwn import context

from support.offline import offline_debugger

BREAKPOINTS = """\
Num     Type           Disp Enb Address            What
1       catchpoint     keep y                      syscall "getpid" 
"""


@pytest.fixture
def dbg():
    with context.local(arch="amd64"):
        dbg = offline_debugger(gdb=object(), _event_table={}, _event_breakpoints={})
        dbg.execute_results["info breakpoints"] = BREAKPOINTS
        yield dbg


def test_catch_event_remembers_the_number_gdb_gave(dbg):
    """catch_event() sends `catch <name>` and maps the catchpoint number gdb lists last to the callback."""
    callback = lambda d: False
    dbg.catch_event("syscall getpid", callback)
    assert dbg.executed[0] == "catch syscall getpid"
    assert dbg._event_table == {"syscall getpid": 1}
    assert dbg._event_breakpoints == {1: callback}


def test_catching_the_same_event_again_only_replaces_the_callback(dbg):
    """A second catch_event() on the same event sends nothing to gdb and replaces the callback of the catchpoint."""
    dbg.catch_event("syscall getpid", lambda d: False)
    sent = list(dbg.executed)
    second = lambda d: True
    dbg.catch_event("syscall getpid", second)
    assert dbg.executed == sent
    assert dbg._event_breakpoints == {1: second}


def test_delete_catch_removes_the_catchpoint(dbg):
    """delete_catch() deletes the catchpoint in gdb and forgets its callback."""
    dbg.catch_event("syscall getpid", lambda d: False)
    dbg.delete_catch("syscall getpid")
    assert dbg.executed[-1] == "delete 1"
    assert dbg._event_table == {} and dbg._event_breakpoints == {}


def test_delete_catch_of_an_event_not_caught(dbg):
    """delete_catch() of an event that isn't caught only warns: nothing is sent to gdb and it returns None."""
    assert dbg.delete_catch("fork") is None
    assert dbg.executed == []


def test_catch_syscall_refuses_riscv():
    """On riscv catch_syscall() returns None without asking gdb (the riscv gdb stub can't catch syscalls)."""
    with context.local(arch="riscv64"):
        dbg = offline_debugger(gdb=object(), _event_table={}, _event_breakpoints={})
        assert dbg.catch_syscall("write") is None
        assert dbg.executed == []
