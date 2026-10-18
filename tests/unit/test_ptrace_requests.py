"""
The handlers of the ptrace requests emulated by emulate_ptrace() (PEEK/POKE, options, attach, seize, cont, detach,
traceme) and the WNOHANG wait, on offline debuggers. The expected values are the ones the kernel documents in ptrace(2).
"""
from threading import Event

import pytest
from pwn import constants, context

from support.offline import FakeMemory, offline_debugger

DATA = 0x600000
EXITKILL = 0x100000
TRACESYSGOOD = 0x1


@pytest.fixture(autouse=True)
def amd64():
    # emulate_ptrace() defines these on pwntools' constants before any _PTRACE_* handler can run
    constants.PTRACE_O_EXITKILL = EXITKILL
    with context.local(arch="amd64"):
        yield


class FakeLibdebug:
    """Enough of the legacy libdebug for Debugger.running: the process is stopped"""

    def _test_execution(self):
        return True


def _debugger(pid, **attributes):
    memory = FakeMemory()
    memory.map(DATA, b"\x11" * 8 + b"\x00" * 8)
    state = dict(_ptrace_has_stopped=Event(), _ptrace_can_continue=Event(), _out_of_breakpoint=Event(), _slaves={},
                 _ptrace_emulated=True, _parent=None)
    state.update(attributes)
    return offline_debugger(memory=memory, pid=pid, **state)


@pytest.fixture
def tracer():
    return _debugger(1000)


@pytest.fixture
def slave():
    dbg = _debugger(1001)
    dbg.continued = []
    dbg._Debugger__hidden_continue = lambda *args, **kwargs: dbg.continued.append(True)
    return dbg


def test_peek_reads_the_slave(tracer, slave):
    """PTRACE_PEEKTEXT returns the word of the tracee at that address in the tracer's return register."""
    tracer._PTRACE_PEEKTEXT(DATA, 0, slave=slave)
    assert tracer.rax == 0x1111111111111111


def test_peek_of_an_unmapped_address_returns_minus_one(tracer, slave):
    """PTRACE_PEEKTEXT of an address the tracee doesn't map returns -1 instead of raising in the tracer."""
    tracer._PTRACE_PEEKTEXT(0xdead0000, 0, slave=slave)
    assert tracer.rax % 2**64 == 2**64 - 1


def test_poke_writes_the_slave(tracer, slave):
    """PTRACE_POKETEXT writes a word into the tracee and returns 0."""
    tracer._PTRACE_POKETEXT(DATA + 8, 0x4242, slave=slave)
    assert slave.read(DATA + 8, 8) == (0x4242).to_bytes(8, "little")
    assert tracer.rax == 0


def test_setoptions_accepts_exitkill_and_tracesysgood(tracer, slave):
    """PTRACE_SETOPTIONS with EXITKILL | TRACESYSGOOD succeeds (returns 0)."""
    tracer._PTRACE_SETOPTIONS(0, EXITKILL | TRACESYSGOOD, slave=slave)
    assert tracer.rax == 0


def test_setoptions_refuses_an_option_it_does_not_emulate(tracer, slave):
    """PTRACE_SETOPTIONS with an option the emulation doesn't know (TRACEFORK) raises instead of being ignored."""
    with pytest.raises(Exception):
        tracer._PTRACE_SETOPTIONS(0, 0x2, slave=slave)


def test_seize_makes_the_process_a_slave(tracer, slave):
    """PTRACE_SEIZE registers the tracee as a slave of the tracer, applies the options and returns 0."""
    tracer._PTRACE_SEIZE(slave.pid, TRACESYSGOOD, slave=slave)
    assert tracer._slaves == {slave.pid: slave}
    assert tracer.rax == 0


def test_attach_makes_the_process_a_slave_and_reports_it_stopped(tracer, slave):
    """
    PTRACE_ATTACH registers the tracee, stops it (it is already stopped here: no signal is sent) and makes its next
    waitpid report the stop; it returns 0.
    """
    slave.libdebug = FakeLibdebug()
    slave._out_of_breakpoint.set()
    tracer._PTRACE_ATTACH(slave.pid, 0, slave=slave)
    assert tracer._slaves == {slave.pid: slave}
    assert slave._ptrace_has_stopped.is_set()
    assert tracer.rax == 0


def test_traceme_makes_the_caller_a_slave(tracer, slave):
    """PTRACE_TRACEME, called by the tracee, registers it as a slave of its tracer and returns 0."""
    assert slave._PTRACE_TRACEME(tracer) is False
    assert tracer._slaves == {slave.pid: slave}
    assert slave.rax == 0


@pytest.mark.parametrize("manual", [False, True])
def test_cont_resumes_the_slave(tracer, slave, manual):
    """
    PTRACE_CONT resumes the tracee at once; with manual=True it only allows it to continue and leaves the stop to the
    user (the handler returns True so that the tracer stops too).
    """
    slave._ptrace_has_stopped.set()
    assert tracer._PTRACE_CONT(0, 0, slave=slave, manual=manual) is manual
    assert slave.continued == ([] if manual else [True])
    assert slave._ptrace_can_continue.is_set() == manual
    assert tracer.rax == 0


def test_detach_releases_the_slave(tracer, slave):
    """PTRACE_DETACH removes the tracee from the slaves and lets it run."""
    tracer._slaves[slave.pid] = slave
    tracer._PTRACE_DETACH(0, 0, slave=slave)
    assert tracer._slaves == {}
    assert slave.continued == [True]
    assert tracer.rax == 0


def test_wnohang_does_not_wait(slave):
    """waitpid(WNOHANG) on a running slave answers at once (False); on a stopped one it reports the stop once."""
    assert slave._wait_slave(0x1) is False
    slave._ptrace_has_stopped.set()
    assert slave._wait_slave(0x1) is True
    assert not slave._ptrace_has_stopped.is_set()
