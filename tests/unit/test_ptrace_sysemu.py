"""
PTRACE_SYSEMU_SINGLESTEP, the SYSEMU stop and the wait bookkeeping of the ptrace emulation, on offline
debuggers (no process). The kernel behaviour they encode is pinned by tests/fixtures/src/sysemu_tracer.c
(integration/test_processes.py::test_sysemu_tracer_oracle).
"""
from threading import Event

import pytest
from pwn import constants, context

from gdb_plus.utils.regs import user_regs_struct
from support.offline import FakeMemory, offline_debugger

CODE = 0x401000
REGS = 0x500000
SYSCALL = b"\x0f\x05"
NOP = b"\x90"
TRACESYSGOOD = 0x1
EXITKILL = 0x100000
WNOHANG, WEXITED, WSTOPPED, WNOWAIT = 0x1, 0x4, 0x2, 0x01000000
MINUS_ENOSYS = 2**64 - 38


@pytest.fixture(autouse=True)
def amd64():
    # emulate_ptrace() defines these on pwntools' constants before any _PTRACE_* handler can run
    constants.PTRACE_O_EXITKILL = EXITKILL
    constants.PTRACE_O_SUSPEND_SECCOMP = 0x00200000
    with context.local(arch="amd64"):
        yield


def ptrace_state(**changes):
    state = dict(_ptrace_has_stopped=Event(), _ptrace_emulated=True, _slaves={}, _ptrace_options=0,
                 _ptrace_status=None, _ptrace_sysemu_stop=False, _ptrace_orig_rax=None)
    state.update(changes)
    return state


class Slave:
    """An offline tracee whose step() and continue only record that they were asked."""

    def __init__(self, code, *, options=0, **registers):
        memory = FakeMemory()
        memory.map(CODE, code + NOP * 0x10)
        self.dbg = offline_debugger(memory=memory, pid=1001, registers={"rip": CODE, **registers},
                                    **ptrace_state(_ptrace_options=options))
        self.steps = []
        self.continues = []
        self.dbg.step = lambda *args, **kwargs: self.steps.append(self.dbg.rip)
        self.dbg._Debugger__hidden_continue = lambda *args, **kwargs: self.continues.append(self.dbg.rip)
        self.dbg.reverse_lookup = hex


@pytest.fixture
def tracer():
    memory = FakeMemory()
    memory.map(REGS, size=user_regs_struct().size)
    return offline_debugger(memory=memory, pid=1000, **ptrace_state())


def park(tracer, slave):
    """SYSEMU-step a slave that sits on a syscall."""
    assert tracer._PTRACE_SYSEMU_SINGLESTEP(0, 0, slave=slave.dbg) is False
    assert slave.dbg._ptrace_sysemu_stop


########################## SYSEMU_SINGLESTEP ##########################

def test_sysemu_singlestep_on_a_syscall_does_not_run_it(tracer):
    """
    Emulated PTRACE_SYSEMU_SINGLESTEP on a syscall instruction: the tracee is not stepped, rip moves past it, rax is
    -ENOSYS, orig_rax keeps the number and the wait status is the TRACESYSGOOD syscall stop (0x857f), as the kernel
    does.
    """
    slave = Slave(SYSCALL, options=EXITKILL | TRACESYSGOOD, rax=0x4042)
    park(tracer, slave)
    assert slave.steps == []
    assert slave.dbg.rip == CODE + 2
    assert slave.dbg.rax == MINUS_ENOSYS
    assert slave.dbg._ptrace_orig_rax == 0x4042
    assert slave.dbg._ptrace_wait_status() == 0x857f
    assert slave.dbg._ptrace_has_stopped.is_set()
    assert tracer.rax == 0  # ptrace() return value


def test_sysemu_stop_without_tracesysgood_is_a_plain_sigtrap(tracer):
    """Without PTRACE_O_TRACESYSGOOD the emulated syscall stop reports a plain SIGTRAP (0x57f)."""
    slave = Slave(SYSCALL, rax=0x4042)
    park(tracer, slave)
    assert slave.dbg._ptrace_wait_status() == 0x57f


def test_sysemu_singlestep_on_any_other_instruction_steps(tracer):
    """PTRACE_SYSEMU_SINGLESTEP on an instruction that is not a syscall single steps it, like the kernel."""
    slave = Slave(NOP, options=TRACESYSGOOD)
    tracer._PTRACE_SYSEMU_SINGLESTEP(0, 0, slave=slave.dbg)
    assert slave.steps == [CODE]
    assert not slave.dbg._ptrace_sysemu_stop
    assert slave.dbg._ptrace_status is None  # derived from the real stop signal
    assert slave.dbg._ptrace_has_stopped.is_set()


def test_sysemu_singlestep_out_of_a_sysemu_stop_steps_the_next_instruction(tracer):
    """
    SYSEMU_SINGLESTEP from a syscall stop steps the next instruction: the kernel reports no syscall exit in SYSEMU mode.
    """
    # SYSCALL_EMU is still set: the kernel reports no syscall exit
    slave = Slave(SYSCALL + NOP, options=TRACESYSGOOD, rax=0x4043)
    park(tracer, slave)
    slave.dbg._ptrace_has_stopped.clear()
    tracer._PTRACE_SYSEMU_SINGLESTEP(0, 0, slave=slave.dbg)
    assert slave.steps == [CODE + 2]
    assert not slave.dbg._ptrace_sysemu_stop
    assert slave.dbg._ptrace_orig_rax is None
    assert slave.dbg._ptrace_status is None


def test_two_syscalls_in_a_row_are_both_reported(tracer):
    """
    Two syscall instructions in a row give two syscall stops, the second with orig_rax = -ENOSYS (nobody injected a
    result).
    """
    slave = Slave(SYSCALL + SYSCALL, options=TRACESYSGOOD, rax=0x27)
    park(tracer, slave)
    tracer._PTRACE_SYSEMU_SINGLESTEP(0, 0, slave=slave.dbg)
    assert slave.steps == []
    assert slave.dbg.rip == CODE + 4
    assert slave.dbg._ptrace_sysemu_stop
    assert slave.dbg._ptrace_orig_rax == MINUS_ENOSYS  # rax was -ENOSYS: nobody injected a result


########################## LEAVING A SYSEMU STOP ##########################

def test_singlestep_out_of_a_sysemu_stop_runs_nothing(tracer):
    """
    PTRACE_SINGLESTEP from a syscall stop gives the exit report (SIGTRAP, rip unchanged) without executing anything.
    """
    # The exit report: SIGTRAP, rip unchanged. The loader injects rax only after it (0x4ee1)
    slave = Slave(SYSCALL, options=TRACESYSGOOD, rax=0x4042)
    park(tracer, slave)
    slave.dbg._ptrace_has_stopped.clear()
    assert tracer._PTRACE_SINGLESTEP(0, 0, slave=slave.dbg) is False
    assert slave.steps == []
    assert slave.dbg.rip == CODE + 2
    assert slave.dbg._ptrace_wait_status() == 0x57f
    assert slave.dbg._ptrace_has_stopped.is_set()
    assert not slave.dbg._ptrace_sysemu_stop
    assert slave.dbg._ptrace_orig_rax is None
    assert tracer.rax == 0


def test_singlestep_after_the_exit_report_steps_again(tracer):
    """
    After rewinding rip and the exit report, the next PTRACE_SINGLESTEP really runs the syscall (the native path of the
    traps loader).
    """
    # The loader's native path (0x47ef): rewind, SINGLESTEP (report), SINGLESTEP (runs the syscall)
    slave = Slave(SYSCALL, options=TRACESYSGOOD, rax=0x27)
    park(tracer, slave)
    slave.dbg.rip -= 2
    tracer._PTRACE_SINGLESTEP(0, 0, slave=slave.dbg)
    assert slave.steps == []
    tracer._PTRACE_SINGLESTEP(0, 0, slave=slave.dbg)
    assert slave.steps == [CODE]
    assert slave.dbg._ptrace_status is None


def test_singlestep_outside_a_sysemu_stop_steps(tracer):
    """PTRACE_SINGLESTEP outside a syscall stop is an ordinary single step."""
    slave = Slave(NOP)
    tracer._PTRACE_SINGLESTEP(0, 0, slave=slave.dbg)
    assert slave.steps == [CODE]
    assert slave.dbg._ptrace_status is None
    assert slave.dbg._ptrace_has_stopped.is_set()


def test_cont_out_of_a_sysemu_stop_forgets_it(tracer):
    """PTRACE_CONT from a syscall stop continues past the syscall and clears the emulated stop state."""
    slave = Slave(SYSCALL, options=TRACESYSGOOD, rax=0x4049)
    park(tracer, slave)
    tracer._PTRACE_CONT(0, 0, slave=slave.dbg)
    assert slave.continues == [CODE + 2]
    assert not slave.dbg._ptrace_sysemu_stop
    assert slave.dbg._ptrace_status is None
    assert slave.dbg._ptrace_orig_rax is None


########################## OPTIONS AND REGISTERS ##########################

def test_setoptions_remembers_the_options(tracer):
    """PTRACE_SETOPTIONS stores the options (EXITKILL, TRACESYSGOOD) on the emulated tracee."""
    slave = Slave(NOP)
    tracer._PTRACE_SETOPTIONS(0, EXITKILL | TRACESYSGOOD, slave=slave.dbg)
    assert slave.dbg._ptrace_options == EXITKILL | TRACESYSGOOD


def read_regs(tracer):
    return user_regs_struct().set(tracer.read(REGS, user_regs_struct().size))


def test_getregs_copies_eflags_and_orig_rax(tracer):
    """Emulated PTRACE_GETREGS copies the general registers, eflags and orig_rax into the tracer's user_regs_struct."""
    # The loader's CFG VM decides every jcc from eflags; in SYSEMU mode it reads the number from orig_rax
    slave = Slave(NOP, rax=5, rbx=6, rsp=0x7ffe0000, eflags=0x246, orig_rax=0x27)
    tracer._PTRACE_GETREGS(0, REGS, slave=slave.dbg)
    regs = read_regs(tracer)
    assert (regs.rax, regs.rbx, regs.rsp, regs.rip) == (5, 6, 0x7ffe0000, CODE)
    assert regs.eflags == 0x246
    assert regs.orig_ax == 0x27


def test_getregs_in_a_sysemu_stop_reports_the_syscall_number(tracer):
    """
    PTRACE_GETREGS in a syscall stop reports orig_rax = the syscall number, rax = -ENOSYS and rip after the syscall.
    """
    slave = Slave(SYSCALL, options=TRACESYSGOOD, rax=0x4042, eflags=0x202)
    park(tracer, slave)
    tracer._PTRACE_GETREGS(0, REGS, slave=slave.dbg)
    regs = read_regs(tracer)
    assert regs.orig_ax == 0x4042
    assert regs.rax == MINUS_ENOSYS
    assert regs.rip == CODE + 2
    assert regs.eflags == 0x202


def test_setregs_in_a_sysemu_stop_keeps_orig_rax_and_only_writes_the_gprs(tracer):
    """
    PTRACE_SETREGS writes the general registers and orig_rax, but never fs_base: the tracer's copy must not clobber the
    TLS base.
    """
    slave = Slave(SYSCALL, options=TRACESYSGOOD, rax=0x4042)
    park(tracer, slave)
    tracer._PTRACE_GETREGS(0, REGS, slave=slave.dbg)
    regs = read_regs(tracer)
    regs.rax, regs.orig_ax, regs.fs_base = 0x1337, 0x27, 0xdead0000
    tracer.write(REGS, regs.get())
    tracer._PTRACE_SETREGS(0, REGS, slave=slave.dbg)
    assert slave.dbg.rax == 0x1337
    assert slave.dbg._ptrace_orig_rax == 0x27
    assert "fs_base" not in slave.dbg.__dict__  # the tracer's copy must never clobber the TLS base


########################## WAIT BOOKKEEPING ##########################

def test_wait_status_is_the_override_when_there_is_one(tracer):
    """_ptrace_wait_status() returns the emulated status when one is set."""
    slave = Slave(NOP)
    slave.dbg._ptrace_status = 0x857f
    assert slave.dbg._ptrace_wait_status() == 0x857f


def test_wait_slave_consumes_the_stop(tracer):
    """An emulated wait on a stopped tracee returns True and consumes the stop."""
    slave = Slave(NOP)
    slave.dbg._ptrace_has_stopped.set()
    assert slave.dbg._wait_slave(WEXITED | WSTOPPED) is True
    assert not slave.dbg._ptrace_has_stopped.is_set()


def test_wait_slave_wnowait_leaves_the_stop(tracer):
    """With WNOWAIT the emulated wait reports the stop and leaves it for the next wait."""
    slave = Slave(NOP)
    slave.dbg._ptrace_has_stopped.set()
    assert slave.dbg._wait_slave(WEXITED | WSTOPPED | WNOWAIT) is True
    assert slave.dbg._ptrace_has_stopped.is_set()


@pytest.mark.timeout(5)
def test_wait_slave_wnohang_is_a_flag(tracer):
    """With WNOHANG the emulated wait returns False at once when nothing stopped, instead of blocking."""
    # waitid(..., WEXITED | WNOHANG) must not block when nothing stopped
    slave = Slave(NOP)
    assert slave.dbg._wait_slave(WEXITED | WNOHANG) is False
