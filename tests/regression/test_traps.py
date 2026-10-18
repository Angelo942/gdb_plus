"""
CSCG 'traps' (amd64, static): anti-debug, a child unpacking code under ptrace and a linear system.
The heaviest scenario of the suite: debug_from + fork splitting + ptrace emulation on every backend.
"""
import pytest

from regression.conftest import parse_matrix_line, solve_traps_matrix

pytestmark = pytest.mark.timeout(240)

ANTI_DEBUG_DONE = 0x0401590
CALLED_MMAP = 0x0402520
RWX_SECTION = 0x7ffff7ff8000
END_UNPACK = RWX_SECTION + 0x80
TRAP_PTRACE = RWX_SECTION + 0x9e
MATRIX_DATA = RWX_SECTION + 0xc2
FLAG = b"CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}"


@pytest.fixture
def traps(challenge):
    return challenge("traps_withSymbols")


def test_debug_from(debugger, traps):
    """
    debug_from= after the anti-debug checks of traps: gdb attaches only once they passed and stops at that address.
    """
    dbg = debugger(traps, aslr=False, debug_from=ANTI_DEBUG_DONE, timeout=0.4)
    assert dbg.rip == ANTI_DEBUG_DONE


def test_finish_inside_a_callback_during_next(debugger, traps):
    """finish() inside a callback hit during next() returns to the caller, and next() still completes."""
    dbg = debugger(traps, aslr=False)
    dbg.until(0x401581)
    finished = []

    def callback(d):
        d.finish()
        finished.append(d.instruction_pointer)
        return False
    dbg.b(0x433494, callback=callback)
    dbg.next()
    assert finished[0] == 0x401586


def test_close_breakpoints(debugger, traps):
    """A continuing callback on the instruction right before a stopping breakpoint: c() stops on the second one."""
    dbg = debugger(traps, aslr=False)
    dbg.b(0x401802)
    dbg.b(0x401801, callback=lambda d: False)
    dbg.c()
    assert dbg.rip == 0x401802


def test_split_with_interrupt(debugger, traps):
    """set_split_on_fork(interrupt=True) on traps: parent and child both stop right after the fork syscall."""
    dbg = debugger(traps, aslr=False, script="")
    dbg.set_split_on_fork(interrupt=True)
    dbg.c(wait=False)
    child = dbg.children[dbg.wait_split()]
    assert dbg.instruction_pointer == 0x432d37
    assert child.instruction_pointer == 0x432d37


def test_split_after_finish(debugger, traps):
    """
    set_split_on_fork() then finish() out of fork(): the parent is back in its caller and the child waits at the fork.
    """
    dbg = debugger(traps, aslr=False)
    dbg.set_split_on_fork(interrupt=False)
    dbg.until("fork")
    dbg.finish()
    child = dbg.children[dbg.wait_split()]
    assert dbg.instruction_pointer == 0x4025c0
    assert child.instruction_pointer == 0x432d37


def _split(dbg):
    dbg.set_split_on_fork()
    dbg.continue_until("fork")
    dbg.finish()
    return dbg.children[dbg.wait_split()]


def test_ptrace_emulation(debugger, traps):
    """
    The full scenario: the child unpacks code under its parent's ptrace; with emulate_ptrace() on both and the child
    stepped by hand the right flag gives "YES !".
    """
    dbg = debugger(traps, aslr=False, debug_from=ANTI_DEBUG_DONE)
    child = _split(dbg)
    child.emulate_ptrace(silent=True)
    dbg.emulate_ptrace(silent=True)
    dbg.p.sendline(FLAG)
    done = dbg.c(wait=False)
    child.continue_until(CALLED_MMAP)
    for _ in range(1, 5):
        child.continue_until(END_UNPACK, hw=True, loop=True)
    child.continue_until(TRAP_PTRACE, loop=True)
    child.step()
    child.return_value = 0x0
    child.c()
    assert b"YES !" in dbg.p.recv()
    done.wait()


def _dump_matrix(child, patch_trap):
    A, b = [], []
    child.continue_until(CALLED_MMAP)
    for i in range(1, 21):
        child.continue_until(END_UNPACK, hw=True, loop=True)
        if patch_trap and i == 4:
            child.continue_until(TRAP_PTRACE, loop=True)
            child.step()
            child.return_value = 0x0
        if i in range(5, 5 + 0x10):
            A.append(parse_matrix_line(child.read(MATRIX_DATA, 0x40)))
            b.append(int.from_bytes(child.read(MATRIX_DATA + 0x40, 4), "little"))
    return A, b


@pytest.mark.sage
@pytest.mark.allow_priority_leak  # the parent is still inside an emulated waitpid when the test ends
def test_ptrace_emulation_on_the_syscall(debugger, traps):
    """
    emulate_ptrace(syscall=True) catches the ptrace syscalls instead of the libc function; the linear system dumped from
    the child solves to the flag.
    """
    dbg = debugger(traps, aslr=False, debug_from=ANTI_DEBUG_DONE)
    child = _split(dbg)
    child.emulate_ptrace(syscall=True, silent=True)
    dbg.p.sendline(b"A" * 0x40)
    dbg.emulate_ptrace(syscall=True, silent=True)
    dbg.cont(wait=False)
    assert solve_traps_matrix(*_dump_matrix(child, patch_trap=False)) == FLAG


@pytest.mark.sage
@pytest.mark.libdebug
@pytest.mark.allow_priority_leak  # the parent is still inside an emulated waitpid when the test ends
def test_ptrace_emulation_with_libdebug(debugger, traps):
    """The same scenario after migrating child and parent to the legacy libdebug."""
    dbg = debugger(traps, aslr=False, debug_from=ANTI_DEBUG_DONE)
    dbg.set_split_on_fork()
    dbg.emulate_ptrace(silent=True)
    dbg.continue_until("fork")
    dbg.finish()
    child = dbg.children[dbg.wait_split()]
    child.emulate_ptrace(silent=True)
    dbg.p.sendline(b"A" * 0x40)
    child.migrate(libdebug=True)  # the legacy test notes that migrating the parent first breaks
    dbg.migrate(libdebug=True)
    dbg.cont(wait=False)
    assert solve_traps_matrix(*_dump_matrix(child, patch_trap=True)) == FLAG


@pytest.mark.sage
@pytest.mark.libdebug
@pytest.mark.new_libdebug
@pytest.mark.allow_priority_leak  # the parent is still inside an emulated waitpid when the test ends
def test_ptrace_emulation_with_new_libdebug(debugger, traps):
    """The same scenario with the parent on new libdebug and the child on the legacy libdebug."""
    dbg = debugger(traps, aslr=False, debug_from=ANTI_DEBUG_DONE)
    dbg.set_split_on_fork()
    dbg.emulate_ptrace(silent=True)
    dbg.continue_until("fork")
    dbg.finish()
    child = dbg.children[dbg.wait_split()]
    child.emulate_ptrace(silent=True)
    dbg.p.sendline(b"A" * 0x40)
    child.migrate(libdebug=True)  # the child can not use new_libdebug here
    dbg.migrate(new_libdebug=True)
    dbg.cont(wait=False)
    assert solve_traps_matrix(*_dump_matrix(child, patch_trap=True)) == FLAG
