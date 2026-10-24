"""Fork splitting, inferiors, ptrace emulation and bruteforce."""
import os
import signal
import time

import pytest

from support.targets import is_return

pytestmark = [
    pytest.mark.timeout(90),
    # Documented: under QEMU fork detection and re-attaching are unreliable (and the freestanding fixtures don't fork)
    pytest.mark.not_applicable("qemu", "fork detection and re-attaching are unreliable under QEMU (documented)"),
]


def NO_SPLIT(test):
    test = pytest.mark.not_applicable("libdebug", "the legacy libdebug fork can not split on fork")(test)
    test = pytest.mark.known_gap("new_libdebug", "wait_split() raises NotImplementedError")(test)
    return pytest.mark.known_gap("remote", "the child gets a new local gdb attached to its pid: impossible on a real remote host", run=False)(test)


@pytest.fixture
def forking(target_binary):
    return target_binary("forking")


@NO_SPLIT
def test_split_on_fork_with_interrupt(debugger, forking, backend):
    """
    set_split_on_fork(interrupt=True): at the fork the child gets its own Debugger in dbg.children[pid] and both parent
    and child are stopped; each can then be continued on its own.
    """
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(interrupt=True)
    dbg.c(wait=False)
    pid = dbg.wait_split()
    child = dbg.children[pid]
    assert child.pid == pid != dbg.pid
    assert not dbg.running and not child.running
    child.c()
    assert child.control.closed.is_set()
    dbg.c()
    output = dbg.p.recvall(timeout=5)
    assert b"child\n" in output and b"child exited 3" in output


@NO_SPLIT
def test_split_on_fork_without_interrupt(debugger, forking, backend):
    """
    set_split_on_fork() without interrupt: the parent keeps running through fork (its return value is the child's pid)
    while the child gets its own Debugger that can break in child_work.
    """
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork()
    dbg.until("fork")
    dbg.finish()
    child = dbg.children[dbg.wait_split()]
    assert dbg.return_value == child.pid
    child.until("child_work")
    assert child.instruction_pointer == child.symbols["child_work"]
    child.c()
    dbg.c()
    assert b"child exited 3" in dbg.p.recvall(timeout=5)


@NO_SPLIT
def test_child_keeps_the_libraries(debugger, forking, backend):
    """The Debugger of a split child knows the same libraries as its parent: same libc, same symbol addresses (puts)."""
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(interrupt=True)
    dbg.c(wait=False)
    child = dbg.children[dbg.wait_split()]
    assert child.libc is not None
    assert child.symbols["puts"] == dbg.symbols["puts"]


@NO_SPLIT
def test_split_off(debugger, forking, backend):
    """set_split_on_fork(off=True) cancels the split: the fork happens without creating a child Debugger."""
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork()
    dbg.set_split_on_fork(off=True)
    dbg.c()
    assert dbg.children == {}
    assert b"child exited 3" in dbg.p.recvall(timeout=5)


@pytest.mark.not_applicable("libdebugs", "inferiors are gdb's own objects (one per process it holds): libdebug has no equivalent")
def test_inferiors(debugger, forking, backend):
    """
    With gdb following both sides of a fork, dbg.inferiors lists them, current_inferior is the parent and
    switch_inferior() moves the debugger (and dbg.pid) between them.
    """
    dbg = debugger(forking, script="set detach-on-fork off\nset follow-fork-mode parent\n", backend=backend)
    dbg.until("parent_work")
    assert sorted(dbg.inferiors) == [1, 2]
    assert dbg.current_inferior.num == 1 and dbg.current_inferior.pid == dbg.pid
    assert dbg.inferior.num == dbg.current_inferior.num
    parent = dbg.pid
    old = dbg.switch_inferior(2)
    assert old.num == 1
    assert dbg.pid != parent
    dbg.switch_inferior(1)
    assert dbg.pid == parent


@NO_SPLIT
@pytest.mark.not_applicable("new_libdebug", "inferiors are gdb's own objects (one per process it holds): libdebug has no equivalent")
def test_split_an_existing_inferior(debugger, forking, backend):
    """_split_child(n=2) turns an inferior gdb already holds into a separate Debugger that can be driven on its own."""
    dbg = debugger(forking, script="set detach-on-fork off\nset follow-fork-mode parent\n", backend=backend)
    dbg.until("parent_work")
    child = dbg._split_child(n=2)
    child.until("child_work")
    assert child.instruction_pointer == child.symbols["child_work"]
    child.c()
    dbg.c()
    assert b"child exited 3" in dbg.p.recvall(timeout=5)


########################## PTRACE ##########################

# The ptrace emulation is replayed with the libdebug backends on a CTF challenge
PTRACE_LIBDEBUG = pytest.mark.untested("libdebugs", "covered end to end by regression/test_traps.py (libdebug and new libdebug)")


@NO_SPLIT
@PTRACE_LIBDEBUG
@pytest.mark.parametrize("mode", ["cont", "detach"])
def test_emulate_ptrace(debugger, target_binary, run_without_debugger, backend, mode):
    """A parent tracing its child behaves exactly as without a debugger, although both are debugged."""
    path = target_binary("tracer")
    argv = [path] if mode == "cont" else [path, "detach"]
    expected = run_without_debugger(argv)
    dbg = debugger(argv, binary=path, backend=backend)
    dbg.set_split_on_fork()
    dbg.emulate_ptrace()
    dbg.until("fork")
    dbg.finish()
    child = dbg.children[dbg.wait_split()]
    child.emulate_ptrace()
    dbg.c(wait=False)
    child.c(wait=False)
    assert _program_output(dbg.p.recvall(timeout=30)) == expected


def _program_output(output):
    """Drop what gdbserver prints on the same stdout as the program."""
    noise = (b"Detaching from process", b"Child exited with status", b"Process ", b"Remote debugging", b"Listening on port")
    return b"".join(line for line in output.splitlines(keepends=True) if line.strip() and not line.startswith(noise))


def test_emulate_ptrace_off_restores_the_functions(debugger, target_binary, backend):
    """emulate_ptrace() patches the libc's ptrace(); emulate_ptrace(off=True) restores its original bytes."""
    dbg = debugger(target_binary("tracer"), backend=backend)
    ptrace = dbg.read(dbg.symbols["ptrace"], 4)
    dbg.emulate_ptrace()
    assert dbg.read(dbg.symbols["ptrace"], 4) != ptrace
    dbg.emulate_ptrace(off=True)
    assert dbg.read(dbg.symbols["ptrace"], 4) == ptrace
    assert dbg.ptrace.emulated is False


# What tests/fixtures/src/sysemu_tracer.c prints without a debugger (x86-64 Linux).
SYSEMU_TRACER_OUTPUT = b"""\
stopped 1 signal 19
emulated: steps 2 status 0x857f nr 0x4042 rax -38 past_syscall 1
emulated: exit report si_code 4 si_status 0x5 rip_moved 0
native: steps 3 status 0x857f nr 0x27 rax -38 past_syscall 1
native: exit report si_code 4 si_status 0x5 rip_moved 0
native: executed status 0x57f rip_moved 2 rax_is_child 1
skipped: steps 3 status 0x857f nr 0x4043 rax -38 past_syscall 1
skipped: next request status 0x57f rip_moved 1
done: steps 3 status 0x857f nr 0x4049 rax -38 past_syscall 1
child: hypercall 0x1337 getpid_ok 1 skipped -38
exit: si_code 1 si_status 0
"""


@pytest.mark.not_applicable("not_gdb", "an oracle of the kernel: no debugger is involved, so it only runs once, in the gdb column")
def test_sysemu_tracer_oracle(fixture_binary, run_without_debugger):
    """The kernel behaviour the SYSEMU_SINGLESTEP / waitid emulation copies. If this fails, the kernel changed, not gdb_plus."""
    assert run_without_debugger([fixture_binary("sysemu_tracer")]) == SYSEMU_TRACER_OUTPUT


@pytest.mark.timeout(120)
@pytest.mark.not_applicable("foreign", "PTRACE_SYSEMU only exists on x86-64")
@pytest.mark.known_gap("remote", "the child gets a new local gdb attached to its pid: impossible on a real remote host")
@pytest.mark.untested("new_libdebug", "the SYSEMU emulation is only replayed with gdb and the legacy libdebug")
@pytest.mark.parametrize("engine", [
    "gdb",
    # the parent is still inside its final emulated waitid when the test ends (see below)
    pytest.param("libdebug", marks=[pytest.mark.libdebug, pytest.mark.allow_priority_leak]),
])
def test_emulate_ptrace_sysemu_and_waitid(debugger, fixture_binary, engine):
    """A parent driving its child with PTRACE_SYSEMU_SINGLESTEP and waitid() behaves as without a debugger."""
    dbg = debugger(fixture_binary("sysemu_tracer"))
    dbg.set_split_on_fork()
    dbg.emulate_ptrace()
    dbg.until("fork")
    dbg.finish()
    child = dbg.children[dbg.wait_split()]
    child.emulate_ptrace()
    if engine == "libdebug":
        child.migrate(libdebug=True)  # migrating the parent first breaks (regression/test_traps.py)
        dbg.migrate(libdebug=True)
    dbg.c(wait=False)
    child.c(wait=False)
    if engine == "gdb":
        assert _program_output(dbg.p.recvall(timeout=90)) == SYSEMU_TRACER_OUTPUT
    else:
        # Legacy libdebug never tells an emulated wait that the tracee exited (only gdb's exit handler
        # sets _ptrace_has_stopped), so the final waitid() blocks: check everything before it.
        before_exit = SYSEMU_TRACER_OUTPUT[:SYSEMU_TRACER_OUTPUT.index(b"exit:")]
        assert _program_output(dbg.p.recvuntil(b"skipped -38\n", timeout=90)) == before_exit
        # libdebug's detach() waits for the parent to exit, which it never does from inside that waitid
        os.kill(dbg.pid, signal.SIGKILL)


@pytest.mark.not_applicable("foreign", "the sysemu_tracer fixture drives its child with PTRACE_SYSEMU, which only exists on x86-64")
def test_emulate_ptrace_off_restores_waitid(debugger, fixture_binary, backend):
    """emulate_ptrace() also patches waitid(); emulate_ptrace(off=True) restores its original bytes."""
    dbg = debugger(fixture_binary("sysemu_tracer"), backend=backend)
    waitid = dbg.read(dbg.symbols["waitid"], 4)
    dbg.emulate_ptrace()
    assert dbg.read(dbg.symbols["waitid"], 4) != waitid
    dbg.emulate_ptrace(off=True)
    assert dbg.read(dbg.symbols["waitid"], 4) == waitid


@NO_SPLIT
def test_trace_links_two_debuggers(debugger, forking, backend):
    """
    trace(child) declares that the parent ptraces the child: the two Debuggers are linked (slave / parent) and the
    child's ptrace is emulated.
    """
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(interrupt=True)
    dbg.c(wait=False)
    child = dbg.children[dbg.wait_split()]
    dbg.trace(child)
    assert dbg.ptrace.slaves[child.pid] is child
    assert child._parent is dbg and child.ptrace.emulated
    assert dbg._process_group == {dbg.pid: dbg, child.pid: child}


########################## BRUTEFORCE ##########################

@pytest.mark.timeout(180)
@pytest.mark.not_applicable("new_libdebug", "bruteforce() runs its children with gdb or the legacy libdebug (libdebug=True)")
@pytest.mark.not_applicable("remote", "bruteforce() forks and splits the process locally")
@pytest.mark.untested("i386", "slow (forks and debugs n processes): only run on x86-64")
@pytest.mark.known_gap("gdb", "bruteforce() never returns (root cause not investigated yet)", run=False)
@pytest.mark.known_gap("libdebug", "bruteforce() never returns (root cause not investigated yet)", run=False)
def test_bruteforce(debugger, basic, backend):
    """
    bruteforce() forks the stopped process and tries a value per child (setup writes the argument, check reads
    check_secret's result) until it finds the right one, 42.
    """
    dbg = debugger(basic, aslr=False)  # always started with gdb: bruteforce() migrates the children itself
    dbg.until("check_secret")
    ret = [i.address for i in dbg.disassemble(dbg.symbols["check_secret"], 0x40) if is_return(i)][0]

    def setup(d, i):
        d.args[0] = i

    def check(d, i):
        return d.return_value == 1

    found = dbg.bruteforce(ret, check, _from="check_secret", setup=setup, limit=64, n_processes=2, libdebug=backend == "libdebug")
    assert found == 42


########################## MORE FORK / PTRACE OPTIONS ##########################

@NO_SPLIT
def test_split_child_runs_the_script(debugger, forking, backend):
    """set_split_on_fork(script=) runs that gdbscript in the gdb of every child: a convenience variable it sets is there."""
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(interrupt=True, script="set $gdb_plus_marker = 7\n")
    dbg.c(wait=False)
    child = dbg.children[dbg.wait_split()]
    assert int(child.execute("p $gdb_plus_marker").split()[-1], 0) == 7


@pytest.mark.not_applicable("libdebug", "the legacy libdebug fork can not split on fork")
@pytest.mark.known_gap("gdb_only", "set_split_on_fork(off=True) disconnects self.fork_handler, which only exists once the split was turned on (debugger/engines/gdb.py:stop_splitting)")
def test_split_off_before_it_was_on(debugger, forking, backend):
    """set_split_on_fork(off=True) on a debugger that never split is harmless: the program forks and ends normally."""
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(off=True)
    dbg.c()
    assert dbg.children == {}
    assert b"child exited 3" in dbg.p.recvall(timeout=5)


@NO_SPLIT
def test_closing_the_parent_closes_the_children(debugger, forking, backend):
    """Leaving `with dbg:` closes the parent's Debugger and the Debuggers of its split children: both processes are gone."""
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(interrupt=True)
    dbg.c(wait=False)
    child = dbg.children[dbg.wait_split()]
    with dbg:
        pass
    deadline = time.time() + 5
    while _alive(child.pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not _alive(child.pid)


def _alive(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


@NO_SPLIT
def test_trace_a_parent(debugger, forking, backend):
    """trace(parent, parent=True): the child declares that it traces its own parent; the links go the other way round."""
    dbg = debugger(forking, backend=backend)
    dbg.set_split_on_fork(interrupt=True)
    dbg.c(wait=False)
    child = dbg.children[dbg.wait_split()]
    child.trace(dbg, parent=True)
    assert child.ptrace.slaves[dbg.pid] is dbg
    assert child._parent is dbg and dbg.children[child.pid] is child
    assert dbg.ptrace.emulated


@pytest.mark.not_applicable("libdebugs", "inferiors are gdb's own objects (one per process it holds): libdebug has no equivalent")
@pytest.mark.known_gap("remote", "write() ignores inferior= with gdb: GdbBackend.write_inferior is called without it and writes in the current inferior (debugger/engines/gdb.py:write)")
@pytest.mark.known_gap("gdb", "write() ignores inferior= with gdb: GdbBackend.write_inferior is called without it and writes in the current inferior (debugger/engines/gdb.py:write)")
@pytest.mark.known_gap("i386", "write() ignores inferior= with gdb: GdbBackend.write_inferior is called without it and writes in the current inferior (debugger/engines/gdb.py:write)")
def test_read_and_write_in_another_inferior(debugger, forking, backend):
    """
    read(inferior=) and write(inferior=) access the memory of another process gdb holds (the child of a fork) without
    switching to it: the parent's memory is untouched.
    """
    dbg = debugger(forking, script="set detach-on-fork off\nset follow-fork-mode parent\n", backend=backend)
    dbg.until("parent_work")
    child = dbg.inferiors[2]
    address = dbg.symbols["parent_work"]
    original = dbg.read(address, 4)
    dbg.write(address, b"\xcc\xcc\xcc\xcc", inferior=child)
    assert dbg.read(address, 4, inferior=child) == b"\xcc\xcc\xcc\xcc"
    assert dbg.read(address, 4) == original
    assert dbg.current_inferior.num == 1


@pytest.mark.timeout(180)
@pytest.mark.not_applicable("new_libdebug", "bruteforce() runs its children with gdb or the legacy libdebug (libdebug=True)")
@pytest.mark.not_applicable("remote", "bruteforce() forks and splits the process locally")
@pytest.mark.untested("i386", "slow (forks and debugs n processes): only run on x86-64")
@pytest.mark.known_gap("gdb", "bruteforce() never returns: test_bruteforce times out the same way", run=False)
@pytest.mark.known_gap("libdebug", "bruteforce() never returns: test_bruteforce times out the same way", run=False)
def test_bruteforce_with_threads_init_and_backup(debugger, basic, backend):
    """
    bruteforce(n_threads=2, init=, backup=) runs two threads per process, calls init once per child, restores the backed
    up memory (counter) after every try, and still finds 42.
    """
    dbg = debugger(basic, aslr=False)  # always started with gdb: bruteforce() migrates the children itself
    dbg.until("check_secret")
    ret = [i.address for i in dbg.disassemble(dbg.symbols["check_secret"], 0x40) if is_return(i)][0]
    counter = dbg.symbols["counter"]

    def init(d):
        d.write_pointer(counter, 1000)

    def setup(d, i):
        # Only try i if init ran and the backup put counter back after the previous try (42 is the 11th try of its thread)
        if d.read_pointer(counter) == 1000:
            d.args[0] = i
        d.write_pointer(counter, i)

    def check(d, i):
        return d.return_value == 1

    found = dbg.bruteforce(ret, check, _from="check_secret", setup=setup, init=init, backup=[(counter, 8)], limit=64,
                           n_threads=2, n_processes=1, libdebug=backend == "libdebug")
    assert found == 42


@pytest.mark.timeout(180)
@pytest.mark.not_applicable("new_libdebug", "bruteforce() runs its children with gdb or the legacy libdebug (libdebug=True)")
@pytest.mark.not_applicable("remote", "bruteforce() forks and splits the process locally")
@pytest.mark.untested("i386", "slow (forks and debugs n processes): only run on x86-64")
@pytest.mark.known_gap("gdb", "bruteforce() never returns: test_bruteforce times out the same way", run=False)
@pytest.mark.known_gap("libdebug", "bruteforce() never returns: test_bruteforce times out the same way", run=False)
def test_bruteforce_without_a_solution(debugger, basic, backend):
    """bruteforce() over values that are all wrong (0..15) returns None once every child has tried its range."""
    dbg = debugger(basic, aslr=False)
    dbg.until("check_secret")
    ret = [i.address for i in dbg.disassemble(dbg.symbols["check_secret"], 0x40) if is_return(i)][0]

    def setup(d, i):
        d.args[0] = i

    assert dbg.bruteforce(ret, lambda d, i: d.return_value == 1, _from="check_secret", setup=setup, limit=16,
                          n_processes=2, libdebug=backend == "libdebug") is None
