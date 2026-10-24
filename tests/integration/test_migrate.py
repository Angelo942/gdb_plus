"""migrate() between gdb, legacy libdebug and new libdebug keeps the state of the debugging session."""
import pytest

TARGETS = [pytest.param("libdebug", marks=pytest.mark.libdebug), pytest.param("new_libdebug", marks=pytest.mark.new_libdebug)]

pytestmark = [
    pytest.mark.not_applicable("gdb", "every test here starts with gdb and migrates to a libdebug backend: a gdb column would migrate from gdb to gdb"),
    pytest.mark.not_applicable("gdbserver", "libdebug debugs local processes: migrate() is refused on a gdbserver target (test_gdbserver.py checks it)"),
    pytest.mark.not_applicable("qemu", "libdebug can't debug a process under QEMU (migrate asserts context.native)"),
    pytest.mark.untested("i386", "the legacy libdebug is x86-64 only; new libdebug on i386: test_architectures.py::test_new_libdebug_on_i386"),
]


@pytest.fixture
def dbg(debugger, basic):
    dbg = debugger(basic, aslr=False)
    dbg.until("add")
    return dbg


@pytest.mark.parametrize("target", TARGETS)
def test_keeps_the_position(dbg, target):
    """
    After migrate() from gdb to a libdebug backend, gdb is detached, the process is still stopped at the same address
    and step() works with the new engine.
    """
    address = dbg.instruction_pointer
    dbg.migrate(**{target: True})
    assert dbg.gdb is None
    assert dbg.instruction_pointer == address
    size = dbg.next_inst.size
    dbg.step()
    assert dbg.instruction_pointer == address + size


@pytest.mark.parametrize("target", TARGETS)
def test_keeps_the_breakpoints(dbg, target):
    """
    migrate() replays the breakpoint table on the new engine: a stopping breakpoint still stops and a continuing
    callback still runs (the program counts 5 ticks).
    """
    dbg.b("outer")
    dbg.b("tick", callback=lambda d: False)
    dbg.migrate(**{target: True})
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["outer"]
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"counter 5" in dbg.p.recvall(timeout=5)


@pytest.mark.parametrize("target", [
    pytest.param("libdebug", marks=[pytest.mark.libdebug, pytest.mark.xfail(strict=True, reason="migrate(libdebug=True) sets every breakpoint as a software one (TODO in migrate)")]),
    pytest.param("new_libdebug", marks=pytest.mark.new_libdebug),
])
def test_keeps_hardware_breakpoints(dbg, target):
    """A hardware breakpoint set with gdb is still a hardware breakpoint in the new engine after migrate()."""
    dbg.b("outer", hw=True)
    dbg.migrate(**{target: True})
    native = dbg.control.breakpoints[dbg.symbols["outer"]][0].native_breakpoint
    assert getattr(native, "hardware", getattr(native, "hw", False))


@pytest.mark.parametrize("target", TARGETS)
def test_round_trip(dbg, target):
    """
    migrate() to libdebug and back to gdb: the position reached with libdebug is kept and gdb's breakpoints work again.
    """
    address = dbg.instruction_pointer
    dbg.migrate(**{target: True})
    dbg.step()
    after_step = dbg.instruction_pointer
    assert after_step != address
    dbg.migrate(gdb=True)
    assert dbg.gdb is not None and dbg.libdebug is None and dbg.new_libdebug is None
    assert dbg.instruction_pointer == after_step
    dbg.b("outer")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["outer"]


@pytest.mark.parametrize("target", TARGETS)
def test_catchpoints_are_dropped(dbg, target):
    """
    Catchpoints (gdb only) are dropped by migrate() to libdebug instead of breaking it: the program runs to its end.
    """
    dbg.catch_syscall("getpid")
    dbg.migrate(**{target: True})
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"result" in dbg.p.recvall(timeout=5)


@pytest.mark.parametrize("target", [
    pytest.param("libdebug", marks=pytest.mark.libdebug),
    pytest.param("new_libdebug", marks=[pytest.mark.new_libdebug, pytest.mark.xfail(strict=True, reason="migrate(gdb=True) from new libdebug calls detach(block=True), whose default quit=True kills the process (debugger/backends.py:migrate)")]),
])
def test_back_to_gdb_runs_the_script(dbg, target):
    """migrate(gdb=True, script=...) runs the gdbscript in the new gdb: a convenience variable it sets can be read back."""
    dbg.migrate(**{target: True})
    dbg.migrate(gdb=True, script="set $gdb_plus_marker = 5\n")
    assert int(dbg.execute("p $gdb_plus_marker").split()[-1], 0) == 5


@pytest.mark.parametrize("target", [
    pytest.param(name, marks=[getattr(pytest.mark, name), pytest.mark.xfail(strict=True, reason="migrate() called from a callback fails inside the breakpoint handler thread: gdb is detached while __handle_breakpoints still uses it, and the exception is lost with the thread")])
    for name in ["libdebug", "new_libdebug"]])
def test_migrate_from_a_callback(dbg, target):
    """
    A callback can call migrate() and return False: the program goes on under the new engine and stops at the next
    breakpoint (after_input), whose ticks all ran.
    """
    migrated = []

    def callback(d):
        d.migrate(**{target: True})
        migrated.append(d.gdb is None)
        return False
    dbg.b("outer", callback=callback)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert migrated == [True]
    assert dbg.instruction_pointer == dbg.symbols["after_input"]
    assert dbg.read_pointer("counter") == 5
