"""Every way of starting, attaching to, detaching from and closing a debugger."""
import os
import signal
import threading
import time
from pathlib import Path
from threading import Event

import pytest
from pwn import ELF, args, context, process

from gdb_plus.utils.exe import EXE
from support.local_server import serve_binary

# Debugger() always starts the process with gdb; the libdebug backends only exist after migrate()
CONSTRUCTION = pytest.mark.not_applicable("libdebugs", "Debugger() always starts with gdb: the libdebug backends come later, with migrate()")
# A (host, port) target is already running under gdbserver: how to start or attach to it is not ours to choose
NO_LOCAL_PROCESS = pytest.mark.not_applicable("remote", "the target is a gdbserver: there is no local process to start or attach to")
# QEMU starts the program itself, gdb_plus refuses to attach to an emulated process (documented)
NO_ATTACH_UNDER_QEMU = pytest.mark.not_applicable("qemu", "gdb_plus can't attach to a process under QEMU (documented)")
STATIC = pytest.mark.not_applicable("qemu", "the QEMU fixtures are static: no loader, no libc")

# qemu-user only stops a guest between two instructions, not inside a host syscall
QEMU_BLOCKED_READ = pytest.mark.not_applicable("qemu", "qemu-user can't stop a guest blocked in a syscall: the interrupt waits for read() to return (gdb_plus warns about it)")


def _alive(pid):
    try:
        os.kill(pid, 0)
        return open(f"/proc/{pid}/stat").read().split()[2] != "Z"
    except OSError:
        return False


def test_starts_at_the_entry_point(debugger, basic, backend):
    """
    Debugger(binary) starts the process stopped at the executable's entry point, with the PIE base at gdb's usual
    0x555555554000 when aslr=False and the libc already mapped.
    """
    dbg = debugger(basic, aslr=False, backend=backend)
    assert dbg.instruction_pointer == dbg.exe.entry
    if dbg.exe.pie and context.arch == "amd64":
        assert dbg.exe.address == 0x555555554000
    if not dbg.exe.statically_linked:
        assert dbg.libc is not None
    if dbg.exe.pie:  # the range of the others: test_non_pie_executable_has_a_range
        assert dbg.instruction_pointer in dbg.exe


def test_non_pie_executable_has_a_range(debugger, fixture_binary, target_binary, backend):
    """
    For a non PIE executable dbg.exe.address is the address in the ELF, dbg.exe has an end address and the instruction
    pointer is inside its range.
    """
    path = fixture_binary("basic_nopie") if backend in ["gdb", "libdebug", "new_libdebug", "remote"] else target_binary("basic")
    dbg = debugger(path, backend=backend)
    assert not dbg.exe.pie
    assert dbg.exe.address == ELF(path, checksec=False).address
    assert dbg.exe.end_address is not None
    assert dbg.instruction_pointer in dbg.exe


@CONSTRUCTION
@STATIC
def test_from_entry_false_stops_in_the_loader(debugger, basic, backend):
    """from_entry=False stops at the first instruction of the loader (ld.so), before the executable has run."""
    dbg = debugger(basic, from_entry=False, backend=backend)
    assert dbg.ld is not None
    assert dbg.instruction_pointer in dbg.ld
    assert dbg.instruction_pointer not in dbg.exe


@CONSTRUCTION
@pytest.mark.not_applicable("remote", "the test passes a path, an ELF or an EXE as target: a remote target is a (host, port) tuple instead")
@pytest.mark.parametrize("kind", ["str", "ELF", "EXE"])
def test_target_types(debugger, basic, backend, kind):
    """The target can be a path, a pwntools ELF or a gdb_plus EXE: all of them start the same binary."""
    target = {"str": basic, "ELF": ELF(basic, checksec=False), "EXE": EXE(basic, checksec=False)}[kind]
    dbg = debugger(target, backend=backend)
    assert dbg.exe.path == basic
    dbg.c(wait=False)
    dbg.p.sendline(b"x")
    assert b"line x" in dbg.p.recvall(timeout=5)


@CONSTRUCTION
def test_argv_and_env(debugger, basic, backend):
    """A list target passes argv to the program and env= its environment: the fixture prints both back."""
    # no spaces: gdbserver --wrapper splits them
    dbg = debugger([basic, "hello"], binary=basic, env={"GDB_PLUS_TEST": "from_env"}, backend=backend)
    dbg.c(wait=False)
    dbg.p.sendline(b"x")
    output = dbg.p.recvall(timeout=5)
    assert b"argv hello" in output
    assert b"env from_env" in output


@CONSTRUCTION
def test_context_comes_from_the_binary(debugger, basic, backend):
    """Debugger() sets pwntools' context (arch, bits, endianness) from the binary, even after context.clear()."""
    terminal = context.terminal
    context.clear()
    context.terminal = terminal  # clear() also forgets the headless terminal of the suite
    dbg = debugger(basic, backend=backend)
    assert dbg._context_params["arch"] == ELF(basic, checksec=False).arch


@CONSTRUCTION
def test_script_runs_in_gdb(debugger, basic, backend):
    """script= is run by gdb at start-up: a convenience variable it sets can be read back with execute()."""
    dbg = debugger(basic, script="set $gdb_plus_marker = 42\n", backend=backend)
    assert int(dbg.execute("p $gdb_plus_marker").split()[-1], 0) == 42  # GEF prints in hex


@CONSTRUCTION
@NO_LOCAL_PROCESS
def test_silent(debugger, basic, backend, capfd):
    """silent=False lets pwntools log how the process is started; by default gdb_plus keeps it quiet."""
    # silent=False lets pwntools log how the process is started
    with context.local(log_level="info"):
        debugger(basic, backend=backend)
        quiet = capfd.readouterr()
        debugger(basic, silent=False, backend=backend)
        loud = capfd.readouterr()
    assert "Starting" not in quiet.out + quiet.err
    assert "Starting" in loud.out + loud.err


@CONSTRUCTION
@NO_LOCAL_PROCESS
@STATIC
def test_aslr(debugger, basic, backend):
    """
    aslr=False gives the same libc address on every run, aslr=True a different one, and the ASLR command line switch
    forces it on.
    """
    # The libc moves between two runs with aslr=True (also forced by the ASLR switch), not with aslr=False
    fixed = [debugger(basic, aslr=False, backend=backend).libc.address for _ in range(2)]
    assert fixed[0] == fixed[1]
    assert debugger(basic, aslr=True, backend=backend).libc.address != fixed[0]
    args.ASLR = "1"
    assert debugger(basic, aslr=False, backend=backend).libc.address != fixed[0]


# BUG: The symbols don't get updated once we change the address
@NO_LOCAL_PROCESS
@NO_ATTACH_UNDER_QEMU
def test_attach_to_process(debugger, basic, backend):
    """
    Debugger(process) attaches to a pwntools process that is already running and keeps using its tube for input and
    output.
    """
    with context.local(log_level="error"):
        p = process(basic)
    p.recvuntil(b"ready\n")
    dbg = debugger(p, backend=backend)
    assert dbg.pid == p.pid
    assert dbg.read(dbg.symbols["buffer"], 14) == b"buffer content"
    dbg.c(wait=False)
    p.sendline(b"attached")
    assert b"line attached" in p.recvall(timeout=5)


@NO_LOCAL_PROCESS
@NO_ATTACH_UNDER_QEMU
def test_attach_to_pid(debugger, basic, backend):
    """
    Debugger(pid, binary=) attaches to a running process by pid: no tube (dbg.p is None) but memory is readable and
    writable, and detach() leaves it running.
    """
    with context.local(log_level="error"):
        p = process(basic)
    p.recvuntil(b"ready\n")
    dbg = debugger(p.pid, binary=basic, backend=backend)
    assert dbg.p is None
    assert dbg.read(dbg.symbols["buffer"], 14) == b"buffer content"
    dbg.write(dbg.symbols["buffer"], b"BUFFER")
    assert dbg.read(dbg.symbols["buffer"], 6) == b"BUFFER"
    dbg.detach()
    p.close()


@CONSTRUCTION
@NO_LOCAL_PROCESS
@NO_ATTACH_UNDER_QEMU
def test_from_start_false(debugger, basic, backend):
    """
    from_start=False lets the process run instead of stopping at the entry point; the program reads its input normally.
    """
    dbg = debugger(basic, from_start=False, backend=backend)
    dbg.c(wait=False)
    dbg.p.sendline(b"x")
    assert b"line x" in dbg.p.recvall(timeout=5)


@CONSTRUCTION
@NO_LOCAL_PROCESS
@NO_ATTACH_UNDER_QEMU
def test_debug_from(debugger, basic, backend):
    """
    debug_from="main_start" runs the program without a debugger and attaches only when it reaches that address, so anti-
    debug checks before it see no tracer.
    """
    # Attach only once the program reaches the address: anti-debug checks before it see no tracer
    dbg = debugger(basic, aslr=False, debug_from="main_start", timeout=0.2, backend=backend)
    assert dbg.instruction_pointer == dbg.symbols["main_start"]
    dbg.c(wait=False)
    dbg.p.sendline(b"x")
    assert b"result 374" in dbg.p.recvall(timeout=5)


@CONSTRUCTION
@NO_LOCAL_PROCESS
@NO_ATTACH_UNDER_QEMU
def test_non_blocking_debug_from(debugger, basic, backend):
    """
    debug_from(..., event=) lets the script interact with the program first and attaches once the event is set;
    debug_from_done signals when the debugger is ready.
    """
    interaction_finished = Event()
    dbg = debugger(basic, aslr=False, backend=backend).debug_from("after_input", event=interaction_finished, timeout=0.05)
    dbg.p.recvuntil(b"ready\n")
    dbg.p.sendline(b"typed before attaching")
    interaction_finished.set()
    assert dbg.debug_from_done.wait(10)
    assert dbg.instruction_pointer == dbg.symbols["after_input"]


def test_close_kills_the_process(debugger, basic, backend):
    """Closing the debugger (with dbg:) kills the debugged process."""
    dbg = debugger(basic, backend=backend)
    pid = dbg.pid
    with dbg:
        pass
    time.sleep(0.2)
    assert not _alive(pid)


def test_detach_lets_the_process_run(debugger, basic, backend):
    """detach() removes the breakpoints and lets the process run freely to its end."""
    dbg = debugger(basic, backend=backend)
    dbg.b("after_input")
    dbg.detach()
    dbg.p.sendline(b"free")
    assert b"line free" in dbg.p.recvall(timeout=5)


def test_process_exit(debugger, basic, backend):
    """When the program exits, c() returns and the debugger knows it is closed (_closed is set)."""
    dbg = debugger(basic, backend=backend)
    dbg.p.sendline(b"bye")
    dbg.c()
    assert dbg._closed.is_set()
    assert b"line bye" in dbg.p.recvall(timeout=5)


def test_tube_methods_are_forwarded(debugger, basic, backend):
    """
    The pwntools tube methods (recvuntil, sendline, recvall...) can be called on the Debugger itself: they go to the
    process.
    """
    dbg = debugger(basic, backend=backend)
    dbg.c(wait=False)
    assert dbg.recvuntil(b"ready\n").endswith(b"ready\n")
    dbg.sendline(b"forwarded")
    assert b"line forwarded" in dbg.recvall(timeout=5)


@pytest.mark.known_gap("new_libdebug", "repr() returns libdebug's own repr")
def test_repr(debugger, basic, backend):
    """repr(dbg) shows the pid and whether the process is running."""
    dbg = debugger(basic, backend=backend)
    assert repr(dbg).startswith(f"Debugger [{dbg.pid}] <not running>")


@pytest.mark.known_gap("libdebug", "interrupt() raises NotImplementedError for the legacy libdebug")
@QEMU_BLOCKED_READ
def test_running(debugger, basic, backend):
    """dbg.running is False while stopped, True after c(wait=False) and False again after interrupt()."""
    dbg = debugger(basic, backend=backend)
    assert not dbg.running
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    assert dbg.running
    dbg.interrupt()
    assert not dbg.running


def test_execute_action_and_wait(debugger, basic, backend):
    """
    The low level pair under every action: execute_action() starts the engine (gdb's continue, libdebug's cont) and
    wait() blocks until the next stop.
    """
    # The low level pair under every action: start something that runs, then wait for the next stop
    dbg = debugger(basic, backend=backend)
    dbg.b("tick")
    if dbg.gdb is not None:
        dbg.execute_action("continue", sender="test")
    elif dbg.libdebug is not None:
        dbg.execute_action(lambda: dbg.libdebug.cont(blocking=False), sender="test")
    else:
        dbg.execute_action(lambda: dbg.new_libdebug.cont(), sender="test")
    dbg.wait()
    assert dbg.instruction_pointer == dbg.symbols["tick"]


########################## CTF SWITCHES ##########################

SWITCH = [pytest.mark.not_applicable("libdebugs", "NOPTRACE and REMOTE start no debugger at all: there is no libdebug backend to choose"),
          pytest.mark.not_applicable("remote", "the switch changes how a local binary is started (or replaces it with a connection): a gdbserver target is already started"),
          pytest.mark.untested("foreign", "the switch only changes how the process is started: covered on x86-64")]


def _switch(test):
    for mark in SWITCH:
        test = mark(test)
    return test


@_switch
def test_noptrace_disables_every_action(debugger, basic):
    """
    With the NOPTRACE switch nothing is debugged: debugging is False, every action returns a neutral value (None, 0,
    zero bytes) and the program runs normally.
    """
    with context.local(noptrace=True):
        dbg = debugger(basic)
        assert dbg.debugging is False
        assert dbg.gdb is None
        assert dbg.b("main") is None
        assert dbg.c() is None
        assert dbg.rax == 0
        assert dbg.read(0x1000, 4) == b"\x00" * 4
        assert dbg.args[3] == 0
        assert dbg.children[1234] is dbg
        dbg.p.sendline(b"plain")
        assert b"line plain" in dbg.p.recvall(timeout=5)


@_switch
def test_remote_switch(debugger, basic):
    """
    With the REMOTE switch, remote(host, port) connects to the challenge server instead of debugging the local binary.
    """
    with serve_binary([basic]) as (host, port):
        args.REMOTE = "1"
        dbg = debugger(basic).remote(host, port)
        assert dbg.debugging is False
        assert dbg.p.recvuntil(b"ready\n")
        dbg.p.sendline(b"remote")
        assert b"line remote" in dbg.p.recvall(timeout=5)


@_switch
def test_connect_while_debugging(debugger, basic):
    """
    connect() opens a connection to the remote target while debugging: with overwrite=False it is kept in dbg.r next to
    the local process, otherwise it replaces dbg.p.
    """
    with serve_binary([basic]) as (host, port):
        dbg = debugger(basic).remote(host, port)
        local = dbg.p
        dbg.connect(overwrite=False)
        assert dbg.p is local
        assert dbg.r.recvuntil(b"ready\n")
        dbg.connect()
        assert dbg.p is not local
        assert dbg.p.recvuntil(b"ready\n")


########################## DETACH / GDB DEATH ##########################

def _state(pid):
    """The state letter of /proc/<pid>/stat: R running, S sleeping, T stopped, Z zombie"""
    return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]


def test_detach_without_quit_leaves_the_process_running(debugger, basic, backend):
    """
    detach(quit=False) stops debugging without killing the program: it then reads its input and runs to its end on its
    own.
    """
    dbg = debugger(basic, backend=backend)
    dbg.until("main_start")
    dbg.detach(quit=False)
    dbg.p.sendline(b"left alone")
    assert b"line left alone" in dbg.p.recvall(timeout=5)


@pytest.mark.known_gap("new_libdebug", "detach(block=True) on new libdebug calls self.logger.warn_once: a logging.Logger has no warn_once (gdb_plus.py:detach)")
@pytest.mark.known_gap("qemu", "detach(block=True) sends SIGSTOP to qemu itself before `detach`: the stopped gdbstub never answers gdb", run=False)
def test_detach_with_block_leaves_the_process_stopped(debugger, basic, backend):
    """
    detach(quit=False, block=True) leaves the program stopped (state T in /proc/<pid>/stat) so that another tool can
    attach; a SIGCONT lets it run to its end.
    """
    dbg = debugger(basic, backend=backend)
    dbg.until("main_start")
    pid = dbg.pid
    dbg.detach(quit=False, block=True)
    deadline = time.time() + 5
    while _state(pid) != "T" and time.time() < deadline:
        time.sleep(0.05)
    assert _state(pid) == "T"
    os.kill(pid, signal.SIGCONT)
    dbg.p.sendline(b"resumed")
    assert b"line resumed" in dbg.p.recvall(timeout=5)


def _gdb_pid(dbg):
    return int(dbg.execute("python gdb.write(str(__import__('os').getpid()))"))


@pytest.mark.not_applicable("libdebugs", "about the gdb process dying under the script: the libdebug backends run in the script's own process")
@pytest.mark.known_gap("i386", "instruction_pointer catches every exception while reading eip and raises its own PwnlibException: the GdbDiedError is lost (gdb_plus.py:instruction_pointer)")
def test_gdb_dying_wakes_the_script(debugger, basic, backend):
    """
    If gdb dies (killed, crashed, `quit` typed in its terminal) while the script waits in c(), c() raises GdbDiedError
    instead of hanging, and so does every later action.
    """
    from gdb_plus import GdbDiedError
    dbg = debugger(basic, backend=backend)
    dbg.b("after_input")  # never reached: the program waits for input
    gdb = _gdb_pid(dbg)
    threading.Timer(1, os.kill, (gdb, signal.SIGKILL)).start()
    with pytest.raises(GdbDiedError):
        dbg.c()
    with pytest.raises(GdbDiedError):
        dbg.instruction_pointer


@_switch
def test_libs_without_debugging(debugger, basic):
    """
    With the NOPTRACE switch there is no process to read the maps of: dbg.libs still lists the libraries the binary
    loads (the libc), each with a [start, end] pair.
    """
    with context.local(noptrace=True):
        dbg = debugger(basic)
        libs = dbg.libs
        assert any("libc" in Path(path).name for path in libs)
        assert all(len(addresses) == 2 for addresses in libs.values())
