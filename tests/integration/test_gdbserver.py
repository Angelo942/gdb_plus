"""
Debugger((host, port)) on a gdbserver: no local process object, files may have to be downloaded.
Each test runs on the gdbserver of this machine (remote) and on the one of the arm64 machine given with
--remote-gdbserver=user@host (aarch64_remote), reached through an ssh tunnel (support/remote_host.py).
Every other feature also runs through a local gdbserver: the `remote` target of the axis (integration/conftest.py).
"""
from contextlib import contextmanager
from pathlib import Path
from queue import Queue

import pytest
from pwnlib.exception import PwnlibException

from support.local_server import gdbserver
from support.targets import after_call, call_to, read_c_long

pytestmark = [
    pytest.mark.not_applicable("native", "about connecting to a gdbserver: a local process is debugged directly"),
    pytest.mark.not_applicable("aarch64_native", "about connecting to a gdbserver: on the arm64 machine itself a local "
                                                 "process is debugged directly"),
    pytest.mark.untested("i386", "a gdbserver of the host's architecture: the remote target of the axis runs the x86-64 fixture"),
    pytest.mark.untested("qemu", "foreign architectures are reached through QEMU's gdbstub: test_architectures.py::test_qemu_gdbstub"),
]

@pytest.fixture(params=["remote", pytest.param("aarch64_remote", marks=pytest.mark.remote_gdbserver)])
def backend(request):
    """
    Where the gdbserver runs: on this machine (remote) or on the arm64 machine of --remote-gdbserver (aarch64_remote).
    Replaces the target axis of integration/conftest.py for this module; `basic` follows it.
    """
    return request.param

@pytest.fixture
def start_server(request, backend, basic):
    """start_server() -> context manager that runs `basic` under a gdbserver of the target and yields its (host, port)"""
    if backend == "remote":
        return lambda: gdbserver([basic])
    host = request.getfixturevalue("remote_host")

    @contextmanager
    def start():
        with host.gdbserver([host.remote_path(Path(basic).name)]) as (_, address):
            yield address
    return start

@pytest.fixture
def server(start_server):
    with start_server() as address:
        yield address

@pytest.fixture
def read_on_server(request, backend):
    """read_on_server(path) -> content of a file of the machine that runs the gdbserver"""
    if backend == "remote":
        return lambda path: Path(path).read_bytes()
    return request.getfixturevalue("remote_host").read_file

@pytest.fixture
def dbg(debugger, basic, backend):
    """A debugger on a gdbserver started by the debugger fixture: dbg.p is the program's stdin and stdout"""
    return debugger(basic, backend=backend)

########################## CONNECTION ##########################

def test_connect(debugger, basic, server):
    """
    Debugger((host, port)) connects to a gdbserver: there is no local tube (dbg.p is None, local_debugging False), the
    pid is known and the process waits at the entry point.
    """
    dbg = debugger(server, binary=basic, aslr=False)
    assert dbg.p is None
    assert dbg.local_debugging is False
    assert dbg.pid is not None
    assert dbg.instruction_pointer == dbg.exe.entry

def test_breakpoints_and_memory(debugger, basic, server):
    """Through a gdbserver, breakpoints stop the process and memory can be read and written like on a local process."""
    dbg = debugger(server, binary=basic)
    dbg.b("tick")
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["tick"]
    assert dbg.read_string("buffer") == b"buffer content"
    dbg.write(dbg.symbols["buffer"], b"REMOTE")
    assert dbg.read(dbg.symbols["buffer"], 6) == b"REMOTE"

def test_maps_come_from_gdb(debugger, basic, server):
    """
    Without /proc of the remote process, dbg.libs, dbg.libc and the range of dbg.exe are rebuilt from what gdb reports
    about the mappings.
    """
    dbg = debugger(server, binary=basic)
    assert any(path.endswith("/basic") for path in dbg.libs)
    assert dbg.libc is not None
    assert dbg.instruction_pointer in dbg.exe

@pytest.mark.xfail(strict=True, reason="pwntools >= 4.14 refuses gdb.attach((host, port)) without exe")
def test_executable_is_found_without_binary(debugger, server, basic):
    """
    With download=True and no binary=, the executable is fetched from the gdbserver. Expected to fail: pwntools >= 4.14
    refuses gdb.attach((host, port)) without exe.
    """
    dbg = debugger(server, download=True)
    assert dbg.exe is not None
    assert dbg.exe.name == "basic"

@pytest.mark.untested("aarch64_remote", "checks that the executable found through `info proc` is the file already on "
                                       "this machine: the fixture of the arm64 gdbserver only exists there "
                                       "(test_executable_is_found_without_binary covers the download)")
@pytest.mark.xfail(strict=True, reason="pwnlib.gdb.attach((host, port)) without exe looks for the gdbserver with "
                                       "proc.pidof((host, port)), which matches the processes connected to that address, "
                                       "never the listening one: no exe, no pid, it raises before find_executable() can "
                                       "read `info proc` (debugger/engines/gdb.py:attach)")
def test_attach_without_binary_finds_the_executable(debugger, server, basic):
    """
    Debugger((host, port)) with no binary= asks gdb which file the remote process runs (`info proc`) and loads it: on a
    gdbserver of this machine dbg.exe is the fixture and its symbols resolve to the remote process.
    """
    dbg = debugger(server, aslr=False)
    assert dbg.exe is not None
    assert Path(dbg.exe.path).resolve() == Path(basic).resolve()
    assert dbg.instruction_pointer == dbg.exe.entry
    assert dbg.symbols["tick"] == dbg.exe.symbols["tick"]

########################## FILES ##########################

def test_download_libraries(debugger, server, basic):
    """download=True copies the remote libc into ./gdb_files and dbg.libc points at that copy."""
    dbg = debugger(server, binary=basic, download=True)
    assert dbg.libc is not None
    assert Path("gdb_files", Path(dbg.libc.path).name).is_file()
    assert Path(dbg.libc.path).resolve().parent == Path("gdb_files").resolve()

def test_downloaded_files_are_reused(debugger, basic, start_server):
    """
    A second session with download=True reuses the files already in gdb_files instead of downloading them again (same
    modification time).
    """
    with start_server() as address:
        first = debugger(address, binary=basic, download=True)
        library = Path(first.libc.path)
        first_download = library.stat().st_mtime_ns
    with start_server() as address:
        second = debugger(address, binary=basic, download=True)
        assert Path(second.libc.path).stat().st_mtime_ns == first_download

def test_access_library_by_remote_path(debugger, basic, server):
    """
    access_library() accepts the path a library has on the server: it is downloaded to gdb_files and placed at the base
    address the remote maps give.
    """
    dbg = debugger(server, binary=basic, download=True)
    remote_libc = next(path for path in dbg.libs if Path(path).name.startswith("libc"))
    assert dbg.remote_path(Path(remote_libc).name) == Path(remote_libc)
    library = dbg.access_library(remote_libc)
    assert library is not None
    assert library.address == dbg.libs[remote_libc][0]
    assert Path(library.path).resolve().parent == Path("gdb_files").resolve()

def test_download(debugger, basic, server, read_on_server):
    """download(remote_path, local_path) copies any file of the server: the copy is byte for byte the remote libc."""
    dbg = debugger(server, binary=basic)
    remote_libc = next(path for path in dbg.libs if Path(path).name.startswith("libc"))
    dbg.download(remote_libc, "copy_of_libc")
    assert Path("copy_of_libc").read_bytes() == read_on_server(remote_libc)

########################## CONTROL FLOW ##########################

def test_breakpoint_callback_keeps_running(dbg):
    """
    A callback on tick() that returns False runs once per call (it sees counter 0..4) without waking the script, which
    stops at the next breakpoint, after_input.
    """
    hits = []
    dbg.b("tick", callback=lambda d: hits.append(read_c_long(d, "counter")) or False)
    dbg.b("after_input")
    dbg.p.sendline(b"x")
    dbg.c()
    assert hits == [0, 1, 2, 3, 4]
    assert dbg.instruction_pointer == dbg.symbols["after_input"]

def test_step_enters_a_call(dbg):
    """step() on the call to inner() in outer() stops on the first instruction of inner()."""
    call = call_to(dbg, "outer", "inner")
    dbg.until(call.address)
    dbg.step()
    assert dbg.instruction_pointer == dbg.symbols["inner"]

def test_next_steps_over_a_call(dbg):
    """
    next() on the call to inner() in outer() stops on the instruction after the call, with inner(20)'s result (40) in
    the return register.
    """
    call = call_to(dbg, "outer", "inner")
    dbg.until(call.address)
    dbg.next()
    assert dbg.instruction_pointer == after_call(call)
    assert dbg.return_value == 40

def test_finish_returns_to_the_caller(dbg):
    """finish() at the entry of inner() runs to the return address in outer(), with the return value 40."""
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("inner")
    dbg.finish()
    assert dbg.instruction_pointer == return_address
    assert dbg.return_value == 40

def test_interrupt_a_blocking_read(dbg):
    """
    interrupt() stops a process blocked in read() inside the libc (gdb asks the gdbserver: there is no local pid to
    signal), and c() then resumes it so that it receives the line sent afterwards.
    """
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    dbg.interrupt()
    assert not dbg.running
    assert dbg.instruction_pointer not in dbg.exe
    done = dbg.c(wait=False)
    dbg.p.sendline(b"after interrupt")
    assert done.wait(10)
    assert b"line after interrupt" in dbg.p.recvall(timeout=5)

########################## LOCAL-ONLY ACTIONS ##########################

LOCAL_ONLY_ACTIONS = {
    "migrate": lambda dbg: dbg.migrate(new_libdebug=True),
    "set_split_on_fork": lambda dbg: dbg.set_split_on_fork(),
    "detach_block": lambda dbg: dbg.detach(quit=False, block=True),
    "debug_from": lambda dbg: dbg.debug_from("after_input"),
}

@pytest.mark.parametrize("action", LOCAL_ONLY_ACTIONS)
def test_actions_on_the_local_pid_are_refused(dbg, action):
    """
    The actions that signal the process or attach to it by pid from this machine (migrate to libdebug, splitting on
    fork, detach(block=True), debug_from) raise at once on a gdbserver target, whose pid may be another machine's; the
    session keeps working afterwards.
    """
    with pytest.raises(PwnlibException, match="gdbserver target"):
        LOCAL_ONLY_ACTIONS[action](dbg)
    dbg.until("main_start")
    assert dbg.instruction_pointer == dbg.symbols["main_start"]

########################## REGISTERS, CALLS AND SYSCALLS ##########################

def test_return_value_can_be_overwritten(dbg):
    """Writing the return register after finish() from ask_pid() changes what main() prints: the fake pid 1234."""
    dbg.until("ask_pid")
    dbg.finish()
    dbg.return_value = 1234
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"pid 1234" in dbg.p.recvall(timeout=5)

def test_call(dbg):
    """call("add", [2, 3]) runs add() in the remote process and returns 5."""
    dbg.until("main_start")
    assert dbg.call("add", [2, 3]) == 5

def test_syscall(dbg, sysno):
    """syscall(getpid) runs in the remote process: it returns the pid the program itself prints afterwards."""
    dbg.until("main_start")
    pid = dbg.syscall(sysno("getpid"), [])
    dbg.p.sendline(b"x")
    dbg.c()
    assert f"pid {pid}\n".encode() in dbg.p.recvall(timeout=5)

def test_alloc(dbg):
    """alloc() returns memory of the remote process (malloc called inside it) that can be written and read back."""
    dbg.until("main_start")
    pointer = dbg.alloc(0x20)
    dbg.write(pointer, b"remote heap")
    assert dbg.read(pointer, 11) == b"remote heap"

def test_catch_syscall_entry_and_exit(dbg):
    """
    catch_syscall("write", callback) through the gdbserver calls the callback on the entry of say_hi()'s write and on
    its exit, with the kernel's return value: 16 bytes.
    """
    events = Queue()

    def callback(d, entry):
        if not entry or (d.syscall_args[0] == 1 and d.read(d.syscall_args[1], 7) == b"syscall"):
            events.put((entry, None if entry else d.return_value))
        return False
    dbg.catch_syscall("write", callback)
    dbg.p.sendline(b"x")
    dbg.c()
    assert [events.get(timeout=1) for _ in range(2)] == [(True, None), (False, 16)]
