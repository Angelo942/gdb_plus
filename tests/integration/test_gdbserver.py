"""
Debugger((host, port)) on a gdbserver: no local process object, files may have to be downloaded.
Every other feature also runs through a gdbserver: the `remote` target of the axis (integration/conftest.py).
"""
from pathlib import Path

import pytest

from support.local_server import gdbserver

pytestmark = [
    pytest.mark.domain("remote"),
    pytest.mark.not_applicable("native", "about connecting to a gdbserver: a local process is debugged directly"),
    pytest.mark.untested("i386", "a gdbserver of the host's architecture: the remote target of the axis runs the x86-64 fixture"),
    pytest.mark.untested("qemu", "foreign architectures are reached through QEMU's gdbstub: test_architectures.py::test_qemu_gdbstub"),
]


@pytest.fixture
def server(basic):
    with gdbserver([basic]) as address:
        yield address


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


@pytest.mark.xfail(strict=True, reason="pwnlib.gdb.attach((host, port)) without exe looks for the gdbserver with "
                                       "proc.pidof((host, port)), which matches the processes connected to that address, "
                                       "never the listening one: no exe, no pid, it raises before find_executable() can "
                                       "read `info proc` (gdb_plus.py:__attach_gdb)")
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


def test_download_libraries(debugger, server, basic):
    """download=True copies the remote libc into ./gdb_files and dbg.libc points at that copy."""
    dbg = debugger(server, binary=basic, download=True)
    assert dbg.libc is not None
    assert Path("gdb_files", Path(dbg.libc.path).name).is_file()
    assert Path(dbg.libc.path).resolve().parent == Path("gdb_files").resolve()


def test_downloaded_files_are_reused(debugger, basic):
    """
    A second session with download=True reuses the files already in gdb_files instead of downloading them again (same
    modification time).
    """
    with gdbserver([basic]) as address:
        first = debugger(address, binary=basic, download=True)
        library = Path(first.libc.path)
        first_download = library.stat().st_mtime_ns
    with gdbserver([basic]) as address:
        second = debugger(address, binary=basic, download=True)
        assert Path(second.libc.path).stat().st_mtime_ns == first_download


def test_access_library_by_remote_path(debugger, basic, server):
    """
    access_library() accepts the path a library has on the server: it is downloaded to gdb_files and placed at the base
    address the remote maps give.
    """
    # access_library() with the path the library has on the server: downloaded, then placed where the maps say
    dbg = debugger(server, binary=basic, download=True)
    remote_libc = next(path for path in dbg.libs if Path(path).name.startswith("libc"))
    assert dbg.remote_path(Path(remote_libc).name) == Path(remote_libc)
    library = dbg.access_library(remote_libc)
    assert library is not None
    assert library.address == dbg.libs[remote_libc][0]
    assert Path(library.path).resolve().parent == Path("gdb_files").resolve()


def test_download(debugger, basic, server):
    """download(remote_path, local_path) copies any file of the server: the copy is byte for byte the remote libc."""
    dbg = debugger(server, binary=basic)
    remote_libc = next(path for path in dbg.libs if Path(path).name.startswith("libc"))
    dbg.download(remote_libc, "copy_of_libc")
    assert Path("copy_of_libc").read_bytes() == Path(remote_libc).read_bytes()
