"""
What only exists on some architectures. Every other feature already runs on i386 and under QEMU through the
target axis of integration/conftest.py (the `backend` fixture).

The QEMU targets of the axis are static freestanding binaries: the dynamically linked CTF binaries of tests/
(built with a cross libc) cover the loader and the libraries under QEMU.
"""
import subprocess

import pytest

from support.local_server import free_port
from support.results import QEMU_ARCHES

pytestmark = pytest.mark.timeout(120)

# Prebuilt dynamically linked binaries (tests/test_many_arguments.c): printf(format, 0, 1, ..., 9) in main
DYNAMIC = {"aarch64": "test_many_arguments_aarch64", "riscv64": "test_many_arguments_riscv"}
DYNAMIC_ARCHES = [pytest.param(arch, marks=pytest.mark.qemu(arch)) for arch in DYNAMIC]


def _dynamic_only(test):
    test = pytest.mark.untested("native", "a dynamically linked x86-64 binary is what every other test debugs")(test)
    test = pytest.mark.untested("remote", "a dynamically linked x86-64 binary is what every other test debugs")(test)
    test = pytest.mark.untested("i386", "basic_i386 is dynamically linked: every other test covers it")(test)
    for arch in ["arm", "riscv32", "mips", "mips64"]:
        test = pytest.mark.untested(arch, "no dynamically linked fixture: there is no cross libc for it on this machine")(test)
    return test


@_dynamic_only
@pytest.mark.known_gap("riscv64", "Arguments has no stack lookup for riscv")
@pytest.mark.parametrize("backend", DYNAMIC_ARCHES)
def test_libc_arguments_under_qemu(debugger, ctf_binary, backend):
    """
    On a dynamically linked foreign binary under QEMU, dbg.args reads the ten arguments printf receives, including those
    on the stack.
    """
    dbg = debugger(ctf_binary(DYNAMIC[backend]))
    dbg.until("printf")
    # %x takes ints: in 8 byte stack slots only the low half is set
    assert [argument & 0xffffffff for argument in dbg.args[1:11]] == list(range(10))


@_dynamic_only
@pytest.mark.parametrize("backend", DYNAMIC_ARCHES)
def test_libraries_under_qemu(debugger, ctf_binary, backend):
    """
    A dynamically linked binary under QEMU: libc and loader are found, a breakpoint in the libc's printf stops there and
    finish() returns to the executable.
    """
    dbg = debugger(ctf_binary(DYNAMIC[backend]))
    start, end = dbg.libs[dbg.exe.path]
    assert dbg.instruction_pointer == dbg.exe.entry
    assert dbg.libc is not None
    assert dbg.ld is not None
    dbg.until("printf")
    assert dbg.instruction_pointer in dbg.libc
    dbg.finish()
    assert start <= dbg.instruction_pointer < end
    assert dbg.p.recvline(timeout=5) == b"0, 1, 2, 3, 4, 5, 6, 7, 8, 9\n"


@pytest.mark.new_libdebug
@pytest.mark.not_applicable("native", "about a 32 bit process: test_migrate.py migrates the x86-64 ones")
@pytest.mark.not_applicable("remote", "libdebug only debugs local processes: it can't talk to a gdbserver")
@pytest.mark.not_applicable("qemu", "libdebug can't debug a process under QEMU: it would trace the emulator, not the guest")
@pytest.mark.parametrize("backend", ["i386"])
def test_new_libdebug_on_i386(debugger, basic, backend):
    """
    migrate(new_libdebug=True) on a 32 bit process: the position, the 32 bit registers (eax) and the breakpoints
    survive.
    """
    # libdebug >= 0.8 supports i386: migrating keeps the 32 bit registers and the breakpoints
    dbg = debugger(basic, aslr=False, backend=backend)
    dbg.until("add")
    dbg.b("outer")
    address = dbg.instruction_pointer
    dbg.migrate(new_libdebug=True)
    assert dbg.instruction_pointer == address
    assert dbg.eax == dbg.return_value
    dbg.c()
    assert dbg.instruction_pointer == dbg.symbols["outer"]


@pytest.mark.not_applicable("native", "this test is about qemu-user's gdbstub, which only exists for the emulated architectures")
@pytest.mark.untested("remote", "the x86-64 gdbserver: test_gdbserver.py")
@pytest.mark.not_applicable("i386", "i386 runs natively: no QEMU involved")
@pytest.mark.parametrize("backend", [pytest.param(arch, marks=pytest.mark.qemu(arch)) for arch in QEMU_ARCHES])
def test_qemu_gdbstub(debugger, basic, backend):
    """Debugger((host, port)) on `qemu-<arch> -g port`: no pid, no maps, but breakpoints, registers and memory."""
    port = free_port()
    emulator = subprocess.Popen([f"qemu-{backend}", "-g", str(port), basic], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        dbg = debugger(("127.0.0.1", port), binary=basic)
        assert dbg.instruction_pointer == dbg.exe.entry
        dbg.b("tick")
        dbg.c()
        assert dbg.instruction_pointer == dbg.symbols["tick"]
        assert dbg.read_string("buffer") == b"buffer content"
        dbg.finish()
        assert dbg.read_pointer("counter") == 1  # a long: as big as a pointer on every ABI here
    finally:
        emulator.kill()
        emulator.wait()


@pytest.mark.not_applicable("native", "this test is about qemu-user's gdbstub, which only exists for the emulated architectures")
@pytest.mark.untested("remote", "the x86-64 gdbserver: test_gdbserver.py")
@pytest.mark.not_applicable("i386", "i386 runs natively: no QEMU involved")
@pytest.mark.known_gap("riscv32", "maps/libs with qemu_gdbserver= are qemu's host addresses: qemu-user maps 32 bit guests 0x10000 higher, so _set_range reads the exe at the wrong address (gdb_plus.py:__raw_maps)")
@pytest.mark.parametrize("backend", [pytest.param(arch, marks=pytest.mark.qemu(arch)) for arch in QEMU_ARCHES])
def test_qemu_gdbserver(debugger, basic, backend, tmp_path):
    """
    qemu_gdbserver=: the emulator itself runs under a gdbserver (as on a remote server), a second debugger on it
    gives the guest's memory layout that qemu's gdbstub doesn't have.
    """
    from pwn import ELF, context, which
    port = free_port()
    emulator = which(f"qemu-{backend}")
    with context.local(binary=ELF(emulator, checksec=False)):
        qemu = debugger([emulator, "-g", str(port), basic], binary=emulator, backend="remote")
        qemu.c(wait=False)  # qemu starts and waits for gdb on `port`
    with context.local(binary=ELF(basic, checksec=False)):
        dbg = debugger(("127.0.0.1", port), binary=basic, qemu_gdbserver=qemu)
        assert dbg.pid is None
        start, end = dbg.libs[dbg.exe.path]
        assert start <= dbg.exe.entry < end
        dbg.b("tick")
        dbg.c()
        assert dbg.instruction_pointer == dbg.symbols["tick"]
