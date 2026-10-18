"""Calling functions and syscalls inside the process."""
import os

import pytest
from pwn import context

from support.targets import read_c_long

# call() runs the function in a thread and waits for its result: when restore_backup() raises there, it never returns
CALL_HANGS = {
    "arm": "call() never returns on arm: restore_backup() writes registers gdb can't assign, and no return address is put in lr",
    "mips": "call() never returns on mips: restore_backup() writes $at, which gdb can't assign",
    "mips64": "call() never returns on mips64: restore_backup() writes $at, which gdb can't assign",
}


def _qemu_code_write(test):
    """qemu-user refuses gdb's writes to the guest's code pages, even after mprotect (BUG note on gdb_plus.py:syscall)"""
    for arch in ["aarch64", "riscv32", "riscv64"]:
        test = pytest.mark.known_gap(arch, "syscall() writes its syscall instruction over the code at the instruction pointer: qemu-user refuses gdb's writes to the guest's code pages, even after mprotect")(test)
    return test


def call_hangs(test):
    for arch, reason in CALL_HANGS.items():
        test = pytest.mark.known_gap(arch, reason, run=False)(test)
    return test


@pytest.fixture
def dbg(debugger, basic, backend):
    dbg = debugger(basic, aslr=False, backend=backend)
    dbg.until("main_start")  # a normal stack frame
    return dbg


@call_hangs
def test_call(dbg):
    """
    call("add", [2, 3]) runs add() inside the stopped process with the arguments in the place the calling convention
    puts them, and returns its return value, 5.
    """
    assert dbg.call("add", [2, 3]) == 5


@call_hangs
def test_call_restores_the_registers(dbg):
    """
    After call() every register is back to the value it had before (dbg.backup() before and after are equal): the call
    leaves no trace in the program state.
    """
    backup = dbg.backup()
    dbg.call("add", [2, 3])
    assert dbg.backup() == backup


@call_hangs
def test_call_with_stack_arguments(dbg):
    """
    call() with ten arguments puts the ones that don't fit in registers on the stack in the right order: many_args(0,
    ..., 9) weights each argument by its position, so only the right order gives 330.
    """
    assert dbg.call("many_args", list(range(10))) == 330


@call_hangs
def test_call_with_stack_arguments_on_a_misaligned_stack(dbg):
    """
    Same as the stack arguments test after a push(): call() aligns the stack to 16 bytes, and the padding must go above
    the arguments, not between them and the return address.
    """
    # call() pads the stack to 16 bytes: the padding must not end up between the return address and the arguments
    dbg.push(0)
    assert dbg.call("many_args", list(range(10))) == 330


@call_hangs
def test_call_with_strings_and_bytes(dbg):
    """
    A str or bytes argument is copied into the process (on the heap by default) and the function receives a pointer to
    it: string_length("hello") is 5.
    """
    assert dbg.call("string_length", ["hello"]) == 5
    assert dbg.call("string_length", [b"hello world\x00"]) == 11


@call_hangs
def test_call_with_strings_in_the_bss(dbg):
    """
    With heap=False the string arguments are written in the bss instead of a heap allocation, and the function still
    receives a valid pointer.
    """
    assert dbg.call("string_length", ["bss"], heap=False) == 3


@call_hangs
def test_call_libc(dbg):
    """
    call() resolves a libc symbol (atoi) and runs it. Not strlen: it is an IFUNC whose symbol is the resolver. The
    static QEMU fixtures use the atoi of freestanding.h.
    """
    # Not strlen: it is an IFUNC, the symbol is the resolver that returns the implementation's address.
    # The QEMU targets are static: their atoi comes from fixtures/src/freestanding.h
    assert dbg.call("atoi", ["42"]) == 42


@call_hangs
def test_call_with_a_custom_calling_convention(dbg):
    """
    calling_convention= decides in which registers the arguments go: listing inner()'s argument register second and a
    decoy first must give inner(21) == 42.
    """
    # inner(x) reads its argument from the first register: list it second, after a decoy
    first, second = {"amd64": ["rdi", "rsi"], "i386": [None, None], "aarch64": ["x0", "x1"], "arm": ["r0", "r1"],
                     "riscv32": ["a0", "a1"], "riscv64": ["a0", "a1"], "mips": ["a0", "a1"], "mips64": ["a0", "a1"]}[context.arch]
    if first is None:
        pytest.skip("not applicable: i386 passes every argument on the stack: there are no argument registers to reorder")
    assert dbg.call("inner", [5, 21], calling_convention=[second, first]) == 42


@call_hangs
def test_call_without_waiting(dbg):
    """call(..., wait=False) returns at once with a queue that receives the return value when the function finishes."""
    result = dbg.call("add", [20, 22], wait=False)
    assert result.get(timeout=10) == 42


@call_hangs
def test_program_continues_normally_after_calls(dbg):
    """
    After two call("tick") the program continues as if nothing happened, except for the side effects: it prints counter
    7 (5 ticks of its own + 2).
    """
    dbg.call("tick")
    dbg.call("tick")
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"counter 7" in dbg.p.recvall(timeout=5)

# BUG: Get's called multiple times
@call_hangs
def test_call_from_a_callback(dbg):
    """
    call() inside a breakpoint callback works and returns to the address of that breakpoint without running the callback
    again.
    """
    # call() returns to the address of the breakpoint that is running the callback
    results, entered = [], []

    def callback(d):
        entered.append(d.instruction_pointer)
        if len(entered) > 1:
            return False  # re-entered: don't recurse forever
        results.append(d.call("inner", [21]))
        return False
    dbg.b("add", callback=callback)
    dbg.b("outer")
    dbg.c()
    assert results == [42]
    assert len(entered) == 1, "the callback ran again when call() returned onto its breakpoint"
    assert dbg.instruction_pointer == dbg.symbols["outer"]


@call_hangs
@pytest.mark.not_applicable("libdebugs", "gdb_call() forwards to gdb's own `call` command: libdebug has no expression evaluator")
def test_gdb_call(dbg):
    """gdb_call() forwards to gdb's own `call` command (which uses the debug information) and parses its result."""
    assert dbg.gdb_call("add", [2, 3]) == 5


def test_syscall(dbg, sysno):
    """
    syscall(getpid) runs a syscall instruction in the process and returns the kernel's answer: the pid of the debugged
    process.
    """
    assert dbg.syscall(sysno("getpid"), []) == dbg.pid


@call_hangs
def test_syscall_with_buffers(dbg, sysno, tmp_path):
    """
    syscall() copies bytes and str arguments into the process: openat + write + close create a real file on the host
    whose content the test reads back.
    """
    # openat exists on every architecture (aarch64 and riscv have no open)
    path = str(tmp_path / "written")
    open(path, "wb").close()
    at_fdcwd, o_wronly = -100, 1
    fd = dbg.syscall(sysno("openat"), [at_fdcwd % 2**context.bits, path, o_wronly, 0])
    assert 2 < fd < 2**16
    data = b"written by a syscall"
    assert dbg.syscall(sysno("write"), [fd, data, len(data)]) == len(data)
    assert dbg.syscall(sysno("close"), [fd]) == 0
    assert open(path, "rb").read() == data


@call_hangs
def test_syscall_restores_code_and_registers(dbg, sysno):
    """
    syscall() writes a syscall instruction over the current code; afterwards both the code bytes at the instruction
    pointer and every register are restored.
    """
    code = dbg.read(dbg.instruction_pointer, 8)
    backup = dbg.backup()
    dbg.syscall(sysno("getppid"), [])
    assert dbg.read(dbg.instruction_pointer, 8) == code
    assert dbg.backup() == backup


@call_hangs
def test_syscall_at_a_given_address(dbg, sysno):
    """
    syscall(..., syscall_address=) runs the syscall instruction already present at that address instead of patching the
    current code: nothing at the instruction pointer changes.
    """
    # syscall_address: run the syscall instruction found there instead of writing one over the current code
    from gdb_plus.utils.arch import shellcode_syscall
    address = dbg.inject_shellcode(shellcode_syscall[context.arch])
    before = dbg.read(dbg.instruction_pointer, 8)
    ip = dbg.instruction_pointer
    assert dbg.syscall(sysno("getpid"), [], syscall_address=address) == dbg.pid
    assert dbg.instruction_pointer == ip
    assert dbg.read(dbg.instruction_pointer, 8) == before


def test_syscall_too_many_arguments(dbg):
    """syscall() refuses more than six arguments (no architecture passes more to the kernel)."""
    with pytest.raises(AssertionError):
        dbg.syscall(0, [0] * 7)


@call_hangs
def test_syscall_result_is_visible_to_the_program(dbg, sysno):
    """
    A write(1, ...) injected with syscall() reaches the process' real stdout, and the process is still alive afterwards.
    """
    dbg.syscall(sysno("write"), [1, b"injected\n", 9])
    assert dbg.p.recvuntil(b"injected\n", timeout=5).endswith(b"injected\n")  # gdbserver may print first
    assert os.path.exists(f"/proc/{dbg.pid}")


@call_hangs
@pytest.mark.known_gap("new_libdebug", "syscall() restores the registers with restore_backup(), which writes orig_rax: new libdebug has no such register")
@_qemu_code_write
def test_syscall_with_buffers_in_the_bss(dbg, sysno):
    """
    syscall(..., heap=False) copies its bytes arguments into the bss instead of the heap: write(1, buffer) still prints
    them, and the bss is not left used.
    """
    assert dbg.syscall(sysno("write"), [1, b"from the bss\n", 13], heap=False) == 13
    assert dbg.p.recvuntil(b"from the bss\n", timeout=5).endswith(b"from the bss\n")
    assert dbg.alloc(1, heap=False) == dbg.exe.bss()  # what the syscall took was given back


@call_hangs
@pytest.mark.not_applicable("libdebugs", "gdb_call() forwards to gdb's own `call` command: libdebug has no expression evaluator")
@pytest.mark.known_gap("aarch64", "gdb_call() on a static binary falls back to call() and ignores cast=: a void function returns whatever the return register holds")
@pytest.mark.known_gap("riscv32", "gdb_call() on a static binary falls back to call() and ignores cast=: a void function returns whatever the return register holds")
@pytest.mark.known_gap("riscv64", "gdb_call() on a static binary falls back to call() and ignores cast=: a void function returns whatever the return register holds")
def test_gdb_call_void(dbg):
    """gdb_call(..., cast="void") calls a function without a return value (tick) and returns None; tick() did run."""
    assert dbg.gdb_call("tick", [], cast="void") is None
    assert read_c_long(dbg, "counter") == 1


@pytest.mark.not_applicable("libdebugs", "gdb_call() forwards to gdb's own `call` command: libdebug has no expression evaluator")
@pytest.mark.known_gap("gdb", "gdb_call() catches every gdb error and retries after finish(): an unknown function never raises (gdb_plus.py:gdb_call)", run=False)
@pytest.mark.known_gap("remote", "gdb_call() catches every gdb error and retries after finish(): an unknown function never raises (gdb_plus.py:gdb_call)", run=False)
@pytest.mark.known_gap("i386", "gdb_call() catches every gdb error and retries after finish(): an unknown function never raises (gdb_plus.py:gdb_call)", run=False)
def test_gdb_call_of_an_unknown_function_raises(dbg):
    """gdb_call() of a function that doesn't exist raises, and the process is still stopped where it was."""
    address = dbg.instruction_pointer
    with pytest.raises(Exception):
        dbg.gdb_call("no_such_function", [1])
    assert dbg.instruction_pointer == address
