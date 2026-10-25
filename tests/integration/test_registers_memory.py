"""Registers, arguments, memory access, allocation and code patching on a live process."""
import os
import re
from pathlib import Path

import pytest
from pwn import context, pack, process

from support.known_bugs import LIBDEBUG_EXIT
from support.targets import RETURN_0x1337, after_call, call_to, read_c_long, registers, word_mask

STACK_ARGUMENTS_GAP = [pytest.mark.known_gap(arch, "Arguments has no stack lookup for riscv and mips")
                       for arch in ["riscv32", "riscv64", "mips", "mips64"]]
# /proc/<qemu>/maps describes qemu's own address space, the guest pages live at an offset only qemu knows
GUEST_PERMISSIONS = pytest.mark.untested("qemu", "the permissions of a guest page can't be read from the host: "
                                                 "test_inject_shellcode checks that the code runs")

# qemu-user only stops a guest between two instructions, not inside a host syscall
QEMU_BLOCKED_READ = pytest.mark.not_applicable("qemu", "qemu-user can't stop a guest blocked in a syscall: the interrupt waits for read() to return (gdb_plus warns about it)")


# call() runs the function in a thread and waits for its result: when restore_backup() raises there, it never returns
CALL_HANGS = {
    "arm": "alloc() (malloc through call) never returns on arm: restore_backup() writes registers gdb can't assign, and no return address is put in lr",
    "mips": "alloc() (malloc through call) never returns on mips: restore_backup() writes $at, which gdb can't assign",
    "mips64": "alloc() (malloc through call) never returns on mips64: restore_backup() writes $at, which gdb can't assign",
}


def call_hangs(test):
    for arch, reason in CALL_HANGS.items():
        test = pytest.mark.known_gap(arch, reason, run=False)(test)
    return test


def _with(marks):
    def decorate(test):
        for mark in marks:
            test = mark(test)
        return test
    return decorate


@pytest.fixture
def dbg(debugger, basic, backend):
    return debugger(basic, aslr=False, backend=backend)


########################## REGISTERS ##########################

def test_general_purpose_registers(dbg):
    """
    Two general purpose registers (rax/r11, x0/x11, a0/t1... per architecture) can be written as attributes of dbg and
    read back with the full word.
    """
    first, second = registers()["gprs"]
    setattr(dbg, first, 0xdeadbeefdeadbeef & word_mask())
    setattr(dbg, second, 0x134343432342 & word_mask())
    assert getattr(dbg, first) == 0xdeadbeefdeadbeef & word_mask()
    assert getattr(dbg, second) == 0x134343432342 & word_mask()


@pytest.mark.known_gap("libdebug", "the legacy fork can not parse lower registers")
@pytest.mark.known_gap("aarch64", "gdb 12 gives $wN the type long: GdbBackend.read_register masks with the size gdb reports and returns all of xN (debugger/engines/gdb.py:read_register)")
@pytest.mark.known_gap("aarch64_remote", "gdb 12 gives $wN the type long: GdbBackend.read_register masks with the size gdb reports and returns all of xN (debugger/engines/gdb.py:read_register)")
@pytest.mark.not_applicable("arm", "this architecture has no named sub-registers (like eax inside rax, or w0 inside x0)")
@pytest.mark.not_applicable("riscv32", "this architecture has no named sub-registers (like eax inside rax, or w0 inside x0)")
@pytest.mark.not_applicable("riscv64", "this architecture has no named sub-registers (like eax inside rax, or w0 inside x0)")
@pytest.mark.not_applicable("mips", "this architecture has no named sub-registers (like eax inside rax, or w0 inside x0)")
@pytest.mark.not_applicable("mips64", "this architecture has no named sub-registers (like eax inside rax, or w0 inside x0)")
def test_sub_registers(dbg):
    """
    Writing a sub-register changes only its bits of the full register: eax / ax / ah inside rax on x86, w3 as the low
    half of x3 on aarch64.
    """
    if context.arch == "aarch64":
        dbg.x3 = 0xdeadbeefcafebabe
        assert dbg.w3 == 0xcafebabe
        return
    wide = "rax" if context.arch == "amd64" else "eax"
    setattr(dbg, wide, 0xdeadbeefdeadbeef & word_mask())
    dbg.eax = 0xfafafafa
    dbg.ax = 0xbabe
    dbg.ah = 0x90
    assert getattr(dbg, wide) == 0xdeadbeeffafa90be & word_mask()
    assert (dbg.eax, dbg.ax, dbg.al) == (0xfafa90be, 0x90be, 0xbe)


def test_negative_values_are_wrapped(dbg):
    """
    Assigning -1 to a register stores the all-ones word of the architecture (two's complement), instead of failing.
    """
    register = registers()["gprs"][1]
    setattr(dbg, register, -1)
    assert getattr(dbg, register) == word_mask()


def test_special_registers(dbg):
    """
    The special registers of _special_registers are readable and plausible: eflags' reserved bit, a non zero cs,
    orig_rax = -1 outside a syscall on x86; user mode in cpsr on arm.
    """
    values = {name: getattr(dbg, name) for name in dbg._special_registers}
    if context.arch in ["amd64", "i386"]:
        assert values["eflags"] & 0x2  # reserved bit always set
        assert values["cs"] != 0
        assert values["orig_rax" if context.arch == "amd64" else "orig_eax"] == word_mask()  # not stopped in a syscall
    elif context.arch in ["arm", "aarch64"]:
        assert values["cpsr"] & 0x1f in ([0x10] if context.arch == "arm" else [0x0])  # user mode (EL0)


def test_generic_registers(dbg):
    """
    The architecture independent names (instruction_pointer, stack_pointer, return_value, base_pointer) read the same
    value as the architecture's own register.
    """
    names = registers()
    assert dbg.instruction_pointer == getattr(dbg, names["ip"])
    assert dbg.stack_pointer == getattr(dbg, names["sp"])
    assert dbg.return_value == getattr(dbg, names["ret"])
    if names["fp"] is not None:
        assert dbg.base_pointer == getattr(dbg, names["fp"])


@pytest.mark.not_applicable("riscv32", "base_pointer raises NotImplementedError: riscv has no frame pointer role")
@pytest.mark.not_applicable("riscv64", "base_pointer raises NotImplementedError: riscv has no frame pointer role")
@pytest.mark.not_applicable("native", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
@pytest.mark.not_applicable("gdbserver", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
@pytest.mark.not_applicable("i386", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
@pytest.mark.not_applicable("arm", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
@pytest.mark.not_applicable("aarch64", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
@pytest.mark.not_applicable("mips", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
@pytest.mark.not_applicable("mips64", "this test checks that base_pointer raises where the ABI has no frame pointer: this architecture has one (test_generic_registers reads it)")
def test_no_base_pointer_on_riscv(dbg):
    """
    On riscv, which has no frame pointer role in its ABI, dbg.base_pointer raises NotImplementedError instead of
    returning an unrelated register.
    """
    with pytest.raises(NotImplementedError):
        dbg.base_pointer


@pytest.mark.known_gap("libdebugs", "the long registers are read through gdb only")
@pytest.mark.known_gap("i386", "_long_registers only lists the xmm registers of amd64")
@pytest.mark.not_applicable("qemu", "xmm registers are the SSE registers of x86: the QEMU targets are other architectures")
@pytest.mark.not_applicable("aarch64_remote", "xmm registers are the SSE registers of x86: the gdbserver of this target runs on arm64")
def test_xmm_registers(dbg):
    """
    A 128 bit xmm register can be assigned and read back as one integer (it is a register, not a Python attribute) and
    gdb sees the same value.
    """
    value = 0x112233445566778899aabbccddeeff00
    dbg.xmm1 = value
    assert "xmm1" not in vars(dbg), "set as a python attribute instead of the register"
    assert dbg.xmm1 == value
    if dbg.gdb is not None:
        assert int(dbg.execute("p/x $xmm1.uint128").split()[-1], 16) == value


def test_registers_are_listed(dbg):
    """dir(dbg) lists the register names, so a REPL can complete them."""
    # dir() completes the register names in a REPL
    assert set(dbg._registers) <= set(dir(dbg))


@_with(STACK_ARGUMENTS_GAP)
def test_arguments_in_registers_and_on_the_stack(dbg):
    """
    At the entry of many_args, dbg.args[0:10] reads the ten arguments, from registers and then from the stack per the
    calling convention.
    """
    dbg.until("many_args")
    assert dbg.args[0:10] == list(range(10))


@_with(STACK_ARGUMENTS_GAP)
@pytest.mark.known_gap("aarch64", "Arguments reads the stack arguments from sp + i*8, only right at the function entry")
@pytest.mark.known_gap("aarch64_remote", "Arguments reads the stack arguments from sp + i*8, only right at the function entry")
@pytest.mark.known_gap("arm", "Arguments reads the stack arguments from sp + i*4, only right at the function entry")
def test_arguments_in_the_function_body(dbg):
    """
    dbg.args still finds the stack arguments two instructions into many_args, after the prologue moved the stack
    pointer.
    """
    # After the prologue (which moves the stack pointer) the arguments must still be found
    dbg.until("many_args")
    dbg.step(repeat=2)
    assert dbg.args[0:10] == list(range(10))


def test_write_arguments(dbg):
    """Writing dbg.args at the entry of add() changes what the function computes: add(40, 2) returns 42."""
    dbg.until("add")
    dbg.args[0] = 40
    dbg.args[1] = 2
    dbg.finish()
    assert dbg.return_value == 42


def test_backup_and_restore(dbg):
    """
    backup() saves every register; after running add() to its end, restore_backup() brings back the stack pointer, the
    instruction pointer and all the rest.
    """
    dbg.until("add")
    backup = dbg.backup()
    sp, ip = dbg.stack_pointer, dbg.instruction_pointer
    dbg.finish()
    assert dbg.return_value == 3
    dbg.restore_backup(backup)
    assert (dbg.stack_pointer, dbg.instruction_pointer) == (sp, ip)
    assert dbg.backup() == backup


########################## MEMORY ##########################

def test_read_and_write(dbg):
    """read() and write() access the process' memory: write() overwrites only the bytes given."""
    buffer = dbg.symbols["buffer"]
    assert dbg.read(buffer, 14) == b"buffer content"
    dbg.write(buffer, b"BUFFER")
    assert dbg.read(buffer, 14) == b"BUFFER content"


@pytest.mark.known_gap("gdb_only", "read() goes through gdb, which can't read while the process runs")
@pytest.mark.known_gap("new_libdebug", "new libdebug can't be interrupted (interrupt() raises NotImplementedError)", run=False)
@QEMU_BLOCKED_READ
@pytest.mark.known_gap("libdebug", "interrupt() raises NotImplementedError for the legacy libdebug")
def test_memory_is_accessible_while_running(dbg):
    """
    Memory can be read and written while the process runs (the documented convention), not only while it is stopped.
    """
    dbg.c(wait=False)
    dbg.p.recvuntil(b"ready\n")
    assert dbg.running
    assert read_c_long(dbg, "counter") == 5
    dbg.write(dbg.symbols["buffer"], b"live\x00")
    assert dbg.read_string("buffer") == b"live"
    dbg.interrupt()


def _little(n):
    return n if context.endian == "little" else int.from_bytes(n.to_bytes(4, "little"), "big")


def test_typed_access(dbg):
    """
    The typed helpers read and write in the target's endianness: read_bytes / read_ints / write_longs / read_long, and
    read_string through a pointer.
    """
    assert dbg.read_bytes("table", 16) == list(range(16))
    assert dbg.read_ints("table", 1) == [_little(0x03020100)]
    dbg.write_longs("table", [1, 2])
    assert dbg.read_long("table+8") == 2
    assert dbg.read_string(dbg.read_pointer("greeting")) == b"Hello gdb_plus"


# (size, write list, read list, write one, read one) for every typed helper
TYPED = {
    "byte": (1, lambda d: (d.write_bytes, d.read_bytes, d.write_byte, d.read_byte)),
    "short": (2, lambda d: (d.write_shorts, d.read_shorts, d.write_short, d.read_short)),
    "int": (4, lambda d: (d.write_ints, d.read_ints, d.write_int, d.read_int)),
    "long": (8, lambda d: (d.write_longs, d.read_longs, d.write_long, d.read_long)),
    "long_long": (16, lambda d: (d.write_long_longs, d.read_long_longs, d.write_long_long, d.read_long_long)),
    "pointer": (None, lambda d: (d.write_pointers, d.read_pointers, d.write_pointer, d.read_pointer)),
}


@call_hangs
@pytest.mark.parametrize("kind", list(TYPED))
def test_every_typed_helper(dbg, kind):
    """
    Each typed family (byte, short, int, long, long long, pointer) writes and reads a list and a single value of its
    size, packs it in the target's endianness, and allocates when the address is None.
    """
    size, methods = TYPED[kind]
    size = size or context.bytes
    write_list, read_list, write_one, read_one = methods(dbg)
    values = [1, (1 << (size * 8)) - 1, 0x42]
    assert write_list("buffer", values) == dbg.symbols["buffer"]
    assert read_list("buffer", 3) == values
    assert dbg.read(dbg.symbols["buffer"], size) == pack(1, size * 8)  # in the endianness of the target
    write_one("buffer", 7)
    assert read_one("buffer") == 7
    allocated = write_one(None, 9)
    assert read_one(allocated) == 9


@call_hangs
def test_write_strings(dbg):
    """
    write_strings() / read_strings() handle a list of NUL terminated strings, write_string(None, ...) allocates one, and
    read_string(limit=) stops at the limit.
    """
    dbg.write_strings("buffer", [b"one", "two"])
    assert dbg.read_strings("buffer", 2) == [b"one", b"two"]
    pointer = dbg.write_string(None, "allocated")
    assert dbg.read_string(pointer) == b"allocated"
    assert dbg.read_string("buffer", limit=1) == b"one"


@call_hangs
def test_heap_allocation(dbg):
    """
    alloc() returns a malloc chunk (its header gives the size 0x30) that can be written, read and freed with dealloc().
    """
    pointer = dbg.alloc(0x20)
    # malloc chunk header (glibc's, mimicked by fixtures/src/freestanding.h)
    assert dbg.read_pointer(pointer - context.bytes) & ~0xf == 0x30
    dbg.write(pointer, b"in the heap")
    assert dbg.read(pointer, 11) == b"in the heap"
    dbg.dealloc(pointer)


@call_hangs
def test_write_allocates_when_address_is_none(dbg):
    """write(None, data) allocates memory for the data (on the heap, outside the binary) and returns its address."""
    pointer = dbg.write(None, b"allocated")
    assert dbg.read(pointer, 9) == b"allocated"
    if not dbg.exe.statically_linked:  # a static binary's malloc arena is inside the binary
        assert pointer not in dbg.exe


def test_bss_allocation(dbg):
    """alloc(..., heap=False) takes the memory from the end of the bss instead of calling malloc."""
    pointer = dbg.alloc(0x10, heap=False)
    bss = dbg.exe.get_section_by_name(".bss").header.sh_size
    assert dbg.exe.bss() <= pointer < dbg.exe.bss() + bss  # not `in dbg.exe`: see test_non_pie_executable_has_a_range
    dbg.write(pointer, b"in the bss")
    assert dbg.read(pointer, 10) == b"in the bss"


def test_push_and_pop(dbg):
    """
    push() moves the stack pointer down by one word and stores the value; pop() returns it and restores the stack
    pointer.
    """
    sp = dbg.stack_pointer
    dbg.push(0x41414141)
    assert dbg.stack_pointer == sp - context.bytes
    assert dbg.read_pointer(dbg.stack_pointer) == 0x41414141
    assert dbg.pop() == 0x41414141
    assert dbg.stack_pointer == sp


def test_safe_read(dbg):
    """safe_read() returns None for an unmapped address instead of raising, and the bytes for a mapped one."""
    assert dbg.safe_read(0x10, 8) is None
    assert dbg.safe_read(dbg.symbols["buffer"], 6) == b"buffer"


@pytest.mark.known_gap("riscv32", "nop() only has the 4 byte riscv nop: a compressed (2 byte) call can't be patched")
@pytest.mark.known_gap("libdebug", LIBDEBUG_EXIT, run=False)
def test_nop_a_call(dbg):
    """
    nop(address) replaces the instruction there with nops of the same size (it returns the old bytes): with the call to
    tick() gone, the program counts 0.
    """
    call = call_to(dbg, "main", "tick", end="main_end")
    backup = dbg.nop(call.address)
    assert len(backup) == call.size
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"counter 0" in dbg.p.recvall(timeout=5)


def test_canary(dbg):
    """
    dbg.canary reads the stack canary of the process: one word whose first byte is 0 and, on amd64, the value at fs_base
    + 0x28.
    """
    canary = dbg.canary
    assert len(canary) == context.bytes and canary[0] == 0
    if context.arch == "amd64" and dbg.gdb is not None:
        fs_base = int(dbg.execute("p/x $fs_base").split()[-1], 16)
        assert dbg.read(fs_base + 0x28, 8) == canary


def test_canary_can_be_set_after_a_leak(dbg):
    """dbg.canary can be assigned, for example with a value leaked by an exploit, and is read back."""
    leaked = b"\x00" + b"A" * (context.bytes - 1)
    dbg.canary = leaked
    assert dbg.canary == leaked


def _permissions(machine, pid, address):
    """Permissions (rwxp) of the mapping that holds address, from /proc/<pid>/maps on the machine of the process"""
    for line in machine.read_file(f"/proc/{pid}/maps").decode().splitlines():
        start, end = (int(x, 16) for x in line.split()[0].split("-"))
        if start <= address < end:
            return line.split()[1]


@GUEST_PERMISSIONS
def test_make_page_rwx(dbg, target_machine):
    """make_page_rwx() changes the permissions of the page holding an address to rwx, as /proc/<pid>/maps shows."""
    pointer = dbg.alloc(0x20)
    dbg.make_page_rwx(pointer)
    assert _permissions(target_machine, dbg.pid, pointer).startswith("rwx")


@GUEST_PERMISSIONS
def test_make_page_rwx_across_pages(dbg, target_machine):
    """make_page_rwx(address, size) also changes the next page when the data crosses the end of the first one."""
    pointer = dbg.alloc(0x20)
    end_of_page = pointer - pointer % dbg.page_size + dbg.page_size
    if _permissions(target_machine, dbg.pid, end_of_page) is None:
        pytest.skip("the page after the allocation is not mapped")
    dbg.make_page_rwx(end_of_page - 0x10, 0x20)
    assert _permissions(target_machine, dbg.pid, end_of_page - 0x10).startswith("rwx")
    assert _permissions(target_machine, dbg.pid, end_of_page).startswith("rwx")


def test_page_size(dbg):
    """dbg.page_size is the page size of the process: 4K, 16K or 64K."""
    assert dbg.page_size in (0x1000, 0x4000, 0x10000)
    if context.native:
        assert dbg.page_size == os.sysconf("SC_PAGE_SIZE")


@call_hangs
def test_inject_shellcode(dbg, target_machine):
    """
    inject_shellcode() writes code into a new rwx page; call() of that address runs it (a hand assembled function that
    returns 0x1337).
    """
    shellcode = RETURN_0x1337[context.arch]
    address = dbg.inject_shellcode(shellcode)
    assert dbg.read(address, len(shellcode)) == shellcode
    if context.native:  # see GUEST_PERMISSIONS
        assert _permissions(target_machine, dbg.pid, address).startswith("rwx")
    assert dbg.call(address) == 0x1337


@pytest.mark.known_gap("arm", "interrupt() never returns while the qemu-user guest spins in the injected loop (debugger/control_flow.py:interrupt)", run=False)
@pytest.mark.known_gap("aarch64", "interrupt() never returns while the qemu-user guest spins in the injected loop (debugger/control_flow.py:interrupt)", run=False)
@pytest.mark.known_gap("libdebug", "interrupt() raises NotImplementedError for the legacy libdebug")
def test_inject_sleep(dbg):
    """
    inject_sleep() writes an infinite loop over a function (used by debug_from and fork splitting to park a process);
    restoring the bytes lets the program finish normally.
    """
    # The shellcode that debug_from() and split use to park a process: it must loop on itself
    from gdb_plus.utils.arch import shellcode_sleep
    if context.arch not in shellcode_sleep:
        pytest.xfail(f"no sleep shellcode for {context.arch}: debug_from() and fork splitting can't park the process")
    dbg.until("tick")
    backup = dbg.inject_sleep(dbg.symbols["tick"])
    done = dbg.c(wait=False)
    assert not done.wait(1)
    dbg.interrupt()
    assert dbg.symbols["tick"] <= dbg.instruction_pointer < dbg.symbols["tick"] + len(backup)
    dbg.write(dbg.symbols["tick"], backup)
    dbg.jump("tick")
    dbg.p.sendline(b"x")
    dbg.c()
    assert b"counter 5" in dbg.p.recvall(timeout=5)


def test_maps_and_libs(dbg, target_machine):
    """
    dbg.libs maps each loaded file (the executable, the libc) to its range, and dbg.maps gives the size of each mapping.
    """
    libs = dbg.libs
    # dbg.libs is keyed by the paths of the machine that runs the process
    exe_path = target_machine.program_path(dbg.exe.path)
    assert exe_path in libs
    if not dbg.exe.statically_linked:
        assert any(re.search(r"/libc[.-]", path) for path in libs)
    assert dbg.maps[libs[exe_path][0]] > 0


def test_disassemble(dbg):
    """
    disassemble() decodes the instructions at an address with capstone, and next_inst is the instruction at the
    instruction pointer.
    """
    instructions = list(dbg.disassemble(dbg.symbols["add"], 0x10))
    assert instructions[0].address == dbg.symbols["add"]
    assert all(instruction.size > 0 for instruction in instructions)
    assert dbg.next_inst.address == dbg.instruction_pointer
    assert dbg.next_inst.toString() == f"{dbg.next_inst.mnemonic} {dbg.next_inst.op_str}".strip()


def _return_through_injected_code(dbg, **options):
    """Overwrite inner() with a function returning 0x1337 and check that outer() gets it"""
    return_address = after_call(call_to(dbg, "outer", "inner"))
    dbg.until("outer")
    shellcode = RETURN_0x1337[context.arch]
    assert dbg.inject_shellcode(shellcode, address=dbg.symbols["inner"], **options) == dbg.symbols["inner"]
    assert dbg.read(dbg.symbols["inner"], len(shellcode)) == shellcode
    dbg.until(return_address)
    assert dbg.return_value == 0x1337


@pytest.mark.known_gap("new_libdebug", "make_page_rwx() calls mprotect with call(), whose restore_backup() writes orig_rax: new libdebug has no such register")
def test_inject_shellcode_over_a_function(dbg):
    """
    inject_shellcode(address=) makes the page of an existing function (inner) rwx and writes the code over it instead of
    allocating a page: outer() then gets 0x1337 from it.
    """
    _return_through_injected_code(dbg)


def test_inject_shellcode_without_mprotect(dbg):
    """
    inject_shellcode(address=, skip_mprotect=True) writes over inner() without changing the page permissions (the
    debugger can write a read-only page): outer() gets 0x1337 from it.
    """
    _return_through_injected_code(dbg, skip_mprotect=True)


@pytest.mark.not_applicable("gdbserver", "another local process by pid: the remote target has no /proc of its own to read through")
@pytest.mark.not_applicable("foreign", "another local process by pid: under QEMU /proc/<pid>/mem is the emulator's memory, not the guest's")
@pytest.mark.known_gap("gdb", "read()/write() ignore pid= with gdb: they always use the current inferior (debugger/engines/gdb.py:read, write)")
@pytest.mark.known_gap("new_libdebug", "read()/write() ignore pid= with new libdebug: they always use its own process (debugger/engines/new_libdebug.py:read, write)")
def test_read_and_write_another_process_by_pid(dbg, basic):
    """
    read(pid=) and write(pid=) access the memory of another process (here a second copy of the binary, without ASLR so
    that its addresses are the same): the debugged process is untouched.
    """
    with context.local(log_level="error"):
        other = process(basic, aslr=False)
    try:
        other.recvuntil(b"ready\n")
        address = dbg.symbols["buffer"]
        assert dbg.read(address, 14, pid=other.pid) == b"buffer content"
        dbg.write(address, b"OTHER", pid=other.pid)
        with open(f"/proc/{other.pid}/mem", "rb") as memory:
            memory.seek(address)
            assert memory.read(5) == b"OTHER"
        assert dbg.read(address, 5) == b"buffe"
    finally:
        other.close()
