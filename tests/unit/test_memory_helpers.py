"""Typed read/write helpers, strings, stack, bss allocation, nop and canary on fake memory."""
import pytest
from pwn import context, pack

from gdb_plus.utils.arch import nop
from support.offline import FakeExe, offline_debugger

DATA = 0x600000
BSS = 0x404000


@pytest.fixture
def dbg():
    with context.local(arch="amd64"):
        dbg = offline_debugger(exe=FakeExe(bss=BSS))
        dbg.memory.map(DATA, size=0x1000)
        dbg.memory.map(BSS, size=0x1000)
        yield dbg


SIZES = [("byte", 1), ("short", 2), ("int", 4), ("long", 8), ("long_long", 16)]


@pytest.mark.parametrize("kind, size", SIZES)
def test_typed_round_trip(dbg, kind, size):
    """
    Each typed family (byte, short, int, long...) writes and reads a list and a single value of its size, in little
    endian, on a fake memory.
    """
    values = [1, 2 ** (size * 8) - 1, 0x42]
    getattr(dbg, f"write_{kind}s")(DATA, values)
    assert getattr(dbg, f"read_{kind}s")(DATA, len(values)) == values
    assert dbg.read(DATA, size) == (1).to_bytes(size, "little")
    getattr(dbg, f"write_{kind}")(DATA, 7)
    assert getattr(dbg, f"read_{kind}")(DATA) == 7


@pytest.mark.parametrize("kind, size", SIZES)
def test_typed_write_allocates_when_address_is_none(dbg, kind, size):
    """write_<type>s(None, values) allocates memory for the values and returns its address."""
    pointer = getattr(dbg, f"write_{kind}s")(None, [3, 4])
    assert getattr(dbg, f"read_{kind}s")(pointer, 2) == [3, 4]


@pytest.mark.parametrize("arch, size", [("amd64", 8), ("i386", 4), ("aarch64", 8), ("arm", 4)])
def test_pointers_follow_the_architecture(arch, size):
    """
    write_pointers / read_pointer use the pointer size of the architecture: 8 bytes on amd64 and aarch64, 4 on i386 and
    arm.
    """
    with context.local(arch=arch):
        dbg = offline_debugger()
        dbg.memory.map(DATA, size=0x100)
        dbg.write_pointers(DATA, [0x1234, 0x5678])
        assert dbg.read(DATA, 2 * size) == pack(0x1234, size * 8) + pack(0x5678, size * 8)
        assert dbg.read_pointer(DATA + size) == 0x5678


def test_heap_false_is_honoured(dbg):
    """heap=False allocates in the bss even when malloc is available."""
    # With malloc available, heap=False must still allocate in the bss instead of calling malloc
    dbg.__dict__["_exe"] = FakeExe(bss=BSS, symbols={"malloc": 0x401000})
    pointer = dbg.write_ints(None, [1, 2], heap=False)
    assert BSS <= pointer < BSS + 0x1000


def test_bss_allocations_do_not_overlap(dbg):
    """Two allocations in the bss don't overlap: each keeps its own data."""
    first = dbg.write(None, b"A" * 0x10, heap=False)
    second = dbg.write(None, b"B" * 0x4, heap=False)
    assert dbg.read(first, 0x10) == b"A" * 0x10
    assert dbg.read(second, 0x4) == b"B" * 0x4


def test_dealloc_on_the_bss_releases_the_last_chunk(dbg):
    """dealloc(heap=False) of the last bss allocation gives its space back to the next alloc()."""
    first = dbg.alloc(0x10, heap=False)
    dbg.dealloc(first, len=0x10, heap=False)
    assert dbg.alloc(0x10, heap=False) == first


def test_strings_round_trip(dbg):
    """
    write_strings / read_strings handle a list of NUL terminated strings (unicode and empty ones included); write_string
    / read_string one.
    """
    strings = [b"ciao", b"come stai ?", "unicode è".encode(), b""]
    pointer = dbg.write_strings(DATA, strings)
    assert pointer == DATA
    assert dbg.read_strings(DATA, len(strings)) == strings
    assert dbg.read(DATA, 5) == b"ciao\x00"
    dbg.write_string(DATA, "text")
    assert dbg.read_string(DATA) == b"text"


def test_strings_longer_than_a_chunk(dbg):
    """Strings longer than the 0x100 byte chunks read_string reads at a time are read whole."""
    dbg.write_strings(DATA, [b"A" * 0x180, b"B"])
    assert dbg.read_strings(DATA, 2, limit=0x400) == [b"A" * 0x180, b"B"]


def test_read_string_limit(dbg):
    """read_string(limit=) returns at most `limit` bytes."""
    dbg.write_string(DATA, b"A" * 0x300)
    assert dbg.read_string(DATA, limit=0x100) == b"A" * 0x100


def test_read_string_at_the_end_of_a_mapping():
    """
    A short string right before the end of a mapping is read without a fault, although the chunk would cross the end.
    """
    # Strings are read in 0x100 chunks: a short string near the end of a page must not fault
    with context.local(arch="amd64"):
        dbg = offline_debugger()
        dbg.memory.map(0x7000, b"\x00" * 0xff0 + b"hi\x00")
        assert dbg.read_string(0x7ff0) == b"hi"


def test_safe_read(dbg):
    """safe_read() returns the bytes of mapped memory and None for an unmapped address."""
    assert dbg.safe_read(DATA, 4) == b"\x00" * 4
    assert dbg.safe_read(0xdead0000, 4) is None


@pytest.mark.parametrize("arch, size", [("amd64", 8), ("i386", 4), ("aarch64", 8)])
def test_push_and_pop(arch, size):
    """push() and pop() move the stack pointer by one word of the architecture and store / load in that word."""
    with context.local(arch=arch):
        dbg = offline_debugger()
        dbg.memory.map(0x7ff000, size=0x1000)
        dbg.stack_pointer = 0x7ff800
        dbg.push(0x41)
        dbg.push(0x42)
        assert dbg.stack_pointer == 0x7ff800 - 2 * size
        assert dbg.read(dbg.stack_pointer, size) == pack(0x42, size * 8)
        assert dbg.pop() == 0x42
        assert dbg.pop() == 0x41
        assert dbg.stack_pointer == 0x7ff800


def test_nop_one_instruction(dbg):
    """nop(address) replaces exactly one instruction with nops of the same size and returns the old bytes."""
    code = b"\x48\xc7\xc0\x01\x00\x00\x00" + b"\xc3"  # mov rax, 1; ret
    dbg.memory.map(0x401000, code, size=0x100)
    backup = dbg.nop(0x401000)
    assert backup == code[:7]
    assert dbg.read(0x401000, 8) == b"\x90" * 7 + b"\xc3"


def test_nop_several_instructions_and_restore(dbg):
    """nop(address, instructions=2) replaces two instructions; writing back the returned bytes restores the code."""
    code = b"\x55" + b"\x48\x89\xe5" + b"\xc3"  # push rbp; mov rbp, rsp; ret
    dbg.memory.map(0x401000, code, size=0x100)
    backup = dbg.nop(0x401000, instructions=2)
    assert dbg.read(0x401000, 5) == b"\x90" * 4 + b"\xc3"
    dbg.write(0x401000, backup)
    assert dbg.read(0x401000, 5) == code


def test_nop_explicit_size_on_arm():
    """nop(address, size=8) on aarch64 writes two 4 byte nops and nothing more."""
    with context.local(arch="aarch64"):
        dbg = offline_debugger()
        dbg.memory.map(0x401000, b"\xff" * 16)
        dbg.nop(0x401000, size=8)
        assert dbg.read(0x401000, 16) == nop["aarch64"] * 2 + b"\xff" * 8


def test_inject_sleep_returns_what_it_overwrote(dbg):
    """inject_sleep() writes the sleep shellcode (nop; jmp $) and returns the bytes it replaced."""
    dbg.memory.map(0x401000, b"\xcc" * 8)
    backup = dbg.inject_sleep(0x401000)
    assert backup == b"\xcc" * 3
    assert dbg.read(0x401000, 3) == b"\x90\xeb\xfe"


AUXV = """\
33   AT_SYSINFO_EHDR      System-supplied DSO's ELF header 0x7ffff7fc1000
16   AT_HWCAP             Machine-dependent CPU capability hints 0x178bfbff
6    AT_PAGESZ            System page size               4096
25   AT_RANDOM            Address of 16 random bytes     0x7fffffffe389
31   AT_EXECFN            File name of executable        0x7fffffffefc4 "/tmp/basic"
0    AT_NULL              End of vector                  0x0
"""


def test_canary_comes_from_at_random(dbg):
    """
    The canary is read from the bytes AT_RANDOM points to in the auxiliary vector, with its first byte forced to 0.
    """
    dbg.execute_results["info auxv"] = AUXV
    dbg.memory.map(0x7fffffffe389, bytes(range(0x11, 0x21)))
    assert dbg._auxiliary_vector["AT_PAGESZ"] == 4096
    assert dbg._auxiliary_vector["AT_EXECFN"] == 0x7fffffffefc4
    assert dbg.canary == b"\x00" + bytes(range(0x12, 0x19))


def test_auxiliary_vector_when_gdb_fails(dbg):
    """When gdb can't give `info auxv`, the auxiliary vector is None instead of an error."""
    dbg.execute_results["info auxv"] = "The program has no auxiliary information now. failed"
    assert dbg._auxiliary_vector is None


def test_canary_can_be_set_after_a_leak(dbg):
    """dbg.canary can be assigned (from a leak) and is read back."""
    dbg.canary = b"\x00" + b"A" * 7
    assert dbg.canary == b"\x00AAAAAAA"


def test_canary_without_debugger():
    """With debugging=False dbg.canary is 0."""
    with context.local(arch="amd64"):
        assert offline_debugger(debugging=False).canary == 0


def test_nop_size_that_is_not_a_multiple_of_the_nop():
    """
    nop(address, size=6) on aarch64 (4 byte nops) writes the single nop that fits, leaves the last 2 bytes as they were
    and still returns the 6 bytes it was asked to cover.
    """
    with context.local(arch="aarch64"):
        dbg = offline_debugger()
        dbg.memory.map(0x401000, b"\xff" * 16)
        assert dbg.nop(0x401000, size=6) == b"\xff" * 6
        assert dbg.read(0x401000, 16) == bytes.fromhex("1f2003d5") + b"\xff" * 12  # aarch64 nop, hand assembled


def test_canary_set_over_a_different_known_one(dbg):
    """Assigning a canary different from the one read from AT_RANDOM replaces it (gdb_plus only warns)."""
    dbg.execute_results["info auxv"] = AUXV
    dbg.memory.map(0x7fffffffe389, bytes(range(0x11, 0x21)))
    assert dbg.canary == b"\x00" + bytes(range(0x12, 0x19))
    dbg.canary = b"\x00" + b"B" * 7
    assert dbg.canary == b"\x00BBBBBBB"
