"""cube (amd64, PIE, stripped): registers, memory helpers, call() replaying dump_Cube."""
import pytest
from pwn import p64


@pytest.fixture
def cube(challenge):
    return challenge("cube")


def test_register_access(debugger, cube):
    """
    On the stripped PIE cube: writing rax, eax, ax and ah in turn gives the expected combined rax, and r11 keeps a 48
    bit value.
    """
    dbg = debugger(cube, aslr=False)
    dbg.rax = 0xdeadbeefdeadbeef
    dbg.eax = 0xfafafafa
    dbg.ax = 0xbabe
    dbg.ah = 0x90
    assert dbg.rax == 0xdeadbeeffafa90be
    dbg.r11 = 0x134343432342
    assert dbg.r11 == 0x134343432342


def test_special_registers(debugger, cube):
    """On cube, return_value, stack_pointer and instruction_pointer are rax, rsp and rip."""
    dbg = debugger(cube, aslr=False)
    assert dbg.return_value == dbg.rax
    assert dbg.stack_pointer == dbg.rsp
    assert dbg.instruction_pointer == dbg.rip


@pytest.mark.gef
def test_alloc_with_gef(debugger, cube, plugin_script):
    """
    With GEF loaded, alloc() returns a heap chunk that GEF's `heap chunks` lists; alloc(heap=False) /
    dealloc(heap=False) work on the bss.
    """
    dbg = debugger(cube, aslr=False, script=plugin_script("gef"))
    assert dbg._gef
    pointer = dbg.alloc(16)
    dbg.write(pointer, p64(0xdeadbeeffafa90be))
    assert hex(pointer) in dbg.execute("heap chunks")
    dbg.dealloc(pointer)
    pointer = dbg.alloc(16, heap=False)
    dbg.write(pointer, p64(0xdeadbeeffafa90be))
    dbg.dealloc(pointer, len=16, heap=False)


def test_typed_writes(debugger, cube):
    """
    write_ints / write_longs / write_int / write_strings with an address of None allocate and write; the read_*
    counterparts return the same values, even for 300 strings.
    """
    dbg = debugger(cube, aslr=False)
    ints = [4, 6, 295342, 23, 50032]
    strings = [b"ciao", b"come stai ?", b"questo programma fa davvero schifo"]
    pointer = dbg.write_ints(None, ints)
    assert dbg.read_ints(pointer, len(ints)) == ints
    dbg.write_ints(pointer, [x * 2 for x in ints])
    assert dbg.read_ints(pointer, len(ints)) == [x * 2 for x in ints]
    pointer = dbg.write_longs(None, ints)
    assert dbg.read_longs(pointer, len(ints)) == ints
    pointer = dbg.write_int(None, ints[0])
    assert dbg.read_int(pointer) == ints[0]
    pointer = dbg.write_strings(None, strings * 100)
    assert dbg.read_strings(pointer, len(strings) * 100) == strings * 100
    pointer = dbg.write_string(None, strings[0])
    assert dbg.read_string(pointer) == strings[0]


def test_call_replays_the_moves(debugger, cube, reference_file):
    """
    call() of four unnamed functions of cube (by PIE offset) on a buffer of 54 longs gives exactly the dump of the
    legacy suite (dump_Cube).
    """
    out = []
    dbg = debugger(cube, from_entry=True, aslr=False)
    for move in [0x00003175, 0x00003e74, 0x000038d9, 0x00001885]:
        pointer = dbg.alloc(54 * 8)
        dbg.write_longs(pointer, list(range(54)))
        dbg.call(move, [pointer])
        out.append(f"prossima funzione {hex(dbg.elf.address + move)}")
        for i, value in enumerate(dbg.read_longs(pointer, 54)):
            out.append(f"{i}: {value}")
    assert out == reference_file("dump_Cube").split("\n")


def test_manual_load_libc(debugger, cube):
    """Started before the loader, catch("load") + c() stops when the libc is loaded and dbg.libc is then set."""
    dbg = debugger(cube, from_start=True, from_entry=False)
    assert dbg.libc is None
    dbg.catch("load")
    dbg.c()
    assert dbg.libc is not None


def test_load_libc(debugger, cube):
    """Started before the loader, load_libc() runs until the libc is loaded and sets dbg.libc."""
    dbg = debugger(cube, from_start=True, from_entry=False)
    assert dbg.libc is None
    dbg.load_libc()
    assert dbg.libc is not None


@pytest.mark.libdebug
def test_call_malloc_with_libdebug(debugger, cube):
    """
    After debug_from and migrate(libdebug=True), call("malloc") with the legacy libdebug returns the heap address the
    legacy suite recorded.
    """
    dbg = debugger(cube, aslr=False, debug_from=0x55555555950a)
    dbg.migrate(libdebug=True)
    assert dbg.call("malloc", [0x100]) == 0x55555555d2a0
