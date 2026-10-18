"""_parse_address, reverse_lookup, the merged symbol table, library names and /proc maps parsing."""
from pathlib import Path

import pytest
from pwn import context

from gdb_plus.utils.exe import EXE
from support.environment import TESTS
from support.offline import FakeExe, offline_debugger

BASE = 0x555555554000


def pie_debugger(**symbols):
    exe = FakeExe(pie=True, address=BASE, end_address=BASE + 0x6000, symbols={name: BASE + offset for name, offset in symbols.items()})
    with context.local(arch="amd64"):
        return offline_debugger(exe=exe)


@pytest.mark.parametrize("location, expected", [
    (0x1189, BASE + 0x1189),          # offset inside the binary
    (BASE + 0x1189, BASE + 0x1189),   # already absolute
    (0x7ffff7dd0000, 0x7ffff7dd0000),  # somewhere else (libc, stack...)
    ("main", BASE + 0x1189),
    ("main+0x10", BASE + 0x1199),
    ("main+16", BASE + 0x1199),
    ("main + 0x10", BASE + 0x1199),
])
def test_parse_address_pie(location, expected):
    """
    _parse_address() on a PIE: a symbol, "symbol+offset" and an integer offset all resolve to the absolute runtime
    address (base + offset); an address already absolute is kept.
    """
    assert pie_debugger(main=0x1189)._parse_address(location) == expected


def test_parse_address_non_pie_keeps_integers():
    """
    On a non PIE binary an integer is already an absolute address and is kept as is; "main+1" still adds the offset.
    """
    with context.local(arch="amd64"):
        dbg = offline_debugger(exe=FakeExe(pie=False, symbols={"main": 0x401136}))
        assert dbg._parse_address(0x1189) == 0x1189
        assert dbg._parse_address("main+1") == 0x401137


def test_parse_address_unknown_symbol():
    """_parse_address() raises for a symbol that doesn't exist instead of returning a wrong address."""
    with pytest.raises(Exception):
        pie_debugger(main=0x1189)._parse_address("does_not_exist")


def test_parse_address_rejects_other_types():
    """_parse_address() raises for a type that is neither a symbol nor an integer (a float)."""
    with pytest.raises(Exception):
        pie_debugger()._parse_address(1.5)


def test_reverse_lookup():
    """
    reverse_lookup() names an address where a symbol starts, prints others in hex, returns a symbol name unchanged and
    refuses None.
    """
    dbg = pie_debugger(main=0x1189)
    assert dbg.reverse_lookup(BASE + 0x1189) == f"main({hex(BASE + 0x1189)})"
    assert dbg.reverse_lookup(BASE + 0x1190) == hex(BASE + 0x1190)
    assert dbg.reverse_lookup("main") == "main"
    with pytest.raises(NotImplementedError):
        dbg.reverse_lookup(None)


def _system_libc():
    for candidate in ["/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]:
        if Path(candidate).exists():
            return candidate
    pytest.skip("no x86_64 libc.so.6 found")


@pytest.fixture
def merged():
    with context.local(arch="amd64"):
        exe = EXE(str(TESTS / "httpd"), checksec=False)
        libc = EXE(_system_libc(), checksec=False)
        dbg = offline_debugger(exe=exe, libraries={"libc.so.6": libc})
        return dbg, exe, libc


def test_symbols_merge_the_executable_and_its_libraries(merged):
    """
    dbg.symbols contains the symbols of the executable and of every loaded library (main from the binary, malloc from
    the libc).
    """
    dbg, exe, libc = merged
    symbols = dbg.symbols
    assert symbols["main"] == exe.symbols["main"]
    assert symbols["malloc"] == libc.symbols["malloc"]


def test_symbols_drop_plt_and_got_stubs(merged):
    """
    dbg.symbols drops the plt.* / got.* names and never maps a function to its PLT stub, so a breakpoint on "puts" lands
    in the libc.
    """
    dbg, exe, _ = merged
    symbols = dbg.symbols
    assert not [name for name in symbols if name.startswith(("plt.", "got."))]
    for name, stub in exe.plt.items():
        assert symbols.get(name) != stub, f"{name} points to the PLT of the executable"


def test_symbols_are_cached_only_once_every_library_is_loaded():
    """
    The merged symbol table is cached only once every library is known: a table built while the libc is still missing is
    not kept.
    """
    with context.local(arch="amd64"):
        dbg = offline_debugger(exe=FakeExe(symbols={"main": 0x401000}), libraries={"libc.so.6": None})
        assert dbg.symbols == {"main": 0x401000}
        assert dbg._symbols is None
        dbg.__dict__["_libraries"] = {}
        dbg.symbols
        assert dbg._symbols == {"main": 0x401000}


LIBRARIES = ["libc.so.6", "libcrypto.so.3", "ld-linux-x86-64.so.2", "libz.so.1", "libstdc++.so.6"]


@pytest.mark.parametrize("name, expected", [
    ("libc", "libc.so.6"),
    ("libc.so.6", "libc.so.6"),
    ("libcrypto", "libcrypto.so.3"),
    ("libz", "libz.so.1"),
    ("ld", "ld-linux-x86-64.so.2"),
    ("libstdc++", "libstdc++.so.6"),
    ("python", None),
])
def test_library_names(name, expected):
    """
    _library_fullname() turns a short library name (libc, ld, libz...) into the full file name of the loaded library,
    matching on a prefix.
    """
    with context.local(arch="amd64"):
        dbg = offline_debugger(libraries={library: None for library in LIBRARIES})
        assert dbg._library_fullname(name) == expected


def test_libraries_are_attributes():
    """
    Loaded libraries are attributes (dbg.libc), and assigning one (dbg.libc = ELF(...)) replaces the library in the
    table instead of creating a Python attribute.
    """
    with context.local(arch="amd64"):
        sentinel = object()
        dbg = offline_debugger(libraries={"libc.so.6": sentinel})
        assert dbg.libc is sentinel
        dbg.__dict__["_initialized"] = True  # __setattr__ only intercepts library names after __init__
        dbg.libc = "replaced"  # e.g. dbg.libc = ELF("./libc.so.6") when the debugger can't find it
        assert dbg._libraries["libc.so.6"] == "replaced"


PROC_MAPS = """\
555555554000-555555555000 r--p 00000000 08:02 1234                       /tmp/basic
555555555000-555555556000 r-xp 00001000 08:02 1234                       /tmp/basic
555555559000-55555557a000 rw-p 00000000 00:00 0                          [heap]
7ffff7d80000-7ffff7da8000 r--p 00000000 08:02 5678                       /usr/lib/x86_64-linux-gnu/libc.so.6
7ffff7da8000-7ffff7f3d000 r-xp 00028000 08:02 5678                       /usr/lib/x86_64-linux-gnu/libc.so.6
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
"""

INFO_PROC_MAP = """\
process 4242
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x555555554000     0x555555555000     0x1000        0x0 /tmp/basic
      0x555555555000     0x555555556000     0x1000     0x1000 /tmp/basic
      0x7ffff7d80000     0x7ffff7da8000    0x28000        0x0 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7da8000     0x7ffff7f3d000   0x195000    0x28000 /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
"""


@pytest.mark.parametrize("raw", [PROC_MAPS, INFO_PROC_MAP], ids=["/proc/pid/maps", "info proc map"])
def test_libs(raw):
    """dbg.libs parses both /proc/<pid>/maps and gdb's `info proc map` into {path: [start, end]} for each file."""
    with context.local(arch="amd64"):
        libs = offline_debugger(raw_maps=raw).libs
    assert libs == {
        "/tmp/basic": [0x555555554000, 0x555555556000],
        "/usr/lib/x86_64-linux-gnu/libc.so.6": [0x7ffff7d80000, 0x7ffff7f3d000],
    }


@pytest.mark.parametrize("raw", [PROC_MAPS, INFO_PROC_MAP], ids=["/proc/pid/maps", "info proc map"])
def test_maps(raw):
    """dbg.maps parses both formats into {start: size} for every mapping, anonymous ones included."""
    with context.local(arch="amd64"):
        maps = offline_debugger(raw_maps=raw).maps
    assert maps[0x555555554000] == 0x1000
    assert maps[0x7ffff7da8000] == 0x195000
    assert maps[0x7ffffffde000] == 0x21000


QEMU_MAPS = """\
00010000-00011000 r-xp 00000000 08:02 1234                               /tmp/risky
4000000000-4000001000 r--p 00000000 08:02 99                             /usr/riscv64-linux-gnu/lib/libc.so.6
5555555c0000-5555556c0000 r-xp 00000000 08:02 77                         /usr/bin/qemu-riscv64
7ffff7d80000-7ffff7da8000 r--p 00000000 08:02 5678                       /usr/lib/x86_64-linux-gnu/libc.so.6
"""


def test_libs_under_qemu_ignore_the_emulator():
    """Under QEMU the maps also contain qemu itself: dbg.libs keeps only the guest's files."""
    with context.local(arch="riscv64"):
        libs = offline_debugger(raw_maps=QEMU_MAPS).libs
    assert list(libs) == ["/tmp/risky", "/usr/riscv64-linux-gnu/lib/libc.so.6"]


def test_set_range_finds_the_executable():
    """_set_range() finds the executable in the maps and sets its base and end address."""
    with context.local(arch="amd64"):
        exe = EXE(str(TESTS / "httpd"), checksec=False)
        exe.name = "basic"
        dbg = offline_debugger(raw_maps=PROC_MAPS)
        dbg._set_range(exe)
    assert exe.address == 0x555555554000
    assert exe.end_address == 0x555555556000


def test_loader_can_be_set():
    """Assigning dbg.ld (for a loader the debugger can't find, e.g. on a remote target) replaces the one it would look for."""
    with context.local(arch="amd64"):
        dbg = offline_debugger()
        loader = EXE("/bin/true", checksec=False)  # any ELF: the getter only keeps EXE objects
        dbg.ld = loader
        assert dbg.ld is loader


def test_base_elf_setter_moves_the_executable():
    """Assigning dbg.base_elf sets the address of the executable (dbg.exe.address)."""
    with context.local(arch="amd64"):
        dbg = offline_debugger(exe=FakeExe(pie=True, address=0x555555554000))
        dbg.base_elf = 0x560000000000
        assert dbg.exe.address == 0x560000000000 == dbg.base_elf
