"""Symbols, libraries and base addresses of a live process (the pure parsing is in unit/test_addresses_symbols.py)."""
from pathlib import Path

import pytest
from elftools.elf.constants import SH_FLAGS
from pwn import ELF

STATIC = pytest.mark.not_applicable("qemu", "the QEMU fixtures are static: no loader, no libc")


@pytest.fixture
def dbg(debugger, basic, backend):
    return debugger(basic, aslr=False, backend=backend)


def test_symbols_are_rebased(dbg, basic):
    """
    dbg.symbols gives the runtime address of the executable's symbols: the address in the ELF plus the load offset of
    the PIE.
    """
    elf = ELF(basic, checksec=False)
    offset = dbg.exe.address - elf.address
    for name in ["main", "add", "buffer", "counter"]:
        assert dbg.symbols[name] == elf.symbols[name] + offset


@STATIC
def test_symbols_include_the_libc(dbg):
    """dbg.symbols also contains the libc's symbols (malloc, printf) at their runtime addresses."""
    assert dbg.symbols["malloc"] in dbg.libc
    assert dbg.symbols["printf"] == dbg.libc.symbols["printf"]


def test_reverse_lookup(dbg):
    """
    reverse_lookup() turns an address back into "name(address)" when a symbol starts there, and into plain hex
    otherwise.
    """
    assert dbg.reverse_lookup(dbg.symbols["tick"]) == f"tick({hex(dbg.symbols['tick'])})"
    assert dbg.reverse_lookup(dbg.symbols["tick"] + 1) == hex(dbg.symbols["tick"] + 1)
    assert dbg.reverse_lookup("tick") == "tick"


def test_base_addresses(dbg):
    """
    The aliases of the base addresses agree: base_elf / elf_address / exe_address / exe.address, and base_libc /
    libc_address / libc.address, which is a mapping of the process.
    """
    assert dbg.base_elf == dbg.exe.address == dbg.elf_address == dbg.exe_address
    assert dbg.elf is dbg.exe
    if not dbg.exe.statically_linked:
        assert dbg.base_libc == dbg.libc.address == dbg.libc_address
        assert dbg.base_libc in dbg.maps


@STATIC
def test_base_libc_can_be_set(dbg):
    """Assigning base_libc (for example from a leak) moves every symbol of the libc by the same amount."""
    # The setter is for scripts that computed the base from a leak: it moves every symbol of the libc
    original = dbg.base_libc
    printf = dbg.libc.symbols["printf"]
    dbg.base_libc = original + 0x1000
    assert dbg.libc.symbols["printf"] == printf + 0x1000
    dbg.base_libc = original


@STATIC
def test_libraries(dbg):
    """
    dbg.libraries maps each loaded library name to its EXE: the libc entry is dbg.libc, based where the process maps it.
    """
    libraries = dbg.libraries
    names = [name for name in libraries if name.startswith("libc")]
    assert names, libraries
    assert libraries[names[0]] is dbg.libc
    assert dbg.libc.address == dbg.libs[next(path for path in dbg.libs if Path(path).name == names[0])][0]


@STATIC
def test_access_library(dbg):
    """
    access_library(name) returns any library mapped in the process by (partial) name, here the loader, at its runtime
    base; an unknown name gives None.
    """
    # Any library mapped in the process, by (partial) name. The loader is not a DT_NEEDED entry of the binary
    loader = next(Path(path).name for path in dbg.libs if Path(path).name.startswith("ld"))
    library = dbg.access_library(loader)
    assert library is not None
    assert library.address == dbg.ld.address
    assert dbg.access_library("not_a_library") is None


@STATIC
def test_loader(dbg):
    """dbg.ld is the dynamic loader, with the start and end that the process maps show."""
    path = next(path for path in dbg.libs if Path(path).name.startswith("ld"))
    assert dbg.ld is not None
    assert (dbg.ld.address, dbg.ld.end_address) == tuple(dbg.libs[path])


@pytest.mark.not_applicable("native", "this test is about static binaries: the fixture of this target is dynamically linked (only the QEMU fixtures are static)")
@pytest.mark.not_applicable("gdbserver", "this test is about static binaries: the fixture of this target is dynamically linked (only the QEMU fixtures are static)")
@pytest.mark.not_applicable("i386", "this test is about static binaries: the fixture of this target is dynamically linked (only the QEMU fixtures are static)")
def test_static_binary_has_no_libraries(dbg):
    """
    A static binary has no loader and no libraries: dbg.ld is None, dbg.libraries is empty and dbg.libs only lists the
    executable.
    """
    assert dbg.exe.statically_linked
    assert dbg.ld is None
    assert dbg.libraries == {}
    assert list(dbg.libs) == [dbg.exe.path]


def allocated_sections(file):
    """(name, first byte, last byte) at runtime of every section the program can address, .bss included"""
    offset = file.address - ELF(file.path, checksec=False).address
    for section in file.iter_sections():
        if section.header.sh_flags & SH_FLAGS.SHF_ALLOC and section.header.sh_size:
            start = section.header.sh_addr + offset
            yield section.name, start, start + section.header.sh_size - 1


def test_exe_range_is_inferred_from_the_headers(dbg):
    """
    The range of dbg.exe comes from its program headers (what the loader maps): every allocated section, .bss included,
    is inside it and the end address is not.
    """
    # The end is what the loader maps (PT_LOAD), not the last page of the maps that carries the file name
    assert dbg.exe.end_address == dbg.exe.address + dbg.exe.mapped_size
    for name, first, last in allocated_sections(dbg.exe):
        assert first in dbg.exe and last in dbg.exe, name
    assert dbg.symbols["counter"] in dbg.exe  # a .bss variable
    assert dbg.exe.end_address not in dbg.exe


def test_exe_range_matches_the_memory(dbg):
    """
    Every page in the range of dbg.exe is really mapped in the process: its last bytes and the end of the .bss can be
    read.
    """
    # Every page of the range is mapped, the one after it doesn't belong to the program
    assert dbg.read(dbg.exe.end_address - 8, 8) is not None
    for name, first, last in allocated_sections(dbg.exe):
        if name.startswith(".bss") or name == ".sbss":
            assert dbg.read(last, 1) is not None, name


@STATIC
def test_libc_range_covers_its_bss(dbg):
    """The range of the libc includes its .bss, which lives in anonymous pages after the file in /proc/<pid>/maps."""
    # The .bss of the libc is in pages after the file that the maps list without a path
    bss = dbg.libc.get_section_by_name(".bss").header
    assert dbg.libc.end_address == dbg.libc.address + dbg.libc.mapped_size
    assert dbg.libc.bss() in dbg.libc
    assert dbg.libc.bss(bss.sh_size - 1) in dbg.libc
    assert dbg.read(dbg.libc.bss(bss.sh_size - 1), 1) is not None


@STATIC
@pytest.mark.known_gap("aarch64_remote", "the end of ld is taken from its file-backed mappings: the end of its .bss is in an anonymous page after them, so the range is one page short (debugger/space.py, the EXE of ld)")
def test_loader_range_is_inferred_from_the_headers(dbg):
    """The range of the loader comes from its program headers and contains every allocated section."""
    assert dbg.ld.end_address == dbg.ld.address + dbg.ld.mapped_size
    for name, first, last in allocated_sections(dbg.ld):
        assert first in dbg.ld and last in dbg.ld, name


def test_libs_and_exe_agree_on_the_base(dbg, target_machine):
    """dbg.libs and dbg.exe agree on where the executable starts, and its entry point is inside that range."""
    # The end of the range is checked by test_lifecycle.py::test_non_pie_executable_has_a_range
    # dbg.libs is keyed by the paths of the machine that runs the process
    start, end = dbg.libs[target_machine.program_path(dbg.exe.path)]
    assert dbg.exe.address == start
    assert start <= dbg.exe.entry < end


@STATIC
def test_access_library_from_a_local_copy(dbg, tmp_path):
    """
    access_library(name, local_path=) loads the library from the given file (a copy of the libc, as one downloaded
    from a remote server) and still finds where the process maps it.
    """
    path = next(path for path in dbg.libs if Path(path).name == Path(dbg.libc.path).name)
    copy = tmp_path / "copies" / Path(path).name
    copy.parent.mkdir()
    copy.write_bytes(Path(dbg.libc.path).read_bytes())
    library = dbg.access_library("libc_copy", local_path=copy)
    assert Path(library.path) == copy
    assert library.address == dbg.libs[path][0]


@pytest.mark.known_gap("native", "dbg.symbols caches the merged table: assigning base_elf (or the address of a library) leaves it at the old base (debugger/files.py:symbols)")
@pytest.mark.known_gap("remote", "dbg.symbols caches the merged table: assigning base_elf (or the address of a library) leaves it at the old base (debugger/files.py:symbols)")
@pytest.mark.known_gap("foreign", "dbg.symbols caches the merged table: assigning base_elf (or the address of a library) leaves it at the old base (debugger/files.py:symbols)")
def test_base_elf_can_be_set(dbg, basic):
    """
    Assigning base_elf (for example from a leak) moves the executable: its symbols, and the merged dbg.symbols, follow
    the new base.
    """
    offset = ELF(basic, checksec=False).symbols["main"] - ELF(basic, checksec=False).address
    original = dbg.base_elf
    dbg.symbols  # the merged table has already been built once
    dbg.base_elf = original + 0x10000
    assert dbg.exe.symbols["main"] == original + 0x10000 + offset
    assert dbg.symbols["main"] == original + 0x10000 + offset
    dbg.base_elf = original


def test_unknown_symbol_raises(dbg):
    """A breakpoint on a symbol that exists nowhere raises (with a message saying where it was looked for)."""
    with pytest.raises(Exception):
        dbg.b("no_such_symbol")
    assert all(not breakpoints for breakpoints in dbg.control.breakpoints.values())
