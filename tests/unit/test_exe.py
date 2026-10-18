"""EXE and enum_libs on real files (nothing is executed)."""
import shutil
import subprocess
from pathlib import Path

import pytest
from elftools.elf.constants import SH_FLAGS
from pwn import ELF, context

from gdb_plus.utils.exe import EXE, enum_libs
from support.environment import TESTS


@pytest.fixture
def httpd():
    return EXE(str(TESTS / "httpd"), checksec=False)


def test_name_and_size(httpd):
    """An EXE knows its file name, its size in bytes and whether it is a PIE."""
    assert httpd.name == "httpd"
    assert httpd.size == len(httpd.data)
    assert httpd.pie


def test_wraps_an_existing_elf():
    """EXE(elf) turns a pwntools ELF into an EXE with the same symbols and name."""
    elf = ELF(str(TESTS / "httpd"), checksec=False)
    exe = EXE(elf)
    assert type(exe) is EXE
    assert exe.symbols["main"] == elf.symbols["main"]
    assert exe.name == "httpd"


def test_range_is_known_before_the_end_is_set(httpd):
    """
    The size of the mapped image comes from the program headers, so the range of an EXE is known before the program runs
    and doesn't change when the base is set.
    """
    # The end is inferred from the program headers, so it is known before running the program
    assert httpd.range == httpd.mapped_size == 0x6000
    assert 0x1000 in httpd
    httpd.address = 0x555555554000
    httpd.end_address = 0x55555555a000
    assert httpd.range == 0x6000
    assert httpd.symbols["main"] - httpd.address == EXE(str(TESTS / "httpd"), checksec=False).symbols["main"]


def test_contains(httpd):
    """`address in exe` is true from the base (included) to the end address (excluded)."""
    httpd.address = 0x555555554000
    httpd.end_address = 0x55555555a000
    assert 0x555555555000 in httpd
    assert 0x55555555a000 not in httpd
    assert 0x555555553fff not in httpd


def test_contains_its_first_byte(httpd):
    """The base address itself is inside the EXE."""
    httpd.address = 0x555555554000
    httpd.end_address = 0x55555555a000
    assert httpd.address in httpd


def test_constructor_sets_the_known_address():
    """EXE(path, address=, end_address=) starts with that base and range."""
    exe = EXE(str(TESTS / "httpd"), address=0x555555554000, end_address=0x55555555a000, checksec=False)
    assert exe.address == 0x555555554000
    assert exe.range == 0x6000


# The end address is inferred from the PT_LOAD segments: what the loader maps, not what the file contains

PAGE = 0x1000


def loaded_end(elf):
    """Highest byte the loader maps (end of .bss included), as an offset from the base"""
    segments = [segment.header for segment in elf.iter_segments_by_type("PT_LOAD")]
    low = min(header.p_vaddr for header in segments)
    return max(header.p_vaddr + header.p_memsz for header in segments) - low


def test_constructor_with_only_the_base_address():
    """EXE(path, address=) alone infers the end from the mapped size (it used to raise AttributeError)."""
    # Used to raise AttributeError: the address setter ran before end_address existed
    exe = EXE(str(TESTS / "httpd"), address=0x555555554000, checksec=False)
    assert exe.address == 0x555555554000
    assert exe.end_address == 0x555555554000 + exe.mapped_size


def test_end_follows_the_base(httpd):
    """When only the base is set, the end address moves with it: the range stays the size of the image."""
    with context.local(log_level="error"):  # moving the base twice warns
        httpd.address = 0x555555554000
        assert httpd.end_address == 0x55555555a000
        httpd.address = 0x7f0000000000
        assert httpd.end_address == 0x7f0000006000
    assert httpd.range == 0x6000


def test_explicit_end_is_absolute(httpd):
    """An end address given by the caller (read from the maps) stays where it is when the base is set later."""
    # An end given by the caller (e.g. read from the memory maps) is not moved by a later base
    httpd.end_address = 0x55555555b000
    httpd.address = 0x555555554000
    assert httpd.end_address == 0x55555555b000
    assert 0x55555555a000 in httpd
    assert httpd.range == httpd.mapped_size == 0x6000  # the range is the size of the image, whatever end was given


def test_explicit_end_can_be_forgotten(httpd):
    """Setting end_address = None goes back to the end inferred from the headers."""
    httpd.address = 0x555555554000
    httpd.end_address = 0x55555555b000
    httpd.end_address = None
    assert httpd.end_address == 0x55555555a000


def test_end_set_before_the_base_in_the_constructor():
    """The order of address= and end_address= in the constructor doesn't matter: the explicit end is kept."""
    # Order of the arguments in the constructor doesn't matter: the end stays where it was put
    exe = EXE(str(TESTS / "httpd"), end_address=0x55555555b000, address=0x555555554000, checksec=False)
    assert exe.end_address == 0x55555555b000


def test_mapped_size_is_not_the_file_size(fixture_binary):
    """
    mapped_size is the end of the last loaded segment rounded to a page, smaller than the file (which has section
    headers and symbols after it).
    """
    # The file has section headers and symbols after the last loaded byte
    exe = EXE(fixture_binary("basic"), checksec=False)
    assert exe.size == len(exe.data)
    assert exe.mapped_size == loaded_end(exe) + -loaded_end(exe) % PAGE
    assert exe.mapped_size < exe.size


def test_mapped_size_includes_the_bss():
    """mapped_size includes the .bss, which takes no space in the file: the libc's bss is inside its range."""
    # .bss takes no space in the file but is mapped: the libc's is several pages past the end of the file
    libc = EXE("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False) if Path("/usr/lib/x86_64-linux-gnu/libc.so.6").exists() else None
    if libc is None:
        pytest.skip("no x86-64 libc on this machine")
    bss = libc.get_section_by_name(".bss").header
    assert bss.sh_addr + bss.sh_size <= libc.mapped_size
    assert libc.mapped_size > libc.size
    libc.address = 0x7ffff7c00000
    assert libc.bss() in libc
    assert libc.bss(bss.sh_size - 1) in libc


def test_wrapping_an_exe_keeps_the_inference():
    """Wrapping an EXE in another EXE keeps its mapped size and end address."""
    exe = EXE(str(TESTS / "httpd"), address=0x555555554000, checksec=False)
    assert exe.mapped_size == 0x6000  # cached in __dict__, copied by the wrapper
    wrapped = EXE(exe)
    assert wrapped.mapped_size == 0x6000
    assert wrapped.end_address == 0x55555555a000


def test_wrapping_a_plain_elf():
    """Wrapping a pwntools ELF with a base already set gives the right end address."""
    elf = ELF(str(TESTS / "httpd"), checksec=False)
    elf.address = 0x555555554000
    assert EXE(elf).end_address == 0x55555555a000


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc to build an object file")
def test_no_loadable_segment_falls_back_to_the_file_size(tmp_path):
    """A relocatable object (no PT_LOAD) gets the file size, rounded to a page, as its mapped size."""
    # A relocatable object has no program header: the best guess is the file itself
    (tmp_path / "object.c").write_text("int counter; int get(void) { return counter; }\n")
    subprocess.run(["gcc", "-c", str(tmp_path / "object.c"), "-o", str(tmp_path / "object.o")], check=True)
    with context.local(log_level="error"):  # warns once that there is no PT_LOAD
        exe = EXE(str(tmp_path / "object.o"), checksec=False)
        assert exe.mapped_size == exe.size + -exe.size % PAGE


@pytest.mark.parametrize("name", [
    "basic", "basic_nopie", "basic_i386", "basic_freestanding", "httpd", "traps_withSymbols",
    "basic_arm", "basic_aarch64", "basic_riscv32", "basic_riscv64", "basic_mips", "basic_mips64",
])
def test_every_allocated_section_is_inside(name, fixture_binary):
    """
    For each fixture and CTF binary, every section the program can address at runtime (.bss included) is inside the
    EXE's range, whose end is the last page.
    """
    # On every architecture: each byte the program can address at runtime is `in` the exe, and the end is the last page
    path = fixture_binary(name) if name.startswith("basic") else str(TESTS / name)
    exe = EXE(path, checksec=False)
    if exe.pie:
        exe.address = 0x555555554000
    offset = exe.address - ELF(path, checksec=False).address
    last = exe.address
    for section in exe.iter_sections():
        if section.header.sh_flags & SH_FLAGS.SHF_ALLOC and section.header.sh_size:
            start = section.header.sh_addr + offset
            end = start + section.header.sh_size
            assert start in exe and end - 1 in exe, section.name
            last = max(last, end)
    assert exe.end_address % PAGE == 0
    assert exe.end_address - PAGE < last <= exe.end_address
    assert exe.end_address not in exe
    assert exe.address - 1 not in exe


def test_non_pie_end_is_known_without_running(fixture_binary):
    """For a non PIE binary both the base and the end come from the headers, without running it."""
    # non-PIE: the base comes from the headers, so does the end
    assert (EXE(str(TESTS / "traps_withSymbols"), checksec=False).address, EXE(str(TESTS / "traps_withSymbols"), checksec=False).end_address) == (0x400000, 0x4b2000)
    nopie = EXE(fixture_binary("basic_nopie"), checksec=False)
    assert nopie.address == 0x400000
    assert nopie.end_address == 0x400000 + nopie.mapped_size


@pytest.mark.parametrize("name, expected", [
    ("deflation", ["libz.so.1", "libc.so.6"]),
    ("httpd", ["libc.so.6"]),
    ("traps_withSymbols", []),  # static
])
def test_enum_libs(name, expected):
    """enum_libs() lists the DT_NEEDED libraries of a binary (and nothing for a static one)."""
    with context.local(arch="amd64"):
        assert enum_libs(EXE(str(TESTS / name), checksec=False)) == expected


def test_enum_libs_does_not_depend_on_the_context(fixture_binary):
    """enum_libs() reads a 32 bit binary correctly while pwntools' context is set to amd64."""
    # The Debugger of a 64 bit script may look at a 32 bit library (or the opposite)
    with context.local(arch="amd64"):
        assert enum_libs(EXE(fixture_binary("basic_i386"), checksec=False)) == ["libc.so.6"]
