"""gdb_plus.Structure / Array / String without a process (the integration tier reads them from memory)."""
import struct

import pytest
from pwn import p32, p64

pytestmark = pytest.mark.libclang

ADDRESS = """
typedef struct {
    char street[50];
    char city[30];
    char country[30];
} Address;
"""

EMPLOYEE = """
typedef struct {
    int id;
    char name[40];
    char pad[4];
    double salary;
} Employee;
"""

COMPANY = ADDRESS + EMPLOYEE + """
typedef struct {
    char* name;
    Address *office_address;
    Employee employees[5];
    int employee_count;
} Company;
"""

POINT = "typedef struct { int x; int y; float weight; } Point;"


@pytest.fixture(scope="module")
def gdb_plus():
    import gdb_plus
    return gdb_plus


def employee_bytes(identifier, name, salary):
    return p32(identifier) + name.ljust(40, b"\x00") + b"\x00" * 4 + struct.pack("d", salary)


def test_layout(gdb_plus):
    """
    Structure parses a C header with libclang: the size of Company and the offset of each field match the C layout.
    """
    company = gdb_plus.Structure("Company", COMPANY)
    assert len(company) == 8 + 8 + 5 * 56 + 4
    assert company.symbols == {"name": 0, "office_address": 8, "employees": 16, "employee_count": 296}


def test_structures_are_packed(gdb_plus):
    """Structures are parsed packed (-fpack-struct): fields follow each other without padding."""
    # Parsed with -fpack-struct: fields follow each other without padding
    packed = gdb_plus.Structure("Packed", "typedef struct { char a; int b; } Packed;")
    assert len(packed) == 5
    assert packed.symbols == {"a": 0, "b": 1}


def test_address_moves_the_symbols(gdb_plus):
    """
    Setting structure.address turns the field offsets in .symbols into absolute addresses, and moving it moves them.
    """
    point = gdb_plus.Structure("Point", POINT)
    point.address = 0x1000
    assert point.symbols == {"x": 0x1000, "y": 0x1004, "weight": 0x1008}
    point.address = 0x2000
    assert point.symbols["weight"] == 0x2008


def test_address_given_to_the_constructor_moves_the_symbols(gdb_plus):
    """Structure(..., address=) gives absolute field addresses from the start."""
    point = gdb_plus.Structure("Point", POINT, address=0x1000)
    assert point.address == 0x1000
    assert point.symbols == {"x": 0x1000, "y": 0x1004, "weight": 0x1008}


def test_load_and_export_round_trip(gdb_plus):
    """load(bytes) fills the fields (ints, floats) and exporting the structure gives the same bytes back."""
    raw = p32(3) + p32(0xffffffff) + struct.pack("f", 1.5)
    point = gdb_plus.Structure("Point", POINT).load(raw)
    assert (point.x, point.y) == (3, 0xffffffff)
    assert point == raw
    assert bytes(point) == raw


def test_load_rejects_wrong_sizes(gdb_plus):
    """load() refuses bytes that are not the size of the structure."""
    with pytest.raises(AssertionError):
        gdb_plus.Structure("Point", POINT).load(b"\x00" * 3)


def test_modified_fields_are_exported(gdb_plus):
    """Fields assigned after load() are exported with their new values."""
    point = gdb_plus.Structure("Point", POINT).load(b"\x00" * 12)
    point.y = 7
    point.weight = 2.5
    assert bytes(point) == p32(0) + p32(7) + struct.pack("f", 2.5)


def test_uninitialized_fields_are_zero(gdb_plus):
    """A structure never loaded exports as zeros."""
    assert bytes(gdb_plus.Structure("Point", POINT)) == b"\x00" * 12


def test_copy_is_independent(gdb_plus):
    """copy() gives an independent structure: changing its fields or address doesn't touch the original."""
    original = gdb_plus.Structure("Point", POINT).load(p32(1) + p32(2) + b"\x00" * 4)
    original.address = 0x1000
    copy = original.copy()
    copy.x = 5
    copy.address = 0x3000
    assert original.x == 1
    assert original.symbols["x"] == 0x1000
    assert copy.symbols["x"] == 0x3000


def test_expand_types(gdb_plus):
    """
    load(..., expand=True) types the fields: pointers become Arrays with an address, nested arrays of structures become
    lists of Structures, floats are floats; the export is unchanged.
    """
    raw = p64(0x5000) + p64(0x6000) + b"".join(employee_bytes(i, b"emp%d" % i, 1000.0 * i) for i in range(5)) + p32(5)
    company = gdb_plus.Structure("Company", COMPANY).load(raw, expand=True)
    assert isinstance(company.name, gdb_plus.Array) and company.name.address == 0x5000
    assert company.office_address == 0x6000
    assert len(company.employees) == 5
    assert company.employees[2].name.rstrip(b"\x00") == b"emp2"
    assert company.employees[3].salary == 3000.0
    assert isinstance(company.employees[3].salary, float)
    assert company == raw


def test_assigning_to_a_pointer_wraps_the_value(gdb_plus):
    """
    Assigning bytes or a Structure to a pointer field wraps it (String, Array) at the address the pointer held; the
    pointer is exported as that address.
    """
    raw = p64(0x5000) + p64(0x6000) + b"\x00" * (5 * 56) + p32(0)
    company = gdb_plus.Structure("Company", COMPANY).load(raw)
    company.name = b"ACME"
    assert isinstance(company.name, gdb_plus.String)
    assert company.name.address == 0x5000
    address = gdb_plus.Structure("Address", ADDRESS, address=0x6000)
    company.office_address = address
    assert isinstance(company.office_address, gdb_plus.Array)
    # Pointers are exported as the address they point to, not as their content
    assert company == raw


def test_array_and_string_equality(gdb_plus):
    """An Array or String equals both its content and its address, and String.export() gives its bytes."""
    array = gdb_plus.Array([1, 2], address=0x10)
    assert array == [1, 2]
    assert array == 0x10
    string = gdb_plus.String(b"abc", address=0x20)
    assert string == b"abc"
    assert string == 0x20
    assert string.export() == b"abc"


def test_structure_from_sizes(gdb_plus):
    """Structure(name, {field: size}) builds a structure without a header, from field sizes."""
    point = gdb_plus.Structure("Point", {"x": 4, "y": 4})
    assert len(point) == 8
    assert point.load(p32(1) + p32(2)).y == 2


def test_reserved_field_name(gdb_plus):
    """A field named `address` (reserved by Structure) is refused."""
    with pytest.raises(Exception):
        gdb_plus.Structure("Bad", "typedef struct { int address; } Bad;")


def test_unknown_structure_name(gdb_plus):
    """Asking for a structure the header doesn't define raises."""
    with pytest.raises(Exception):
        gdb_plus.Structure("Missing", POINT)


def test_invalid_header(gdb_plus):
    """A header libclang can't parse (unknown type) raises RuntimeError."""
    with pytest.raises(RuntimeError):
        gdb_plus.Structure("Point", "typedef struct { unknown_type x; } Point;")
