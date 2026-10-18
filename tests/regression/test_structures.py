"""Structure / Array / String read from a live process (company) and the CCIT2025 'driveway' writeup."""
import pytest

from gdb_plus import Array, String, Structure

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


@pytest.fixture
def company(debugger, challenge):
    dbg = debugger(challenge("structures_folder/company"))
    dbg.until("total_payroll")
    pointer = dbg.args[0]
    structure = Structure("Company", COMPANY, address=pointer)
    structure.load(dbg.read(pointer, len(structure)))
    return dbg, pointer, structure


def test_export_lists_of_structures_arrays_and_floats(company):
    """
    A C structure read from the company process: replacing its fields with Strings, lists of Structures, floats and
    Arrays still exports the bytes in memory.
    """
    dbg, pointer, structure = company
    structure.name = String(dbg.read_string(structure.name), address=structure.name)
    empty = Structure("Employee", EMPLOYEE)
    raw = structure.employees.to_bytes(len(empty) * 5, "little")
    structure.employees = [empty.copy().load(raw[i * len(empty):(i + 1) * len(empty)]) for i in range(5)]
    for employee, salary in zip(structure.employees, [55000.00, 62000.00, 58000.00, 60000.00]):
        employee.salary = salary
    office = Structure("Address", ADDRESS, address=structure.office_address)
    office.load(dbg.read(office.address, len(office)))
    structure.office_address = Array([office], address=office.address)
    assert structure == dbg.read(pointer, len(structure))
    assert structure == Structure("Company", COMPANY).load(dbg.read(pointer, len(structure)))


def test_assigning_to_pointers(company):
    """
    Assigning a bytes / Structure value to a pointer field turns it into a String / Array, and the export still matches
    memory.
    """
    dbg, pointer, structure = company
    structure.name = dbg.read_string(structure.name)
    office = Structure("Address", ADDRESS, address=structure.office_address)
    office.load(dbg.read(office.address, len(office)))
    structure.office_address = office
    assert structure == dbg.read(pointer, len(structure))
    assert isinstance(structure.office_address, Array)
    assert isinstance(structure.name, String)


def test_expansion(company):
    """
    expand() turns the raw fields into typed ones (floats for salaries) and the expanded structure still exports the
    bytes in memory.
    """
    dbg, pointer, structure = company
    structure.expand()
    structure.name = dbg.read_string(structure.name.address)
    office = Structure("Address", ADDRESS, address=structure.office_address.address)
    office.load(dbg.read(office.address, len(office)), expand=True)
    structure.office_address = office
    assert all(isinstance(employee.salary, float) for employee in structure.employees)
    assert structure == dbg.read(pointer, len(structure))
    assert isinstance(structure.office_address, Array)
    assert isinstance(structure.name, String)


########################## driveway (CCIT2025 rev 2) ##########################

BIN_TREE = """
typedef struct bin_tree {
    int             value;
    int             pad_1;
    struct bin_tree *child1;
    int             weight1;
    int             pad_2;
    struct bin_tree *child2;
    int             weight2;
    int             pad_3;
} bin_tree;
"""
CALL_SRAND = 0x18b1
TREE_TO_STRING = 0x1611
SHOW_SECRET = 0x1b16
SEED = 1749655318  # skip the bruteforce part of the challenge


def _tree_helpers():
    empty = Structure("bin_tree", BIN_TREE)

    def preferred(node):
        return node.child1 if node.weight1 < node.weight2 else node.child2

    def read_node(dbg, address):
        node = empty.copy()
        node.address = address
        node.load(dbg.read(address, len(empty)))
        node.value = chr(node.value)
        return node

    def parse(dbg, address, index=0):
        node = read_node(dbg, address)
        node.index = index
        if node.child1 == 0:
            return node
        if node.weight1 < node.weight2:
            node.child1 = parse(dbg, node.child1, (index + 1) * 2 - 1)
        else:
            node.child2 = parse(dbg, node.child2, (index + 1) * 2)
        return node

    def nodes(tree):
        result = []
        while tree != 0:
            result.append(tree)
            tree = preferred(tree)
        return result

    return read_node, parse, nodes


@pytest.mark.skip(reason="was @unittest.skip in the legacy suite: re-enable once it is known to pass")
def test_driveway_writeup_with_symbols(debugger, challenge):
    """
    The CCIT2025 driveway writeup: fix the srand seed, parse a tree from memory with Structure, repair the corrupted
    nodes and get "Nice job!".
    """
    read_node, parse, nodes = _tree_helpers()
    dbg = debugger(challenge("driveway"))
    dbg.until(CALL_SRAND)
    dbg.args[0] = SEED
    dbg.until(TREE_TO_STRING)
    tree = parse(dbg, dbg.args[0])
    dbg.until(SHOW_SECRET)
    dbg.ni()
    dbg.p.recvuntil(b"This is your driveway, can you follow it?\n")
    secret = dbg.p.recvline().decode().strip()
    valid = nodes(tree)
    assert secret == "".join(node.value for node in valid)
    dbg.until(0x1c3d)
    for node in valid:
        corrupted = read_node(dbg, node.address)
        if node.weight1 != corrupted.weight1:
            dbg.write_int(node.symbols["weight1"], node.weight1)
            dbg.write_int(node.symbols["weight2"], node.weight2)
    dbg.c(wait=False)
    dbg.p.sendline(b"TOYOTA COROLLA")
    dbg.p.recvline()
    dbg.p.recvline()
    assert dbg.p.recvline() == b"Nice job!\n"
